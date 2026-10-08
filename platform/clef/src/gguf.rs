use crate::{Error, Result};
use alloc::{string::String, vec::Vec};

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}
impl<'a> Reader<'a> {
    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or(Error::Format)?;
        let p = self.data.get(self.at..end).ok_or(Error::Format)?;
        self.at = end;
        Ok(p)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))
    }
    fn string(&mut self) -> Result<&'a str> {
        let n = usize::try_from(self.u64()?).map_err(|_| Error::Format)?;
        core::str::from_utf8(self.bytes(n)?).map_err(|_| Error::Format)
    }
    fn skip(&mut self, t: u32, depth: u32) -> Result<()> {
        if depth > 2 {
            return Err(Error::Format);
        }
        match t {
            8 => {
                self.string()?;
            }
            9 => {
                let sub = self.u32()?;
                let n = self.u64()?;
                if n > self.data.len().saturating_sub(self.at) as u64 {
                    return Err(Error::Format);
                }
                for _ in 0..n {
                    self.skip(sub, depth + 1)?;
                }
            }
            0 | 1 | 7 => {
                self.bytes(1)?;
            }
            2 | 3 => {
                self.bytes(2)?;
            }
            4..=6 => {
                self.bytes(4)?;
            }
            10..=12 => {
                self.bytes(8)?;
            }
            _ => return Err(Error::Format),
        }
        Ok(())
    }
}
pub struct Tensor<'a> {
    pub name: String,
    pub shape: [usize; 4],
    kind: u32,
    data: &'a [u8],
    stride: usize,
}
pub struct Model<'a> {
    tensors: Vec<Tensor<'a>>,
}
fn stride(t: u32, n: usize) -> Result<usize> {
    match t {
        0 => Ok(n * 4),
        1 | 30 => Ok(n * 2),
        8 if n % 32 == 0 => Ok(n / 32 * 34),
        12 if n % 256 == 0 => Ok(n / 256 * 144),
        14 if n % 256 == 0 => Ok(n / 256 * 210),
        _ => Err(Error::Format),
    }
}
impl<'a> Model<'a> {
    pub fn open(data: &'a [u8]) -> Result<Self> {
        let mut r = Reader { data, at: 0 };
        if r.u32()? != 0x46554747 || r.u32()? != 3 {
            return Err(Error::Format);
        }
        let nt = r.u64()?;
        let nk = r.u64()?;
        if nt == 0 || nt > 1024 || nk > 4096 {
            return Err(Error::Format);
        }
        let (mut architecture, mut alignment) = (false, 32usize);
        for _ in 0..nk {
            let key = r.string()?;
            let t = r.u32()?;
            if key == "general.architecture" && t == 8 {
                architecture = r.string()? == "clef";
            } else if key == "general.alignment" && t == 4 {
                alignment = r.u32()? as usize;
            } else {
                r.skip(t, 0)?;
            }
        }
        if !architecture || !alignment.is_power_of_two() || alignment > 4096 {
            return Err(Error::Format);
        }
        let mut table = Vec::new();
        for _ in 0..nt {
            let name = r.string()?;
            if name.len() >= 96 || table.iter().any(|(n, _, _, _, _)| n == name) {
                return Err(Error::Format);
            }
            let rank = r.u32()?;
            if !(1..=4).contains(&rank) {
                return Err(Error::Format);
            }
            let mut shape = [1usize; 4];
            for d in &mut shape[..rank as usize] {
                let n = r.u64()?;
                if n == 0 || n > 1_000_000 {
                    return Err(Error::Format);
                }
                *d = n as usize;
            }
            let kind = r.u32()?;
            let offset = usize::try_from(r.u64()?).map_err(|_| Error::Format)?;
            let stride = stride(kind, shape[0])?;
            let bytes = shape[1..]
                .iter()
                .try_fold(stride, |a, &b| a.checked_mul(b))
                .ok_or(Error::Format)?;
            table.push((String::from(name), shape, kind, offset, bytes));
        }
        let base = r.at.checked_add(alignment - 1).ok_or(Error::Format)? & !(alignment - 1);
        let mut tensors = Vec::new();
        for (name, shape, kind, offset, bytes) in table {
            if offset % alignment != 0 {
                return Err(Error::Format);
            }
            let start = base.checked_add(offset).ok_or(Error::Format)?;
            let end = start.checked_add(bytes).ok_or(Error::Format)?;
            let p = data.get(start..end).ok_or(Error::Format)?;
            tensors.push(Tensor {
                name,
                shape,
                kind,
                data: p,
                stride: stride(kind, shape[0])?,
            });
        }
        Ok(Self { tensors })
    }
    pub fn tensor(&self, name: &str, input: usize, output: usize) -> Result<&Tensor<'a>> {
        self.tensors
            .iter()
            .find(|t| t.name == name && t.shape == [input, output, 1, 1])
            .ok_or(Error::Shape)
    }
}
fn half(p: &[u8]) -> f32 {
    let h = u16::from_le_bytes([p[0], p[1]]) as u32;
    let e = (h >> 10) & 31;
    let f = h & 1023;
    let v = match e {
        0 => f as f32 * 5.960464477539063e-8,
        31 => f32::from_bits(0x7f800000 | (f << 13)),
        _ => f32::from_bits(((e + 112) << 23) | (f << 13)),
    };
    if h & 32768 != 0 {
        -v
    } else {
        v
    }
}
fn scale_min(j: usize, q: &[u8]) -> (u8, u8) {
    if j < 4 {
        (q[j] & 63, q[j + 4] & 63)
    } else {
        (
            (q[j + 4] & 15) | ((q[j - 4] >> 6) << 4),
            (q[j + 4] >> 4) | ((q[j] >> 6) << 4),
        )
    }
}
impl Tensor<'_> {
    pub fn row(&self, row: usize, out: &mut [f32]) -> Result<()> {
        let n = self.shape[0];
        if out.len() != n {
            return Err(Error::Shape);
        }
        let start = row.checked_mul(self.stride).ok_or(Error::Format)?;
        let end = start.checked_add(self.stride).ok_or(Error::Format)?;
        let p = self.data.get(start..end).ok_or(Error::Format)?;
        match self.kind {
            0 => {
                for (v, b) in out.iter_mut().zip(p.chunks_exact(4)) {
                    *v = f32::from_le_bytes(b.try_into().unwrap());
                }
            }
            1 | 30 => {
                for (v, b) in out.iter_mut().zip(p.chunks_exact(2)) {
                    *v = if self.kind == 1 {
                        half(b)
                    } else {
                        f32::from_bits((u16::from_le_bytes([b[0], b[1]]) as u32) << 16)
                    };
                }
            }
            8 => {
                for (y, b) in out.chunks_exact_mut(32).zip(p.chunks_exact(34)) {
                    let d = half(b);
                    for j in 0..32 {
                        y[j] = d * (b[j + 2] as i8) as f32;
                    }
                }
            }
            12 => {
                for (y, b) in out.chunks_exact_mut(256).zip(p.chunks_exact(144)) {
                    let d = half(b);
                    let dm = half(&b[2..]);
                    for j in 0..4 {
                        let (s0, m0) = scale_min(j * 2, &b[4..]);
                        let (s1, m1) = scale_min(j * 2 + 1, &b[4..]);
                        for k in 0..32 {
                            let q = b[16 + j * 32 + k];
                            y[j * 64 + k] = d * s0 as f32 * (q & 15) as f32 - dm * m0 as f32;
                            y[j * 64 + 32 + k] = d * s1 as f32 * (q >> 4) as f32 - dm * m1 as f32;
                        }
                    }
                }
            }
            14 => {
                for (y, b) in out.chunks_exact_mut(256).zip(p.chunks_exact(210)) {
                    let d = half(&b[208..]);
                    for j in 0..2 {
                        let ql = &b[j * 64..];
                        let qh = &b[128 + j * 32..];
                        let sc = &b[192 + j * 8..];
                        for k in 0..32 {
                            let s = k / 16;
                            let qs = [
                                (ql[k] & 15) | ((qh[k] & 3) << 4),
                                (ql[k + 32] & 15) | (((qh[k] >> 2) & 3) << 4),
                                (ql[k] >> 4) | (((qh[k] >> 4) & 3) << 4),
                                (ql[k + 32] >> 4) | (((qh[k] >> 6) & 3) << 4),
                            ];
                            for a in 0..4 {
                                y[j * 128 + a * 32 + k] =
                                    d * (sc[s + a * 2] as i8) as f32 * (qs[a] as i32 - 32) as f32;
                            }
                        }
                    }
                }
            }
            _ => return Err(Error::Format),
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        fn string(out: &mut Vec<u8>, s: &str) {
            out.extend_from_slice(&(s.len() as u64).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        let mut bytes = Vec::from(*b"GGUF");
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        string(&mut bytes, "general.architecture");
        bytes.extend_from_slice(&8u32.to_le_bytes());
        string(&mut bytes, "clef");
        string(&mut bytes, "probe");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&4u64.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.resize((bytes.len() + 31) & !31, 0);
        for v in [-1.0f32, 0.125, 0.0, 100.0] {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        bytes
    }
    #[test]
    fn validates_real_table_and_tensor_payload() {
        let bytes = fixture();
        let model = Model::open(&bytes).unwrap();
        let tensor = model.tensor("probe", 4, 1).unwrap();
        let mut row = [0.0; 4];
        tensor.row(0, &mut row).unwrap();
        assert_eq!(row, [-1.0, 0.125, 0.0, 100.0]);
        assert!(model.tensor("probe", 8, 1).is_err());
        for n in 0..bytes.len() {
            assert!(Model::open(&bytes[..n]).is_err());
        }
    }
    #[test]
    fn decodes_quantized_and_half_rows() {
        let mut q4 = [0u8; 144];
        q4[0..2].copy_from_slice(&0x3c00u16.to_le_bytes());
        q4[4..8].fill(1);
        q4[16..].fill(0x21);
        let t = Tensor {
            name: String::new(),
            shape: [256, 1, 1, 1],
            kind: 12,
            data: &q4,
            stride: 144,
        };
        let mut out = [0.0; 256];
        t.row(0, &mut out).unwrap();
        assert!(out[..32].iter().all(|&v| v == 1.0));
        assert!(out[32..64].iter().all(|&v| v == 2.0));
        let mut q6 = [0u8; 210];
        q6[128..192].fill(0xaa);
        q6[192..208].fill(1);
        q6[208..].copy_from_slice(&0x3c00u16.to_le_bytes());
        q6[0] = 0x21;
        let t = Tensor {
            name: String::new(),
            shape: [256, 1, 1, 1],
            kind: 14,
            data: &q6,
            stride: 210,
        };
        t.row(0, &mut out).unwrap();
        assert_eq!(out[0], 1.0);
        assert_eq!(out[64], 2.0);
        out[0] = 0.0;
        out[64] = 0.0;
        assert!(out.iter().all(|&v| v == 0.0));
        assert_eq!(half(&0x3c00u16.to_le_bytes()), 1.0);
        assert_eq!(half(&0xc000u16.to_le_bytes()), -2.0);
        assert_eq!(half(&1u16.to_le_bytes()), 5.960464477539063e-8);
    }
    #[test]
    fn rejects_truncated() {
        for n in 0..64 {
            assert!(Model::open(&[0u8; 64][..n]).is_err());
        }
    }
    #[test]
    fn rows_are_bounded() {
        let t = Tensor {
            name: String::new(),
            shape: [4, 1, 1, 1],
            kind: 0,
            data: &[0; 16],
            stride: 16,
        };
        assert!(t.row(1, &mut [0.0; 4]).is_err());
        assert!(t.row(usize::MAX, &mut [0.0; 4]).is_err());
        assert!(t.row(0, &mut [0.0; 3]).is_err());
        assert!(t.row(0, &mut [1.0; 4]).is_ok());
    }
}
