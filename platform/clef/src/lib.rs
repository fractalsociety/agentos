#![cfg_attr(not(feature = "host"), no_std)]
//! Bounded, native Clef-Flash 9B inference. No device or policy authority.
extern crate alloc;
pub mod gguf;
mod infer;
pub mod math;
#[cfg(any(not(feature = "host"), test))]
mod native_heap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Error {
    Format = 1,
    Shape = 2,
    Input = 3,
    Nonfinite = 4,
    Heap = 5,
}
pub type Result<T> = core::result::Result<T, Error>;
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct Span {
    pub begin: u32,
    pub end: u32,
}
#[repr(C)]
pub struct Input {
    pub count: u32,
    pub options: u32,
    pub tokens: [u32; 512],
    pub question: Span,
    pub option: [Span; 4],
}
impl Input {
    pub fn validate(&self) -> Result<()> {
        if !(1..=512).contains(&self.count) || !(2..=4).contains(&self.options) {
            return Err(Error::Input);
        }
        for s in core::iter::once(&self.question).chain(&self.option[..self.options as usize]) {
            if s.begin >= s.end || s.end > self.count {
                return Err(Error::Input);
            }
        }
        if self.tokens[..self.count as usize]
            .iter()
            .any(|&t| t >= 248320)
        {
            return Err(Error::Input);
        }
        Ok(())
    }
}
#[derive(Default)]
#[repr(C)]
pub struct Scores {
    pub logits: [f32; 4],
    pub probabilities: [f32; 4],
    pub choice: u32,
}
pub use infer::infer;

type Progress = Option<extern "C" fn(*mut core::ffi::c_void, *const core::ffi::c_char, u32)>;
/// C/seL4 boundary. The caller exclusively owns mapped model, arena, input and
/// result regions for the entire call. They must not overlap. Runs once per PD.
///
/// # Safety
/// Pointers must be valid/aligned for their declared sizes. The model region is
/// immutable during inference. `progress` must obey the C ABI and not reenter.
#[no_mangle]
pub unsafe extern "C" fn clef_rust_run(
    data: *const u8,
    bytes: usize,
    input: *const Input,
    arena: *mut u8,
    arena_bytes: usize,
    out: *mut Scores,
    progress: Progress,
    user: *mut core::ffi::c_void,
) -> u32 {
    if data.is_null()
        || input.is_null()
        || out.is_null()
        || bytes != 6_486_448_288
        || (input as usize) % core::mem::align_of::<Input>() != 0
        || (out as usize) % core::mem::align_of::<Scores>() != 0
    {
        return Error::Input as u32;
    }
    #[cfg(not(feature = "host"))]
    if !native_heap::init(arena, arena_bytes) {
        return Error::Heap as u32;
    }
    #[cfg(feature = "host")]
    let _ = (arena, arena_bytes);
    let run = (|| -> Result<Scores> {
        let model = gguf::Model::open(core::slice::from_raw_parts(data, bytes))?;
        infer(&model, &*input, |stage, layer| {
            let stage = match stage {
                "backbone" => b"backbone\0".as_slice(),
                "routing" => b"routing\0".as_slice(),
                _ => b"joint\0".as_slice(),
            };
            if let Some(f) = progress {
                f(user, stage.as_ptr().cast(), layer as u32);
            }
        })
    })();
    match run {
        Ok(scores) => {
            out.write(scores);
            0
        }
        Err(e) => e as u32,
    }
}

#[cfg(not(feature = "host"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    extern "C" {
        fn clef_native_panic() -> !;
    }
    unsafe { clef_native_panic() }
}

// LLVM emits bcmp for slice equality. This is a memory intrinsic, not an OS API.
#[cfg(not(feature = "host"))]
#[no_mangle]
unsafe extern "C" fn bcmp(
    a: *const core::ffi::c_void,
    b: *const core::ffi::c_void,
    n: usize,
) -> i32 {
    let a = a.cast::<u8>();
    let b = b.cast::<u8>();
    for i in 0..n {
        // Volatile reads prevent LLVM replacing this implementation with bcmp.
        if a.add(i).read_volatile() != b.add(i).read_volatile() {
            return 1;
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn input_rejects_invalid_bounds() {
        assert_eq!(core::mem::size_of::<Input>(), 2096);
        assert_eq!(core::mem::size_of::<Scores>(), 36);
        let mut x = Input {
            count: 10,
            options: 2,
            tokens: [0; 512],
            question: Span { begin: 1, end: 2 },
            option: [Span { begin: 3, end: 4 }; 4],
        };
        assert!(x.validate().is_ok());
        x.count = 513;
        assert_eq!(x.validate(), Err(Error::Input));
        x.count = 10;
        x.option[0].end = 11;
        assert_eq!(x.validate(), Err(Error::Input));
        x.option[0].end = 4;
        x.tokens[5] = 248320;
        assert_eq!(x.validate(), Err(Error::Input));
    }
}
