use crate::{gguf::Model, math::*, Error, Input, Result, Scores, Span};
use alloc::{format, vec, vec::Vec};

const H: usize = 4096;
const D: usize = 1024;
#[derive(Clone)]
struct Matrix {
    n: usize,
    d: usize,
    v: Vec<f32>,
}
impl Matrix {
    fn zero(n: usize, d: usize) -> Self {
        Self {
            n,
            d,
            v: vec![0.0; n * d],
        }
    }
    fn row(&self, r: usize) -> &[f32] {
        &self.v[r * self.d..(r + 1) * self.d]
    }
    fn row_mut(&mut self, r: usize) -> &mut [f32] {
        &mut self.v[r * self.d..(r + 1) * self.d]
    }
    fn add(&mut self, b: &Self) {
        assert_eq!((self.n, self.d), (b.n, b.d));
        for (a, b) in self.v.iter_mut().zip(&b.v) {
            *a += b;
        }
    }
}
fn dot(a: &[f32], b: &[f32]) -> f32 {
    assert_eq!(a.len(), b.len());
    let mut s = [0.0f32; 4];
    for (a, b) in a.chunks_exact(4).zip(b.chunks_exact(4)) {
        for j in 0..4 {
            s[j] += a[j] * b[j];
        }
    }
    let mut sum = (s[0] + s[1]) + (s[2] + s[3]);
    for i in a.len() / 4 * 4..a.len() {
        sum += a[i] * b[i];
    }
    sum
}
fn softmax(x: &mut [f32]) {
    let max = x.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut sum = 0.0;
    for v in x.iter_mut() {
        *v = exp(*v - max);
        sum += *v;
    }
    for v in x {
        *v /= sum;
    }
}
fn vector(m: &Model, p: &str, name: &str, n: usize) -> Result<Vec<f32>> {
    let mut v = vec![0.0; n];
    m.tensor(&format!("{p}{name}"), n, 1)?.row(0, &mut v)?;
    Ok(v)
}
fn mm(m: &Model, p: &str, name: &str, x: &Matrix, out: usize) -> Result<Matrix> {
    let t = m.tensor(&format!("{p}{name}"), x.d, out)?;
    let mut y = Matrix::zero(x.n, out);
    let mut w = vec![0.0; 4 * x.d];
    for o in (0..out).step_by(4) {
        let nr = (out - o).min(4);
        for j in 0..nr {
            t.row(o + j, &mut w[j * x.d..(j + 1) * x.d])?;
        }
        for r in 0..x.n {
            // Slice bounds are checked outside the SSE2 numerical kernel.
            let values = dot4(x.row(r), &w, nr);
            y.row_mut(r)[o..o + nr].copy_from_slice(&values[..nr]);
        }
    }
    Ok(y)
}
#[inline]
fn dot4(x: &[f32], w: &[f32], rows: usize) -> [f32; 4] {
    assert!(rows <= 4 && x.len() % 4 == 0 && w.len() == 4 * x.len());
    #[cfg(target_arch = "x86_64")]
    {
        use core::arch::x86_64::*;
        // SAFETY: SSE2 is mandatory on x86_64. Every 4-float unaligned load
        // lies within the checked immutable slices; this code has no stores.
        unsafe {
            if rows != 4 {
                let mut y = [0.0; 4];
                for j in 0..rows {
                    y[j] = dot(x, &w[j * x.len()..(j + 1) * x.len()]);
                }
                return y;
            }
            let mut s0 = _mm_setzero_ps();
            let mut s1 = s0;
            let mut s2 = s0;
            let mut s3 = s0;
            for k in (0..x.len()).step_by(4) {
                let v = _mm_loadu_ps(x.as_ptr().add(k));
                s0 = _mm_add_ps(s0, _mm_mul_ps(v, _mm_loadu_ps(w.as_ptr().add(k))));
                s1 = _mm_add_ps(s1, _mm_mul_ps(v, _mm_loadu_ps(w.as_ptr().add(x.len() + k))));
                s2 = _mm_add_ps(
                    s2,
                    _mm_mul_ps(v, _mm_loadu_ps(w.as_ptr().add(2 * x.len() + k))),
                );
                s3 = _mm_add_ps(
                    s3,
                    _mm_mul_ps(v, _mm_loadu_ps(w.as_ptr().add(3 * x.len() + k))),
                );
            }
            let sums = [s0, s1, s2, s3];
            let mut result = [0.0; 4];
            for j in 0..rows {
                let mut a = [0.0; 4];
                _mm_storeu_ps(a.as_mut_ptr(), sums[j]);
                result[j] = (a[0] + a[1]) + (a[2] + a[3]);
            }
            result
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let mut y = [0.0; 4];
        for j in 0..rows {
            y[j] = dot(x, &w[j * x.len()..(j + 1) * x.len()]);
        }
        y
    }
}
fn linear(m: &Model, p: &str, name: &str, x: &Matrix, out: usize) -> Result<Matrix> {
    let mut y = mm(m, p, &format!("{name}.weight"), x, out)?;
    let bias = vector(m, p, &format!("{name}.bias"), out)?;
    for row in y.v.chunks_exact_mut(out) {
        for (v, b) in row.iter_mut().zip(&bias) {
            *v += b;
        }
    }
    Ok(y)
}
fn norm_row(x: &mut [f32], w: &[f32], b: Option<&[f32]>, eps: f32) {
    assert_eq!(x.len(), w.len());
    let mean = if b.is_some() {
        x.iter().sum::<f32>() / x.len() as f32
    } else {
        0.0
    };
    let sum = x
        .iter()
        .map(|v| {
            let d = (*v - mean) as f64;
            d * d
        })
        .sum::<f64>();
    let inv = 1.0 / sqrt((sum / x.len() as f64) as f32 + eps);
    for (j, v) in x.iter_mut().enumerate() {
        *v = (*v - mean) * inv * w[j] + b.map_or(0.0, |b| b[j]);
    }
}
fn norm(m: &Model, p: &str, name: &str, x: &Matrix, ln: bool) -> Result<Matrix> {
    let w = vector(m, p, &format!("{name}.weight"), x.d)?;
    let b = if ln {
        Some(vector(m, p, &format!("{name}.bias"), x.d)?)
    } else {
        None
    };
    let mut y = x.clone();
    for row in y.v.chunks_exact_mut(x.d) {
        norm_row(row, &w, b.as_deref(), if ln { 1e-5 } else { 1e-6 });
    }
    Ok(y)
}
fn rope(x: &mut Matrix, heads: usize, stride: usize) {
    for r in 0..x.n {
        for j in 0..32 {
            let angle = r as f32 * exp(-16.11809565095832 * j as f32 / 32.0);
            let turns = (angle * 0.15915494309189535 + 0.5) as i32;
            let mut a = (angle - turns as f32 * 6.28125) - turns as f32 * 0.001935307179586477;
            let mut sign = 1.0;
            if a > core::f32::consts::FRAC_PI_2 {
                a = core::f32::consts::PI - a;
                sign = -1.0;
            }
            if a < -core::f32::consts::FRAC_PI_2 {
                a = -core::f32::consts::PI - a;
                sign = -1.0;
            }
            let a2 = a * a;
            let sn = a
                * (1.0
                    + a2 * (-1.0 / 6.0
                        + a2 * (1.0 / 120.0
                            + a2 * (-1.0 / 5040.0
                                + a2 * (1.0 / 362880.0 + a2 * (-1.0 / 39916800.0))))));
            let cs = sign
                * (1.0
                    + a2 * (-0.5
                        + a2 * (1.0 / 24.0
                            + a2 * (-1.0 / 720.0
                                + a2 * (1.0 / 40320.0 + a2 * (-1.0 / 3628800.0))))));
            for h in 0..heads {
                let v = &mut x.row_mut(r)[h * stride..];
                let (a, b) = (v[j], v[j + 32]);
                v[j] = a * cs - b * sn;
                v[j + 32] = a * sn + b * cs;
            }
        }
    }
}
fn attention(m: &Model, p: &str, x: &mut Matrix) -> Result<()> {
    let a = norm(m, p, "attn_norm", x, false)?;
    let mut q = mm(m, p, "attn_q.weight", &a, H * 2)?;
    let mut k = mm(m, p, "attn_k.weight", &a, 1024)?;
    let v = mm(m, p, "attn_v.weight", &a, 1024)?;
    let qw = vector(m, p, "attn_q_norm.weight", 256)?;
    let kw = vector(m, p, "attn_k_norm.weight", 256)?;
    for row in q.v.chunks_exact_mut(512) {
        norm_row(&mut row[..256], &qw, None, 1e-6);
    }
    for row in k.v.chunks_exact_mut(256) {
        norm_row(row, &kw, None, 1e-6);
    }
    rope(&mut q, 16, 512);
    rope(&mut k, 4, 256);
    let mut mix = Matrix::zero(x.n, H);
    let mut scores = vec![0.0; x.n];
    for r in 0..x.n {
        for h in 0..16 {
            let qr = &q.row(r)[h * 512..h * 512 + 512];
            for (s, score) in scores[..=r].iter_mut().enumerate() {
                *score = dot(&qr[..256], &k.row(s)[h / 4 * 256..h / 4 * 256 + 256]) / 16.0;
            }
            softmax(&mut scores[..=r]);
            let out = &mut mix.row_mut(r)[h * 256..h * 256 + 256];
            for (s, score) in scores[..=r].iter().enumerate() {
                let vr = &v.row(s)[h / 4 * 256..h / 4 * 256 + 256];
                for j in 0..256 {
                    out[j] += score * vr[j];
                }
            }
            for j in 0..256 {
                out[j] *= sigmoid(qr[256 + j]);
            }
        }
    }
    x.add(&mm(m, p, "attn_output.weight", &mix, H)?);
    Ok(())
}
fn delta(m: &Model, p: &str, x: &mut Matrix) -> Result<()> {
    let a = norm(m, p, "attn_norm", x, false)?;
    let qkv = mm(m, p, "attn_qkv.weight", &a, 8192)?;
    let z = mm(m, p, "attn_gate.weight", &a, H)?;
    let alpha = mm(m, p, "ssm_alpha.weight", &a, 32)?;
    let beta = mm(m, p, "ssm_beta.weight", &a, 32)?;
    let ct = m.tensor(&format!("{p}ssm_conv1d.weight"), 4, 8192)?;
    let mut cw = vec![0.0; 8192 * 4];
    for ch in 0..8192 {
        ct.row(ch, &mut cw[ch * 4..ch * 4 + 4])?;
    }
    let aw = vector(m, p, "ssm_a", 32)?;
    let dt = vector(m, p, "ssm_dt.bias", 32)?;
    let nw = vector(m, p, "ssm_norm.weight", 128)?;
    let mut conv = Matrix::zero(x.n, 8192);
    for r in 0..x.n {
        for ch in 0..8192 {
            let mut sum = 0.0;
            for tap in 0..4 {
                if r + tap >= 3 {
                    sum += qkv.row(r + tap - 3)[ch] * cw[ch * 4 + tap];
                }
            }
            conv.row_mut(r)[ch] = silu(sum);
        }
    }
    let mut state = vec![0.0; 32 * 128 * 128];
    let mut out = Matrix::zero(x.n, H);
    for r in 0..x.n {
        let cv = conv.row(r);
        for h in 0..32 {
            let vv = &cv[4096 + h * 128..4096 + (h + 1) * 128];
            // GGUF repeats key heads in groups, not adjacent pairs.
            let q = &cv[h % 16 * 128..h % 16 * 128 + 128];
            let k = &cv[2048 + h % 16 * 128..2048 + h % 16 * 128 + 128];
            let qi = 1.0 / sqrt(dot(q, q) + 1e-6) / sqrt(128.0);
            let ki = 1.0 / sqrt(dot(k, k) + 1e-6);
            let av = alpha.row(r)[h] + dt[h];
            let sp = if av > 20.0 { av } else { log(1.0 + exp(av)) };
            let decay = exp(aw[h] * sp);
            let b = sigmoid(beta.row(r)[h]);
            let st = &mut state[h * 128 * 128..(h + 1) * 128 * 128];
            let o = &mut out.row_mut(r)[h * 128..(h + 1) * 128];
            let mut pred = [0.0; 128];
            let mut dv = [0.0; 128];
            for (i, row) in st.chunks_exact_mut(128).enumerate() {
                for j in 0..128 {
                    row[j] *= decay;
                    pred[j] += row[j] * (k[i] * ki);
                }
            }
            for j in 0..128 {
                dv[j] = (vv[j] - pred[j]) * b;
            }
            for (i, row) in st.chunks_exact_mut(128).enumerate() {
                for j in 0..128 {
                    row[j] += (k[i] * ki) * dv[j];
                    o[j] += row[j] * (q[i] * qi);
                }
            }
            norm_row(o, &nw, None, 1e-6);
            for j in 0..128 {
                o[j] *= silu(z.row(r)[h * 128 + j]);
            }
        }
    }
    x.add(&mm(m, p, "ssm_out.weight", &out, H)?);
    Ok(())
}
fn mlp(m: &Model, p: &str, x: &mut Matrix) -> Result<()> {
    let a = norm(m, p, "post_attention_norm", x, false)?;
    let mut gate = mm(m, p, "ffn_gate.weight", &a, 12288)?;
    let up = mm(m, p, "ffn_up.weight", &a, 12288)?;
    for (g, u) in gate.v.iter_mut().zip(&up.v) {
        *g = silu(*g) * u;
    }
    x.add(&mm(m, p, "ffn_down.weight", &gate, H)?);
    Ok(())
}
fn head_attn(m: &Model, p: &str, base: &str, qi: &Matrix, kv: &Matrix) -> Result<Matrix> {
    let q = linear(m, p, &format!("{base}q"), qi, D)?;
    let k = linear(m, p, &format!("{base}k"), kv, D)?;
    let v = linear(m, p, &format!("{base}v"), kv, D)?;
    let mut mix = Matrix::zero(q.n, D);
    let mut scores = vec![0.0; k.n];
    for r in 0..q.n {
        for h in 0..16 {
            let qr = &q.row(r)[h * 64..h * 64 + 64];
            for (s, score) in scores.iter_mut().enumerate() {
                *score = dot(qr, &k.row(s)[h * 64..h * 64 + 64]) / 8.0;
            }
            softmax(&mut scores);
            let out = &mut mix.row_mut(r)[h * 64..h * 64 + 64];
            for (s, score) in scores.iter().enumerate() {
                let vr = &v.row(s)[h * 64..h * 64 + 64];
                for j in 0..64 {
                    out[j] += score * vr[j];
                }
            }
        }
    }
    linear(m, p, &format!("{base}o"), &mix, D)
}
fn head_ffn(m: &Model, p: &str, x: &mut Matrix) -> Result<()> {
    let a = norm(m, p, "ffn_norm", x, true)?;
    let mut f = linear(m, p, "ffn_up", &a, 4096)?;
    for v in &mut f.v {
        *v = gelu(*v);
    }
    x.add(&linear(m, p, "ffn_down", &f, D)?);
    Ok(())
}
fn pool(x: &Matrix, span: Span, out: &mut [f32]) {
    out.fill(0.0);
    for r in span.begin..span.end {
        for (v, x) in out.iter_mut().zip(x.row(r as usize)) {
            *v += x;
        }
    }
    for v in out {
        *v /= (span.end - span.begin) as f32;
    }
}
fn cosine(a: &[f32], b: &[f32]) -> f32 {
    dot(a, b) / (sqrt(dot(a, a) + 1e-12) * sqrt(dot(b, b) + 1e-12))
}
fn head(
    m: &Model,
    input: &Input,
    x: &Matrix,
    progress: &mut impl FnMut(&str, usize),
) -> Result<Scores> {
    let o = input.options as usize;
    let x = norm(m, "decision.", "hidden_norm", x, true)?;
    let memory = mm(m, "decision.", "proj_memory.weight", &x, D)?;
    let mut question = Matrix::zero(1, H);
    pool(&x, input.question, question.row_mut(0));
    let mut ctx = Matrix::zero(o, H);
    let mut lex = Matrix::zero(o, H);
    let emb = m.tensor("output.weight", H, 248320)?;
    let mut row = vec![0.0; H];
    for j in 0..o {
        let span = input.option[j];
        pool(&x, span, ctx.row_mut(j));
        for i in span.begin..span.end {
            emb.row(input.tokens[i as usize] as usize, &mut row)?;
            for (v, w) in lex.row_mut(j).iter_mut().zip(&row) {
                *v += w;
            }
        }
        for v in lex.row_mut(j) {
            *v /= (span.end - span.begin) as f32;
        }
    }
    let mut options = mm(m, "decision.", "proj_option_context.weight", &ctx, D)?;
    options.add(&mm(m, "decision.", "proj_option_lexical.weight", &lex, D)?);
    let oq = mm(m, "decision.", "proj_option_question.weight", &question, D)?;
    for row in options.v.chunks_exact_mut(D) {
        for (v, q) in row.iter_mut().zip(&oq.v) {
            *v += q;
        }
    }
    for l in 0..2 {
        let p = format!("dec.blk.{l}.");
        let a = norm(m, &p, "cross_attn_norm", &options, true)?;
        let b = norm(m, &p, "cross_attn_norm_kv", &memory, true)?;
        options.add(&head_attn(m, &p, "cross_attn_", &a, &b)?);
        head_ffn(m, &p, &mut options)?;
        progress("routing", l);
    }
    let mut field = mm(m, "decision.", "proj_question.weight", &question, D)?;
    let mut scores = vec![0.0; o];
    for (j, v) in scores.iter_mut().enumerate() {
        *v = dot(options.row(j), field.row(0)) / 32.0;
    }
    softmax(&mut scores);
    let mut summary = Matrix::zero(1, D);
    for (j, score) in scores.iter().enumerate() {
        for (v, opt) in summary.v.iter_mut().zip(options.row(j)) {
            *v += score * opt;
        }
    }
    field.add(&norm(
        m,
        "decision.",
        "option_summary_norm",
        &summary,
        true,
    )?);
    let global = Matrix {
        n: 1,
        d: H,
        v: x.row(x.n - 1).to_vec(),
    };
    field.add(&mm(m, "decision.", "proj_global.weight", &global, D)?);
    let mut types = Matrix::zero(1, D);
    m.tensor("token_types.weight", D, 3)?.row(1, &mut types.v)?;
    field.add(&types);
    for l in 2..6 {
        let p = format!("dec.blk.{l}.");
        let a = norm(m, &p, "attn_norm", &field, true)?;
        field.add(&head_attn(m, &p, "attn_", &a, &a)?);
        let a = norm(m, &p, "cross_attn_norm", &field, true)?;
        field.add(&head_attn(m, &p, "cross_attn_", &a, &memory)?);
        head_ffn(m, &p, &mut field)?;
        progress("joint", l - 2);
    }
    let field = norm(m, "decision.", "field_norm", &field, true)?;
    let options = norm(m, "decision.", "option_norm", &options, true)?;
    let mut features = Matrix::zero(o, 4 * D);
    for j in 0..o {
        for k in 0..D {
            let (f, v) = (field.v[k], options.row(j)[k]);
            let row = features.row_mut(j);
            row[k] = f;
            row[D + k] = v;
            row[2 * D + k] = f * v;
            row[3 * D + k] = (f - v).abs();
        }
    }
    let mut residual = linear(m, "decision.", "scorer", &features, D)?;
    for v in &mut residual.v {
        *v = gelu(*v);
    }
    let scores = linear(m, "decision.", "scorer_out", &residual, 1)?;
    let scales = vector(m, "decision.", "scales", 3)?;
    question.add(&global);
    let mut result = Scores::default();
    for j in 0..o {
        result.logits[j] = scales[0] * cosine(question.row(0), lex.row(j))
            + scales[2] * (scales[1] * cosine(field.row(0), options.row(j)) + scores.v[j]);
        result.probabilities[j] = result.logits[j];
    }
    softmax(&mut result.probabilities[..o]);
    for j in 0..o {
        if !result.logits[j].is_finite() || !result.probabilities[j].is_finite() {
            return Err(Error::Nonfinite);
        }
        if result.logits[j] > result.logits[result.choice as usize] {
            result.choice = j as u32;
        }
    }
    Ok(result)
}
pub fn infer(m: &Model, input: &Input, mut progress: impl FnMut(&str, usize)) -> Result<Scores> {
    input.validate()?;
    let mut x = Matrix::zero(input.count as usize, H);
    let emb = m.tensor("token_embd.weight", H, 248320)?;
    for r in 0..x.n {
        emb.row(input.tokens[r] as usize, x.row_mut(r))?;
    }
    for l in 0..32 {
        let p = format!("blk.{l}.");
        if l % 4 == 3 {
            attention(m, &p, &mut x)?;
        } else {
            delta(m, &p, &mut x)?;
        }
        mlp(m, &p, &mut x)?;
        progress("backbone", l);
    }
    head(
        m,
        input,
        &norm(m, "", "output_norm", &x, false)?,
        &mut progress,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sse_matches_scalar() {
        let a: Vec<f32> = (0..128).map(|i| (i as f32 - 50.0) / 33.0).collect();
        let w: Vec<f32> = (0..512)
            .map(|i| ((i * 17 % 211) as f32 - 100.0) / 51.0)
            .collect();
        for nr in 1..=4 {
            let y = dot4(&a, &w, nr);
            for j in 0..nr {
                assert!((y[j] - dot(&a, &w[j * 128..j * 128 + 128])).abs() < 1e-5);
            }
        }
    }
}
