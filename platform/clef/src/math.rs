pub fn sqrt(x: f32) -> f32 {
    #[cfg(target_arch = "x86_64")]
    // SSE2 is part of the x86_64 baseline and preserved by the seL4 SDK.
    unsafe {
        core::arch::x86_64::_mm_cvtss_f32(core::arch::x86_64::_mm_sqrt_ss(
            core::arch::x86_64::_mm_set_ss(x),
        ))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let mut y = f32::from_bits((x.to_bits() >> 1) + 0x1fc00000);
        for _ in 0..5 {
            y = 0.5 * (y + x / y);
        }
        y
    }
}
pub fn exp(x: f32) -> f32 {
    if x < -87.0 {
        return 0.0;
    }
    let x = x.min(88.0);
    let k = (x * core::f32::consts::LOG2_E + if x < 0.0 { -0.5 } else { 0.5 }) as i32;
    let r = (x - k as f32 * 0.693145751953125) - k as f32 * 1.428606765330187e-6;
    let p = 1.0
        + r * (1.0
            + r * (0.5
                + r * (0.1666666667
                    + r * (0.0416666667
                        + r * (0.0083333333 + r * (0.0013888889 + r * 0.0001984127))))));
    p * f32::from_bits(((k + 127) as u32) << 23)
}
pub fn log(x: f32) -> f32 {
    let e = (x.to_bits() >> 23) as i32 - 127;
    let v = f32::from_bits((x.to_bits() & 0x7fffff) | 0x3f800000);
    let z = (v - 1.0) / (v + 1.0);
    let z2 = z * z;
    e as f32 * core::f32::consts::LN_2
        + z * (2.0
            + z2 * (2.0 / 3.0
                + z2 * (2.0 / 5.0
                    + z2 * (2.0 / 7.0 + z2 * (2.0 / 9.0 + z2 * (2.0 / 11.0 + z2 * (2.0 / 13.0)))))))
}
pub fn erf(x: f32) -> f32 {
    let a = x.abs();
    let t = 1.0 / (1.0 + 0.3275911 * a);
    let v = 1.0
        - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t
            + 0.254829592)
            * t
            * exp(-a * a);
    if x < 0.0 {
        -v
    } else {
        v
    }
}
pub fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + exp(-x))
}
pub fn silu(x: f32) -> f32 {
    x * sigmoid(x)
}
pub fn gelu(x: f32) -> f32 {
    0.5 * x * (1.0 + erf(x * core::f32::consts::FRAC_1_SQRT_2))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn numerical_bounds() {
        for i in -8000..=8000 {
            let x = i as f32 * 0.01;
            let e = x.exp();
            assert!((exp(x) - e).abs() / e < 2e-6);
            assert!((log(e) - e.ln()).abs() < 1e-5);
            assert!((sqrt(e) - e.sqrt()).abs() / e.sqrt() < 2e-7);
        }
        for (x, want) in [
            (0.0, 0.0),
            (0.5, 0.5204998778),
            (1.0, 0.8427007929),
            (2.0, 0.995322265),
        ] {
            assert!((erf(x) - want).abs() < 5e-7);
        }
    }
}
