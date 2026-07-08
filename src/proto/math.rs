//! no_std-shaped numeric helpers for the protocol cores.
//!
//! `f64::powi` and the transcendental methods live in `std`, not `core`. The
//! helpers here keep the small amount of protocol math the codecs need in a
//! `core`-only shape so the cores stay portable, without changing any result.

/// Raise `base` to a non-negative integer power via square-and-multiply.
///
/// Bit-identical to `f64::powi` for the exponents the codecs use: it mirrors the
/// compiler-rt `__powidf2` multiply order (multiply-then-square, skipping the
/// final square), so — floating-point multiplication being non-associative — it
/// reproduces `powi` exactly rather than a naive left-to-right product. The
/// `powi_bit_identical_to_std` test pins this. Keeping it bit-identical matters:
/// the bloom false-positive-rate feeds a reject comparison and the FMP backoff
/// feeds a `u64` timer, so any drift could change a decision.
pub(crate) fn powi(base: f64, exp: u32) -> f64 {
    let mut result = 1.0_f64;
    let mut b = base;
    let mut e = exp;
    loop {
        if e & 1 == 1 {
            result *= b;
        }
        e >>= 1;
        if e == 0 {
            break;
        }
        b *= b;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::powi;

    #[test]
    fn powi_bit_identical_to_std() {
        // The core square-and-multiply must match f64::powi bit-for-bit across
        // representative bases and every exponent the protocol math reaches, so
        // the FPR reject decision and the backoff timer are unchanged.
        let bases = [
            0.0, 1.0, 0.5, 0.5469, 0.5493, 0.5508, 0.9999, 1.5, 2.0, 3.7, 0.1, 1e-3,
        ];
        for &base in &bases {
            for exp in 0u32..=64 {
                assert_eq!(
                    powi(base, exp).to_bits(),
                    base.powi(exp as i32).to_bits(),
                    "powi mismatch at base={base}, exp={exp}"
                );
            }
        }
    }
}
