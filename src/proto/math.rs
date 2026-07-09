//! no_std-shaped numeric helpers for the protocol cores.
//!
//! `f64::powi` and the transcendental methods live in `std`, not `core`. The
//! helpers here keep the small amount of protocol math the codecs need in a
//! `core`-only shape so the cores stay portable, without changing any result.

/// Raise `base` to a non-negative integer power via square-and-multiply.
///
/// Built from `core`-only IEEE-754 `f64` multiplication, so the result is
/// **deterministic across every platform** — the property that matters here,
/// since the bloom false-positive-rate feeds a reject comparison and the FMP
/// backoff feeds a `u64` timer, and mesh nodes must agree regardless of OS.
/// This is a strict improvement over `f64::powi`, which is not portably
/// bit-stable: Linux and macOS lower it to compiler-rt's `__powidf2` (whose
/// multiply-then-square order this mirrors, so we match them exactly), but
/// Windows/MSVC rounds differently (and by more as the exponent grows). The
/// `powi_deterministic_and_close` test pins our output to golden bits and bounds
/// the relative drift from `std`.
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
    fn powi_deterministic_and_close() {
        // Determinism: our square-and-multiply is pure IEEE-754 f64 arithmetic,
        // so these outputs are identical on every platform. Pinning the bits
        // guards cross-node agreement and locks against future drift. (The bit
        // patterns were captured from the impl itself; they also match Linux and
        // macOS `f64::powi` — see the golden vs Windows note below.)
        let golden = [
            ((0.5469, 4), 4591110734581567521u64),
            ((0.5, 2), 4598175219545276416),
            ((2.0, 10), 4652218415073722368),
            ((0.9999, 64), 4607124953935219716),
            ((1.5, 8), 4627907113471967232),
            ((3.7, 5), 4649310774781981293),
            ((0.1, 3), 4562254508917369341),
            ((0.5493, 4), 4591224636877479401),
            ((0.5508, 4), 4591296588123960286),
            ((0.5469, 14), 4552032634403898040),
        ];
        for ((base, exp), bits) in golden {
            assert_eq!(
                powi(base, exp).to_bits(),
                bits,
                "powi determinism drift at base={base}, exp={exp}"
            );
        }

        // Correctness: stay within a loose relative tolerance of `std::powi`
        // across every base and exponent the protocol math reaches — a broad
        // sanity sweep backing the exact golden pins above. `f64::powi` is not
        // portably bit-stable: Windows/MSVC drifts from Linux/macOS, and that
        // drift grows with the exponent (3 ULP already by exp=14), so an absolute
        // ULP bound is not portable. Relative error of any sane libm stays around
        // 1e-15 regardless of exponent, so 1e-11 clears the drift by ~1000x while
        // still catching a grossly wrong impl (multiply-order subtleties are
        // caught by the golden pins, not here).
        let bases = [
            0.0, 1.0, 0.5, 0.5469, 0.5493, 0.5508, 0.9999, 1.5, 2.0, 3.7, 0.1, 1e-3,
        ];
        for &base in &bases {
            for exp in 0u32..=64 {
                let ours = powi(base, exp);
                let std = base.powi(exp as i32);
                if std == 0.0 {
                    assert_eq!(
                        ours, 0.0,
                        "powi zero-case mismatch at base={base}, exp={exp}"
                    );
                } else {
                    let rel = ((ours - std) / std).abs();
                    assert!(
                        rel <= 1e-11,
                        "powi relative drift at base={base}, exp={exp}: ours={ours:e}, std={std:e}, rel={rel:e}"
                    );
                }
            }
        }
    }
}
