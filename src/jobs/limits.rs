/// Compute the number of concurrent tasks based on the number of CPUs.
/// - x64 the number of CPUs; generous concurrency for I/O
/// - cap is 4096
pub fn compute_concurrency() -> usize {
    num_cpus::get().saturating_mul(64).min(4096)
}

/// Compute the size of the channel based on the given concurrency.
/// Ensure channel can handle bursts.
pub fn compute_channel_size(concurrency: usize) -> usize {
    (concurrency * 4).clamp(256, 16_384)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrency_is_within_bounds() {
        let c = compute_concurrency();
        assert!(c > 0);
        assert!(c <= 4096);
    }

    #[test]
    fn channel_size_clamps_low() {
        // 10 * 4 = 40, below the 256 floor.
        assert_eq!(compute_channel_size(10), 256);
    }

    #[test]
    fn channel_size_clamps_high() {
        // 5000 * 4 = 20_000, above the 16_384 ceiling.
        assert_eq!(compute_channel_size(5000), 16_384);
    }

    #[test]
    fn channel_size_scales_in_range() {
        assert_eq!(compute_channel_size(100), 400);
    }
}
