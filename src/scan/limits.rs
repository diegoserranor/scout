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
