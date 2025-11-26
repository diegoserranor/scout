use getifs::{Ifv4Net, local_ipv4_addrs};
use smallvec_wrapper::SmallVec;
use std::error::Error;

/// Wrapper function for `getifs::local_ipv4_addrs()`.
pub fn get() -> Result<SmallVec<Ifv4Net>, Box<dyn Error>> {
    let subnets = local_ipv4_addrs()?;
    Ok(subnets)
}

/// Enumerate local IPv4 subnets.
pub fn print(subnets: &[Ifv4Net]) {
    if subnets.is_empty() {
        println!("No local IPv4 subnets detected.");
        return;
    }

    for subnet in subnets {
        println!("- {}", subnet.net());
    }
}
