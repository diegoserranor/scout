use crate::subnets;
use std::error::Error;

/// Enumerate local networks.
pub fn networks() -> Result<(), Box<dyn Error>> {
    let nets = subnets::get()?;
    subnets::print(&nets);
    Ok(())
}
