use crate::scan;
use std::error::Error;

/// Enumerate local networks.
pub fn networks() -> Result<(), Box<dyn Error>> {
    let nets = scan::subnets::get()?;
    scan::subnets::print(&nets);
    Ok(())
}
