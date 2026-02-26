use anyhow::{Context, Result, anyhow};

pub fn ipv6_mask_from_prefix_len(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        (!0u128) << (128 - prefix_len)
    }
}

pub fn get_global_ipv6_prefix_from_interface(
    interface_name: &str,
    prefix_len: u8,
) -> Result<std::net::Ipv6Addr> {
    let ifaces = if_addrs::get_if_addrs().context("Failed to read network interfaces!")?;

    for iface_addr in ifaces {
        if iface_addr.name == interface_name
            && let if_addrs::IfAddr::V6(addr) = iface_addr.addr {
                let ip = addr.ip;
                if !(ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_unique_local()
                    || ip.is_unicast_link_local())
                {
                    return Ok(std::net::Ipv6Addr::from_bits(
                        ip.to_bits() & ipv6_mask_from_prefix_len(prefix_len),
                    ));
                }
            }
    }

    Err(anyhow!(
        "No global IPv6 address found on interface {interface_name}"
    ))
}
