use crate::utils::normalize_dns;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::net::IpAddr;

pub enum ParsedInput {
    Ip(IpNet),
    Dns(String),
}

pub(crate) mod sealed {
    use super::ParsedInput;
    pub trait Sealed {
        fn into_parsed(self) -> Result<ParsedInput, String>;
    }
}

#[allow(private_bounds)]
pub trait RadixTargetInput: sealed::Sealed {}

impl sealed::Sealed for &str {
    fn into_parsed(self) -> Result<ParsedInput, String> {
        if let Ok(net) = self.parse::<IpNet>() {
            Ok(ParsedInput::Ip(net))
        } else if let Ok(addr) = self.parse::<IpAddr>() {
            Ok(ParsedInput::Ip(ipaddr_to_host_net(addr)))
        } else {
            normalize_dns(self).map(ParsedInput::Dns)
        }
    }
}
impl RadixTargetInput for &str {}

impl sealed::Sealed for IpAddr {
    fn into_parsed(self) -> Result<ParsedInput, String> {
        Ok(ParsedInput::Ip(ipaddr_to_host_net(self)))
    }
}
impl RadixTargetInput for IpAddr {}

pub(crate) fn ipaddr_to_host_net(addr: IpAddr) -> IpNet {
    match addr {
        IpAddr::V4(a) => IpNet::V4(Ipv4Net::new(a, 32).unwrap()),
        IpAddr::V6(a) => IpNet::V6(Ipv6Net::new(a, 128).unwrap()),
    }
}
