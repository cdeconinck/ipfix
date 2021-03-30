use std::fmt;
use std::net::Ipv4Addr;

#[repr(packed)]
#[derive(Deserialize, Debug, Default)]
pub struct IpfixMsg {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub next_hop: u32,
    pub input_int: u16,
    pub output_int: u16,
    pub octets: u32,
    pub packets: u32,
    pub start_time: u32,
    pub end_time: u32,
    pub src_port: u16,
    pub dst_port: u16, 
    pub padding1: u8,
    pub tcp_flag: u8,
    pub protocol: u8,
    pub tos: u8,
    pub src_as: u16,
    pub dst_as: u16,
    pub src_mask: u8,
    pub dst_mask: u8,
    pub padding2: u16,
}

impl fmt::Display for IpfixMsg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "src_addr: {}, dst_addr: {}, octets: {}, packets: {}, protocol: {}, duration: {}ms", Ipv4Addr::from(self.src_addr), Ipv4Addr::from(self.dst_addr), self.octets, self.packets, self.protocol, self.end_time - self.start_time)
    }
}

//////////// IPFIX HEADER ////////////
/// 
#[repr(packed)]
#[derive(Deserialize, Debug)]
pub struct IpfixHeader {
    pub version: u16,
    pub count: u16,
    pub uptime: u32,
    pub timestamp: u64,
    pub seq_number: u32,
    pub source_id: u32,
}

impl fmt::Display for IpfixHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "version: {}, count: {}, uptime: {}, timestamp: {}, seq_number: {}, source_id: {}", self.version, self.count, self.uptime, self.timestamp, self.seq_number, self.source_id)
    }
}