use std::fmt;
use std::net::Ipv4Addr;
use bincode::Options;

pub trait IpfixMsg : Send {
    fn print(&self) -> String;
}

#[derive(Deserialize, Debug, Default)]
pub struct IpfixMsgV5 {
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

impl IpfixMsg for IpfixMsgV5 {
    fn print(&self) -> String {
        format!("src_addr: {}, dst_addr: {}, octets: {}, packets: {}, protocol: {}, duration: {}ms", Ipv4Addr::from(self.src_addr), Ipv4Addr::from(self.dst_addr), self.octets, self.packets, self.protocol, self.end_time - self.start_time)
    }
}

impl IpfixMsgV5 {
    pub fn read(buf: &[u8]) -> Self {
         bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_big_endian()
            .deserialize_from::<_,Self>(buf).unwrap()
    }
}

//////////// IPFIX HEADER ////////////

#[derive(Deserialize, Debug)]
pub struct IpfixHeader {
    pub version: u16,
    pub count: u16,
    pub uptime: u32,
    pub timestamp: u64,
    pub seq_number: u32,
    pub source_id: u32,
}

impl IpfixHeader {
    pub fn read(buf: &[u8]) -> Self {
         bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_big_endian()
            .deserialize_from::<_,Self>(buf).unwrap()
    }
}

impl fmt::Display for IpfixHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "version: {}, count: {}, uptime: {}, timestamp: {}, seq_number: {}, source_id: {}", self.version, self.count, self.uptime, self.timestamp, self.seq_number, self.source_id)
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn test() {
        assert_eq!(2 + 2, 5);
    }
}