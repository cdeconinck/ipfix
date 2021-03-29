use byteorder::{ByteOrder, BigEndian};
use std::fmt;
use std::net::Ipv4Addr;

#[derive(Debug, Default)]
pub struct IpfixMsg {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub input_int: u16,
    pub output_int: u16,
    pub octets: u32,
    pub packets: u32,
    pub src_port: u16,
    pub dst_port: u16, 
    pub duration: u64,
    pub protocol: u8,
}

impl IpfixMsg {
    pub fn read(buf: &[u8]) -> IpfixMsg {
        IpfixMsg {
            src_addr: BigEndian::read_u32(&buf[0..4]),
            dst_addr: BigEndian::read_u32(&buf[4..8]),
            input_int: BigEndian::read_u16(&buf[12..14]),
            output_int: BigEndian::read_u16(&buf[14..16]),
            packets: BigEndian::read_u32(&buf[16..20]),
            octets: BigEndian::read_u32(&buf[20..24]),
            /*duration: {
                let start = BigEndian::read_u32(&buf[24..38]);
                let end = BigEndian::read_u32(&buf[28..32]);
                return end - start;
            },*/
            src_port: BigEndian::read_u16(&buf[32..34]),
            dst_port: BigEndian::read_u16(&buf[34..36]),
            protocol: buf[38],
            ..Default::default()
        }
    }
}

impl fmt::Display for IpfixMsg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "src_addr: {}, dst_addr: {}, octets: {}, packets: {}, protocol: {}, duration: {}", Ipv4Addr::from(self.src_addr), Ipv4Addr::from(self.dst_addr), self.octets, self.packets, self.protocol, self.duration)
    }
}