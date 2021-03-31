use bincode::Options;
use std::net::Ipv4Addr;

use crate::netflow::NetflowMsg;

pub static SIZE_OF_NETFLOW_V5_HEADER: usize = std::mem::size_of::<NetflowHeaderV5>();
pub static SIZE_OF_NETFLOW_V5_MSG: usize = std::mem::size_of::<NetflowMsgV5>();

/// HEADER ///

#[derive(Deserialize, Debug)]
pub struct NetflowHeaderV5 {
    pub version: u16,       // NetFlow export format version number
    pub count: u16,         // Number of flows exported in this packet (1-30)
    pub uptime: u32,        // Current time in milliseconds since the export device booted
    pub unix_secs: u32,     // Current count of seconds since 0000 UTC 1970
    pub unix_nsecs: u32,    // Residual nanoseconds since 0000 UTC 1970
    pub seq_number: u32,    // Sequence counter of total flows seen
    pub engine_type: u8,    // Type of flow-switching engine
    pub engine_id: u8,      // Slot number of the flow-switching engine
    pub sampl_interval: u16 // First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval
}

impl NetflowHeaderV5 {
    pub fn read(buf: &[u8]) -> Self {
         bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_big_endian()
            .deserialize_from::<_,Self>(buf).unwrap()
    }
}

/// PDU ///

#[derive(Deserialize, Debug, Default)]
pub struct NetflowMsgV5 {
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
    pub pad1: u8,
    pub tcp_flag: u8,
    pub protocol: u8,
    pub tos: u8,
    pub src_as: u16,
    pub dst_as: u16,
    pub src_mask: u8,
    pub dst_mask: u8,
    pub pad2: u16,
}

impl NetflowMsg for NetflowMsgV5 {
    fn print(&self) -> String {
        format!("src_addr: {}, dst_addr: {}, octets: {}, packets: {}, protocol: {}, duration: {}ms", Ipv4Addr::from(self.src_addr), Ipv4Addr::from(self.dst_addr), self.octets, self.packets, self.protocol, self.end_time - self.start_time)
    }
}

impl NetflowMsgV5 {
    pub fn read(buf: &[u8]) -> Self {
         bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_big_endian()
            .deserialize_from::<_,Self>(buf).unwrap()
    }
}
