use core::convert::TryInto;
use std::net::Ipv4Addr;

use crate::netflow::NetflowMsg;

pub const VERSION: u16 = 5;
pub const HEADER_SIZE: usize = std::mem::size_of::<Header>();

/// HEADER ///

#[derive(Debug)]
pub struct Header {
    pub version: u16,        // NetFlow export format version number
    pub count: u16,          // Number of flows exported in this packet (1-30)
    pub uptime: u32,         // Current time in milliseconds since the export device booted
    pub unix_secs: u32,      // Current count of seconds since 0000 UTC 1970
    pub unix_nsecs: u32,     // Residual nanoseconds since 0000 UTC 1970
    pub seq_number: u32,     // Sequence counter of total flows seen
    pub engine_type: u8,     // Type of flow-switching engine
    pub engine_id: u8,       // Slot number of the flow-switching engine
    pub sampl_interval: u16, // First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval
}

impl Header {
    pub fn read(buf: &[u8]) -> Result<Self, String> {
        Ok(Header {
            version: u16::from_be_bytes(buf[0..2].try_into().unwrap()),
            count: u16::from_be_bytes(buf[2..4].try_into().unwrap()),
            uptime: u32::from_be_bytes(buf[4..8].try_into().unwrap()),
            unix_secs: u32::from_be_bytes(buf[8..12].try_into().unwrap()),
            unix_nsecs: u32::from_be_bytes(buf[12..16].try_into().unwrap()),
            seq_number: u32::from_be_bytes(buf[16..20].try_into().unwrap()),
            engine_type: buf[20],
            engine_id: buf[21],
            sampl_interval: u16::from_be_bytes(buf[22..24].try_into().unwrap()),
        })
    }
}

/// DATA SET ///
pub const DATA_SET_SIZE: usize = std::mem::size_of::<DataSet>();

#[derive(Debug)]
pub struct DataSet {
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

impl NetflowMsg for DataSet {
    fn print(&self) -> String {
        format!(
            "src_addr: {}, dst_addr: {}, octets: {}, packets: {}, protocol: {}, duration: {}ms",
            Ipv4Addr::from(self.src_addr),
            Ipv4Addr::from(self.dst_addr),
            self.octets,
            self.packets,
            self.protocol,
            self.end_time - self.start_time
        )
    }
}

impl DataSet {
    pub fn read(buf: &[u8]) -> Result<Self, String> {
        Ok(DataSet {
            src_addr: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            dst_addr: u32::from_be_bytes(buf[4..8].try_into().unwrap()),
            next_hop: u32::from_be_bytes(buf[8..12].try_into().unwrap()),
            input_int: u16::from_be_bytes(buf[12..14].try_into().unwrap()),
            output_int: u16::from_be_bytes(buf[14..16].try_into().unwrap()),
            octets: u32::from_be_bytes(buf[16..20].try_into().unwrap()),
            packets: u32::from_be_bytes(buf[20..24].try_into().unwrap()),
            start_time: u32::from_be_bytes(buf[24..28].try_into().unwrap()),
            end_time: u32::from_be_bytes(buf[28..32].try_into().unwrap()),
            src_port: u16::from_be_bytes(buf[32..34].try_into().unwrap()),
            dst_port: u16::from_be_bytes(buf[34..36].try_into().unwrap()),
            pad1: buf[36],
            tcp_flag: buf[37],
            protocol: buf[38],
            tos: buf[39],
            src_as: u16::from_be_bytes(buf[40..42].try_into().unwrap()),
            dst_as: u16::from_be_bytes(buf[42..44].try_into().unwrap()),
            src_mask: buf[44],
            dst_mask: buf[45],
            pad2: u16::from_be_bytes(buf[46..48].try_into().unwrap()),
        })
    }
}
