use core::convert::TryInto;
use std::fmt;
use std::net::Ipv4Addr;

use crate::netflow::NetflowMsg;

pub const VERSION: u16 = 5;

/******************************** MSG HEADER ********************************/

pub const HEADER_SIZE: usize = std::mem::size_of::<Header>();

/// from https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006108
#[derive(Debug)]
pub struct Header {
    pub version: u16,    // NetFlow export format version number
    pub count: u16,      // Number of flows exported in this packet (1-30)
    pub uptime: u32,     // Current time in milliseconds since the export device booted
    pub unix_secs: u32,  // Current count of seconds since 0000 UTC 1970
    pub unix_nsecs: u32, // Residual nanoseconds since 0000 UTC 1970
    pub seq_number: u32, // Sequence counter of total flows seen
    pub engine_type: u8, // Type of flow-switching engine
    pub engine_id: u8,   // Slot number of the flow-switching engine
    sampl: u16,          // First two bits hold the sampling mode; remaining 14 bits hold value of sampling interval
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
            sampl: u16::from_be_bytes(buf[22..24].try_into().unwrap()),
        })
    }

    #[inline]
    pub fn sampl_mode(&self) -> u16 {
        self.sampl >> 14
    }

    #[inline]
    pub fn sampl_interval(&self) -> u16 {
        self.sampl & 0b0011111111111111
    }
}

impl fmt::Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "version: {}, count: {}, uptime: {}ms, unix_secs: {}s, unix_nsecs: {}ns, seq_number: {}, engine_type: {}, engine_id: {}, sampl_mode: {}, sampl_interval: {}",
            self.version,
            self.count,
            self.uptime,
            self.unix_secs,
            self.unix_nsecs,
            self.seq_number,
            self.engine_type,
            self.engine_id,
            self.sampl_mode(),
            self.sampl_interval()
        )
    }
}

/******************************** DATA ********************************/

pub const DATA_SET_SIZE: usize = std::mem::size_of::<DataSet>();

/// from https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006186
#[derive(Debug)]
pub struct DataSet {
    pub src_addr: u32,   // Source IP address
    pub dst_addr: u32,   // Destination IP address
    pub next_hop: u32,   // IP address of next hop router
    pub input_int: u16,  // SNMP index of input interface
    pub output_int: u16, // SNMP index of output interface
    pub packets: u32,    // Packets in the flow
    pub octets: u32,     // Total number of Layer 3 bytes in the packets of the flow
    pub start_time: u32, // SysUptime at start of flow
    pub end_time: u32,   // SysUptime at the time the last packet of the flow was received
    pub src_port: u16,   // TCP/UDP source port number or equivalent
    pub dst_port: u16,   // TCP/UDP destination port number or equivalent
    pad1: u8,            // Unused (zero) bytes
    pub tcp_flag: u8,    // Cumulative OR of TCP flags
    pub protocol: u8,    // IP protocol type (for example, TCP = 6; UDP = 17)
    pub tos: u8,         // IP type of service (ToS)
    pub src_as: u16,     // Autonomous system number of the source, either origin or peer
    pub dst_as: u16,     // Autonomous system number of the destination, either origin or peer
    pub src_mask: u8,    // Source address prefix mask bits
    pub dst_mask: u8,    // Destination address prefix mask bits
    pad2: u16,           // Unused (zero) bytes
}

impl NetflowMsg for DataSet {}

impl fmt::Display for DataSet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "from: {}/{}:{}, to: {}/{}:{}, octets: {}, packets: {}, protocol: {}, duration: {}ms, src_ac: {}, dst_as: {}, tos: {}",
            Ipv4Addr::from(self.src_addr),
            self.src_mask,
            self.src_port,
            Ipv4Addr::from(self.dst_addr),
            self.dst_mask,
            self.dst_port,
            self.octets,
            self.packets,
            self.protocol,
            self.end_time - self.start_time,
            self.src_as,
            self.dst_as,
            self.tos
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
