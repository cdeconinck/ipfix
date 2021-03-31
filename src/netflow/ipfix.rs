use bincode::Options;
use std::net::Ipv4Addr;

use crate::netflow::NetflowMsg;

pub static SIZE_OF_IPFIX_HEADER: usize = std::mem::size_of::<IpfixHeader>();

/// MSG HEADER ////

/*
from https://tools.ietf.org/html/rfc7011

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Version Number          |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Export Time                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Sequence Number                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Observation Domain ID                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#[derive(Deserialize, Debug)]
pub struct IpfixHeader {
    pub version: u16,       // Version of IPFIX to which this Message conforms
    pub length: u16,        // Total length of the IPFIX Message, measured in octets, including Message Header and Set(s).
    pub export_time: u32,   // Time at which the IPFIX Message Header leaves the Exporter expressed in seconds since the UNIX epoch
    pub seq_number: u32,    // Incremental sequence counter modulo 2^32 of all IPFIX Data Record sent in the current stream from the current Observation Domain by the Exporting Process.
    pub domain_id: u32,     // Identifier used to uniquely identify to the Collecting Process the Observation Domain that metered the Flows
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

/// SET HEADER ///

/*
from https://tools.ietf.org/html/rfc7011

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Set ID               |          Length               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

pub static IPFIX_TEMPATE_SET_ID: u16 = 2;
pub static IPFIX_OPTION_TEMPATE_SET_ID: u16 = 3;
pub static IPFIX_DATA_SET_ID_MIN: u16 = 256;

#[derive(Deserialize, Debug)]
pub struct IpfixSetHeader {
    pub set_id: u16,  // Identifies the Set.
    pub length: u16,  // Total length of the Set, in octets, including the Set Header, all records, and the optional padding
}

impl IpfixSetHeader {
    pub fn read(buf: &[u8]) -> Self {
         bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_big_endian()
            .deserialize_from::<_,Self>(buf).unwrap()
    }
}

/// TEMPLATE RECORD HEADER ///

/*
from https://tools.ietf.org/html/rfc7011

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Template ID (> 255)      |         Field Count           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#[derive(Deserialize, Debug)]
pub struct IpfixTemplateHeader {
    pub id: u16,            // Each Template Record is given a unique Template ID in the range 256 to 65535
    pub field_count: u16,   // Number of fields in this Template Record.

}

impl IpfixTemplateHeader {
    pub fn read(buf: &[u8]) -> Self {
         bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_big_endian()
            .deserialize_from::<_,Self>(buf).unwrap()
    }
}


/// DATA SET ///

#[derive(Deserialize, Debug, Default)]
pub struct IpfixDataSet {
    pub src_addr: u32,
    pub dst_addr: u32,
    pub input_int: u16,
    pub output_int: u16,
    pub octets: u32,
    pub packets: u32,
    pub start_time: u32,
    pub end_time: u32,
    pub src_port: u16,
    pub dst_port: u16, 
    pub protocol: u8,
    pub tos: u8,
}

impl IpfixDataSet {
    pub fn read(buf: &[u8]) -> Self {
        // parsing manuel en se basant sur un template
        IpfixDataSet{..Default::default()}
    }
}

impl NetflowMsg for IpfixDataSet {
    fn print(&self) -> String {
        format!("src_addr: {}, dst_addr: {}, octets: {}, packets: {}, protocol: {}, duration: {}ms", Ipv4Addr::from(self.src_addr), Ipv4Addr::from(self.dst_addr), self.octets, self.packets, self.protocol, self.end_time - self.start_time)
    }
}