use core::convert::TryInto;
use std::fmt;
use std::net::Ipv4Addr;

use crate::flow::Flow;

pub const VERSION: u16 = 5;

/******************************** MSG HEADER ********************************/

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
    pub const SIZE: usize = 24;

    pub fn read(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < Self::SIZE {
            return Err(format!("Not enough space in buffer to read the NETFLOW V5 Header, required {} but received {}", Self::SIZE, buf.len()));
        }

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
        self.sampl & 0b0011_1111_1111_1111
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

impl Flow for DataSet {}

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
            self.duration(),
            self.src_as,
            self.dst_as,
            self.tos
        )
    }
}

impl DataSet {
    pub const SIZE: usize = 48;

    pub fn read(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < Self::SIZE {
            return Err(format!("Not enough space in buffer to read the NETFLOW V5 DataSet, required {} but received {}", Self::SIZE, buf.len()));
        }

        Ok(DataSet {
            src_addr: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            dst_addr: u32::from_be_bytes(buf[4..8].try_into().unwrap()),
            next_hop: u32::from_be_bytes(buf[8..12].try_into().unwrap()),
            input_int: u16::from_be_bytes(buf[12..14].try_into().unwrap()),
            output_int: u16::from_be_bytes(buf[14..16].try_into().unwrap()),
            packets: u32::from_be_bytes(buf[16..20].try_into().unwrap()),
            octets: u32::from_be_bytes(buf[20..24].try_into().unwrap()),
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

    #[inline]
    pub fn duration(&self) -> u32 {
        self.end_time - self.start_time
    }

    pub fn add_sampling(&mut self, sampling: u32) {
        if sampling > 0 {
            self.octets *= sampling;
            self.packets *= sampling;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    const HEADER_PAYLOD: [u8; Header::SIZE] = hex!(
        "00 05 00 10 00 00 04 b2 60 80 b8 9c 1a 47 ff 30
         00 00 00 02 01 00 00 00"
    );

    const DATA_SET_PAYLOD: [u8; DataSet::SIZE] = hex!(
        "70 0a 14 0a ac 1e be 0a ac c7 0f 01 00 00 00 00
         00 00 03 1b 00 00 01 03 00 00 02 36 00 00 03 a8
         00 28 00 50 00 00 06 00 c3 0d 35 bd 15 1a 00 00"
    );

    #[test]
    fn read_valid_msg_header() {
        let header = Header::read(&HEADER_PAYLOD).unwrap();

        assert_eq!(header.version, VERSION);
        assert_eq!(header.count, 16);
        assert_eq!(header.uptime, 1202);
        assert_eq!(header.unix_secs, 1619048604);
        assert_eq!(header.unix_nsecs, 440926000);
        assert_eq!(header.seq_number, 2);
        assert_eq!(header.engine_type, 1);
        assert_eq!(header.engine_id, 0);
        assert_eq!(header.sampl_mode(), 0);
        assert_eq!(header.sampl_interval(), 0);
    }

    #[test]
    #[should_panic]
    fn read_invalid_msg_header() {
        Header::read(&HEADER_PAYLOD[0..Header::SIZE - 1]).unwrap();
    }

    #[test]
    fn read_valid_data_msg() {
        let msg = DataSet::read(&DATA_SET_PAYLOD).unwrap();

        assert_eq!(msg.src_addr, u32::from(Ipv4Addr::new(112, 10, 20, 10)));
        assert_eq!(msg.dst_addr, u32::from(Ipv4Addr::new(172, 30, 190, 10)));
        assert_eq!(msg.next_hop, u32::from(Ipv4Addr::new(172, 199, 15, 1)));
        assert_eq!(msg.input_int, 0);
        assert_eq!(msg.output_int, 0);
        assert_eq!(msg.packets, 795);
        assert_eq!(msg.octets, 259);
        assert_eq!(msg.start_time, 566);
        assert_eq!(msg.end_time, 936);
        assert_eq!(msg.duration(), 370);
        assert_eq!(msg.src_port, 40);
        assert_eq!(msg.dst_port, 80);
        assert_eq!(msg.pad1, 0);
        assert_eq!(msg.tcp_flag, 0);
        assert_eq!(msg.protocol, 6);
        assert_eq!(msg.tos, 0);
        assert_eq!(msg.src_as, 49933);
        assert_eq!(msg.dst_as, 13757);
        assert_eq!(msg.src_mask, 21);
        assert_eq!(msg.dst_mask, 26);
    }

    #[test]
    #[should_panic]
    fn read_invalid_data_msg() {
        DataSet::read(&DATA_SET_PAYLOD[0..DataSet::SIZE - 1]).unwrap();
    }

    #[test]
    fn check_invalid_sampling() {
        let mut msg = DataSet::read(&DATA_SET_PAYLOD).unwrap();
        msg.add_sampling(0);

        assert_eq!(msg.packets, 795);
        assert_eq!(msg.octets, 259);
    }

    #[test]
    fn check_valid_sampling() {
        let sampling = 10;

        let mut msg = DataSet::read(&DATA_SET_PAYLOD).unwrap();
        msg.add_sampling(sampling);

        assert_eq!(msg.packets, 795 * sampling);
        assert_eq!(msg.octets, 259 * sampling);
    }
}
