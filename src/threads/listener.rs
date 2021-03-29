use std::net::{UdpSocket, SocketAddr};
use log::{info, error, debug};
use std::sync::mpsc;
use std::io::Cursor;
use byteorder::{BigEndian, ReadBytesExt};

use crate::ipfixmsg::IpfixMsg;

pub fn listen(url: &String, sender: mpsc::Sender<IpfixMsg>) {
    let socket = UdpSocket::bind(url).expect(&format!("Failed to bind udp socket to {}", url));
    info!{"Listening on {}", url}

    let mut buf = [0; 1500];

    loop {
        debug!{"Waiting for data..."}
        let (nb_bytes, from) = socket.recv_from(&mut buf).unwrap();
        debug!{"Received {} bytes from {}", nb_bytes, from}

        match parse_msg(from, &buf[..nb_bytes]) {
            Ok(v) =>  sender.send(v).unwrap(),
            Err(e) => error!("Failed to parse ipfix msg : {}",  e),
        }
    }

    info!{"Closing UDP socket on {}", url}
    drop(socket)
}

fn parse_msg(exporter: SocketAddr, data: &[u8]) -> Result<IpfixMsg,String> {

    /*let version = BigEndian::read_u16(&data[0..2]);

    if version != 5 {
        return Err(format!("Invalid ipfix version, expected 5, read {}", version));
    }

    let count = BigEndian::read_u16(&data[2..4]);
    let uptime = BigEndian::read_u32(&data[4..8]);
    let timestamp = BigEndian::read_u64(&data[8..16]);
    let sequence_number = BigEndian::read_u32(&data[16..20]);
    let source_id = BigEndian::read_u32(&data[20..24]);

    let msg = IpfixMsg::read(&data[24..]);*/

    let mut rdr = Cursor::new(data);
    let version = rdr.read_u16::<BigEndian>().unwrap();

    if version != 5 {
        return Err(format!("Invalid ipfix version, expected 5, read {}", version));
    }

    let count = rdr.read_u16::<BigEndian>().unwrap();
    debug!("test {}", count);
    let uptime = rdr.read_u32::<BigEndian>().unwrap();
    let timestamp = rdr.read_u64::<BigEndian>().unwrap();
    let sequence_number = rdr.read_u32::<BigEndian>().unwrap();
    let source_id = rdr.read_u32::<BigEndian>().unwrap();

    let msg = IpfixMsg::read(&data[24..]);
    Ok(msg)
}