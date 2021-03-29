use std::net::{UdpSocket, SocketAddr};
use log::{info, error, debug};
use std::sync::mpsc;
use byteorder::{ByteOrder, LittleEndian};
use core::convert::TryInto;

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
    let version = LittleEndian::read_u16(&data[0..2]);
    let version2 = LittleEndian::read_u16(&data[2..4]);

    //let version = u16::from_be_bytes(data[0..2].try_into().unwrap());
    if version != 5 {
        return Err(format!("Invalid ipfix version, expected 5, read {} {}", version, version2));
    }

    Ok(IpfixMsg {..Default::default()})
}