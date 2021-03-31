use std::net::{UdpSocket};
use log::{info, error, debug};
use std::sync::mpsc;

use crate::ipfixmsg::*;

const SIZE_OF_IPFIXHEADER: usize = std::mem::size_of::<IpfixHeader>();
const SIZE_OF_IPFIXMSG: usize = std::mem::size_of::<IpfixMsgV5>();

pub fn listen(url: &String, sender: mpsc::Sender<Box<dyn IpfixMsg>>) {
    let socket = UdpSocket::bind(url).expect(&format!("Failed to bind udp socket to {}", url));
    info!{"Listening on {}", url}

    let mut buf = [0; 1500];

    loop {
        debug!("Waiting for data...");
        let (nb_bytes, from) = socket.recv_from(&mut buf).unwrap();
        debug!("Received {} bytes from {}", nb_bytes, from);

        if nb_bytes < SIZE_OF_IPFIXHEADER {
            error!("Data to small for an ipfix message, expected at lest {} bytes", SIZE_OF_IPFIXHEADER);
            continue;
        }

        let header = IpfixHeader::read(&buf[0..SIZE_OF_IPFIXHEADER]);
        if header.version != 5 {
            error!("Invalid ipfix version, expected 5, read {}", header.version);
            continue;
        }

        let mut offset :usize = SIZE_OF_IPFIXHEADER;

        for _ in 1..header.count {
            let msg = IpfixMsgV5::read(&buf[offset..offset + SIZE_OF_IPFIXMSG]);
            sender.send(Box::new(msg)).unwrap();
            offset += SIZE_OF_IPFIXMSG;
        }
    }

    info!{"Closing UDP socket on {}", url};
    drop(socket);
}