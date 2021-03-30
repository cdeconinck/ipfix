use std::net::{UdpSocket, SocketAddr};
use log::{info, error, debug};
use std::sync::mpsc;
use bincode::Options;

use crate::ipfixmsg::*;

const SIZE_OF_IPFIXHEADER: usize = std::mem::size_of::<IpfixHeader>();
const SIZE_OF_IPFIXMSG: usize = std::mem::size_of::<IpfixMsg>();

pub fn listen(url: &String, sender: mpsc::Sender<IpfixMsg>) {
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

        let header: IpfixHeader = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .with_big_endian()
            .deserialize_from(&buf[0..24]).unwrap();

        if header.version != 5 {
            error!("Invalid ipfix version, expected 5, read {}", header.version);
            continue;
        }

        let mut offset :usize = SIZE_OF_IPFIXHEADER;
        for _ in 0..(header.count -1) {
            let msg: IpfixMsg = bincode::DefaultOptions::new()
                .with_fixint_encoding()
                .allow_trailing_bytes()
                .with_big_endian()
                .deserialize_from(&buf[offset..]).unwrap();

            offset += SIZE_OF_IPFIXMSG;

            sender.send(msg).unwrap()
        }
    }

    info!{"Closing UDP socket on {}", url};
    drop(socket);
}