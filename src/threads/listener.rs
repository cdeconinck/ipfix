use std::net::{UdpSocket, SocketAddr};
use log::{info, error, debug};
use std::sync::mpsc;
use std::io::Cursor;

use crate::ipfixmsg::*;

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

    info!{"Closing UDP socket on {}", url};
    drop(socket);
}

fn parse_msg(exporter: SocketAddr, data: &[u8]) -> Result<IpfixMsg, String> {
    let mut rdr = Cursor::new(data);

    let header = match IpfixHeader::read(&mut rdr) {
        Ok(h) => h,
        Err(e) => return Err(e),
    };

    debug!("{}", header);

    let msg = IpfixMsg::read(&data[24..]);
    Ok(msg)
}