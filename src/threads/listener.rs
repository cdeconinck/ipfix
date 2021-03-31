use std::net::{UdpSocket};
use log::{info, error, debug};
use std::sync::mpsc;
use core::convert::TryInto;

use crate::netflow::*;
use crate::netflow::v5::*;
use crate::netflow::ipfix::*;

pub fn listen(url: &String, sender: mpsc::Sender<Box<dyn NetflowMsg>>) {
    let socket = UdpSocket::bind(url).expect(&format!("Failed to bind udp socket to {}", url));
    info!{"Listening on {}", url}

    let mut buf = [0; 1500];

    loop {
        debug!("Waiting for data...");
        let (received_bytes, from) = socket.recv_from(&mut buf).unwrap();
        debug!("Received {} bytes from {}", received_bytes, from);

        if received_bytes < SIZE_OF_NETFLOW_V5_HEADER {
            error!("Data to small for an ipfix message, expected at lest {} bytes", SIZE_OF_NETFLOW_V5_HEADER);
            continue;
        }

        // read the first 2 bytes to see what header we have
        let version = u16::from_be_bytes(buf[0..2].try_into().unwrap());
        let result = match version {
            5 => parse_v5_msg(&buf[0..received_bytes], received_bytes),
            10 => parse_ipfix_msg(from, &buf[0..received_bytes], received_bytes),
            _ => {
                error!("Invalid ipfix version, expected 5 or 10, read {}", version);
                continue;
            }
        };

        match result {
            Ok(list) => {
                for msg in list {
                    sender.send(msg).unwrap();
                }
            }
            Err(e) => error!("Error while parsing ipfix msg: {}", e)
        }
    }

    info!{"Closing UDP socket on {}", url};
    drop(socket);
}

fn parse_v5_msg(buf: &[u8], buf_len: usize) -> Result<Vec<Box<dyn NetflowMsg>>, String> {
    let header = NetflowHeaderV5::read(&buf[0..SIZE_OF_NETFLOW_V5_HEADER]);

    // check if the size correspond to our structure
    let pdu_size = (buf_len - SIZE_OF_NETFLOW_V5_HEADER) as u16 / header.count;
    if pdu_size != SIZE_OF_NETFLOW_V5_MSG as u16 {
        error!("Mismatch pud size, read {} but we expect a size of {} ", pdu_size, SIZE_OF_NETFLOW_V5_HEADER);
    }

    let mut pdu_list: Vec<Box<dyn NetflowMsg>> = vec!();
    let mut offset :usize = SIZE_OF_NETFLOW_V5_HEADER;

    for _ in 1..header.count {
        pdu_list.push(Box::new(NetflowMsgV5::read(&buf[offset..offset + SIZE_OF_NETFLOW_V5_MSG])));
        offset += SIZE_OF_NETFLOW_V5_MSG;
    }

    Ok(pdu_list)
}

fn parse_ipfix_msg(from: std::net::SocketAddr, buf: &[u8], buf_len: usize) -> Result<Vec<Box<dyn NetflowMsg>>, String> {
    let header = IpfixHeader::read(&buf[0..SIZE_OF_IPFIX_HEADER]);

    let pdu_list: Vec<Box<dyn NetflowMsg>> = vec!();
    Ok(pdu_list)
}