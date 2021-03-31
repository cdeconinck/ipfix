use std::net::{UdpSocket, SocketAddr};
use log::{info, error, debug};
use std::sync::mpsc;
use core::convert::TryInto;
use std::collections::HashMap;

use crate::netflow::*;
use crate::netflow::v5::*;
use crate::netflow::ipfix::*;

struct ipfix_template_field {
	field_type: u32,
	field_length: u16,
}

struct routeur_template {
    address: u32,
    id: u16,
}

type map_template_t = HashMap<routeur_template, Vec<ipfix_template_field>>;

pub fn listen(url: &String, sender: mpsc::Sender<Box<dyn NetflowMsg>>) {
    let socket = UdpSocket::bind(url).expect(&format!("Failed to bind udp socket to {}", url));
    info!{"Listening on {}", url}

    let mut buf = [0; 1500];
    let mut template_list: map_template_t = HashMap::new();

    loop {
        debug!("Waiting for data...");
        let (received_bytes, from) = socket.recv_from(&mut buf).unwrap();
        debug!("Received {} bytes from {}", received_bytes, from);

        if received_bytes < NETFLOW_V5_HEADER_SIZE {
            error!("Data to small for an ipfix message, expected at lest {} bytes", NETFLOW_V5_HEADER_SIZE);
            continue;
        }

        // read the first 2 bytes to see what header we have
        let version = u16::from_be_bytes(buf[0..2].try_into().unwrap());
        let result = match version {
            NETFLOW_V5_ID => parse_v5_msg(&buf[0..received_bytes], received_bytes),
            NETFLOW_IPFIX_ID => parse_ipfix_msg(from, &buf[0..received_bytes], received_bytes, &mut template_list),
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
    let header = NetflowHeaderV5::read(&buf[0..NETFLOW_V5_HEADER_SIZE]);

    // check if the size correspond to our structure
    let pdu_size = (buf_len - NETFLOW_V5_HEADER_SIZE) as u16 / header.count;
    if pdu_size != NETFLOW_V5_MSG_SIZE as u16 {
        error!("Mismatch pud size, read {} but we expect a size of {} ", pdu_size, NETFLOW_V5_HEADER_SIZE);
    }

    let mut pdu_list: Vec<Box<dyn NetflowMsg>> = vec!();
    let mut offset :usize = NETFLOW_V5_HEADER_SIZE;

    for _ in 1..header.count {
        pdu_list.push(Box::new(NetflowMsgV5::read(&buf[offset..offset + NETFLOW_V5_MSG_SIZE])));
        offset += NETFLOW_V5_MSG_SIZE;
    }

    Ok(pdu_list)
}

fn parse_ipfix_msg(from: SocketAddr, buf: &[u8], buf_len: usize, template_list: &mut map_template_t) -> Result<Vec<Box<dyn NetflowMsg>>, String> {
    let pdu_list: Vec<Box<dyn NetflowMsg>> = vec!();

    let header = IpfixHeader::read(&buf[0..IPFIX_HEADER_SIZE]);
    let mut offset = IPFIX_HEADER_SIZE;

    while offset < header.length as usize {
        let set = IpfixSetHeader::read(&buf[offset..offset+ IPFIX_SET_HEADER_SIZE]);
        offset += IPFIX_SET_HEADER_SIZE;

        if set.set_id == IPFIX_TEMPATE_SET_ID {
            info!{"Template Set received from {}", from} // skiping the parsing for now
            offset += (set.length) as usize - IPFIX_SET_HEADER_SIZE;

        } else if set.set_id == IPFIX_OPTION_TEMPATE_SET_ID {
            info!{"Option Template Set received from {}", from}
            offset += (set.length) as usize - IPFIX_SET_HEADER_SIZE; // skiping the parsing for now

        } else if set.set_id >= IPFIX_DATA_SET_ID_MIN {
            info!{"Data Set received from {}", from}
            offset += (set.length) as usize - IPFIX_SET_HEADER_SIZE;
        }
        else {
            return Err(format!("Invalide set_id read : {}", set.set_id));
        }
    }

    Ok(pdu_list)
}