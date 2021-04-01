use std::net::{UdpSocket, SocketAddr};
use log::{info, error, debug};
use std::sync::mpsc;
use core::convert::TryInto;
use std::collections::HashMap;

use crate::netflow::{v5, ipfix, NetflowMsg};

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
struct RouteurTemplate {
    exporter: SocketAddr,
    id: u16,
}

type MapTemplate = HashMap<RouteurTemplate, Vec<ipfix::TemplateField>>;

pub fn listen(url: &String, sender: mpsc::Sender<Box<dyn NetflowMsg>>) {
    let socket = UdpSocket::bind(url).expect(&format!("Failed to bind udp socket to {}", url));
    info!("Listening on {}", url);

    let mut buf = [0; 1500];
    let mut template_list: MapTemplate = HashMap::new();

    loop {
        debug!("Waiting for data...");
        let (received_bytes, from) = socket.recv_from(&mut buf).unwrap();
        debug!("Received {} bytes from {}", received_bytes, from);

        if received_bytes < v5::HEADER_SIZE {
            error!("Data to small for an ipfix message, expected at lest {} bytes", v5::HEADER_SIZE);
            continue;
        }

        // read the first 2 bytes to see what header we have
        let version = u16::from_be_bytes(buf[0..2].try_into().unwrap());
        let result = match version {
            v5::VERSION => parse_v5_msg(&buf[0..received_bytes], received_bytes),
            ipfix::VERSION => parse_ipfix_msg(from, &buf[0..received_bytes], received_bytes, &mut template_list),
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

    info!("Closing UDP socket on {}", url);
    drop(socket);
}

fn parse_v5_msg(buf: &[u8], buf_len: usize) -> Result<Vec<Box<dyn NetflowMsg>>, String> {
    let header = v5::Header::read(&buf[0..v5::HEADER_SIZE]);

    // check if the size correspond to our structure
    let pdu_size = (buf_len - v5::HEADER_SIZE) as u16 / header.count;
    if pdu_size != v5::DATA_SET_SIZE as u16 {
        error!("Mismatch pud size, read {} but we expect a size of {} ", pdu_size, v5::HEADER_SIZE);
    }

    let mut pdu_list: Vec<Box<dyn NetflowMsg>> = vec!();
    let mut offset :usize = v5::HEADER_SIZE;

    for _ in 1..header.count {
        pdu_list.push(Box::new(v5::DataSet::read(&buf[offset..])));
        offset += v5::DATA_SET_SIZE;
    }

    Ok(pdu_list)
}

fn parse_ipfix_msg(from: SocketAddr, buf: &[u8], buf_len: usize, template_list: &mut MapTemplate) -> Result<Vec<Box<dyn NetflowMsg>>, String> {
    let mut data_set_list: Vec<Box<dyn NetflowMsg>> = vec!();

    let header = ipfix::Header::read(&buf[0..ipfix::HEADER_SIZE]);
    // check if the size provied contains all the data
    if buf_len != header.length as usize {
        return Err(format!("Mismatch size read from the ipfix header ({}) and the packet size ({})",header.length, buf_len));
    }

    let mut offset = ipfix::HEADER_SIZE;

    while offset < header.length as usize {
        let set = ipfix::SetHeader::read(&buf[offset..]);
        offset += ipfix::SET_HEADER_SIZE;

        if set.set_id == ipfix::TEMPATE_SET_ID {
            let mut field_list: Vec<ipfix::TemplateField> = vec!();
            let template_header = ipfix::TemplateHeader::read(&buf[offset..]);
            offset += ipfix::TEMPLATE_HEADER_SIZE;

            for _ in 0..template_header.field_count {
                field_list.push(ipfix::TemplateField::read(&buf[offset..]));
                offset += ipfix::TEMPLATE_FIELD_SIZE;
            }

            info!("Template Set received from {} : {}", from, template_header) ;
            for field in &field_list {
                info!("\t{}", field);
            }

            template_list.insert(RouteurTemplate { exporter: from, id: template_header.id }, field_list);
        } else if set.set_id == ipfix::OPTION_TEMPATE_SET_ID {
            info!("Option Template Set received from {}", from);
            
            offset += (set.length) as usize - ipfix::SET_HEADER_SIZE; // skiping the parsing for now
        } else if set.set_id >= ipfix::DATA_SET_ID_MIN {
            let key = RouteurTemplate{ exporter: from, id: set.set_id };
            match template_list.get(&key) {
                Some(template) => {
                    data_set_list.push(Box::new(ipfix::DataSet::read(&buf[offset..], &template)));
                },
                None => {
                    debug!("No template found for parsing data set from {} with id {}", key.exporter, key.id);
                }
            };

            offset += (set.length) as usize - ipfix::SET_HEADER_SIZE;
            debug!("Data Set received from {}", from);
        }
        else {
            return Err(format!("Invalide set_id read : {}", set.set_id));
        }
    }

    Ok(data_set_list)
}