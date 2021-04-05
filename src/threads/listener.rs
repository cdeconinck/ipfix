use std::net::{UdpSocket, SocketAddr};
use log::{debug, error, info, trace};
use std::sync::mpsc;
use core::convert::TryInto;
use std::collections::HashMap;
use std::fmt::Write;

use crate::netflow::{v5, ipfix, NetflowMsg};

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
struct RouteurTemplate {
    exporter: SocketAddr,
    id: u16,
}

type MapTemplate = HashMap<RouteurTemplate, Vec<ipfix::TemplateField>>;

pub fn listen(addr: SocketAddr, sender: mpsc::Sender<Box<dyn NetflowMsg>>) {
    let socket = UdpSocket::bind(&addr).expect(&format!("Failed to bind UDP socket to {}", &addr));
    info!("Listening for UDP packet on {}", &addr);

    let mut buf = [0; 1500];
    let mut template_list: MapTemplate = HashMap::new();

    loop {
        debug!("Waiting for data...");
        let (rcv_bytes, from) = socket.recv_from(&mut buf).expect("Didn't received data");
        trace!("Received {} bytes from {}", rcv_bytes, from);

        if rcv_bytes < v5::HEADER_SIZE {
            error!("Data to small for a netflow packet from {}, expected at least {} bytes", from, v5::HEADER_SIZE);
            continue;
        }

        // read the first 2 bytes to see what header we have
        let version = u16::from_be_bytes(buf[0..2].try_into().unwrap());
        let result = match version {
            v5::VERSION => parse_v5_msg(&buf[0..rcv_bytes], rcv_bytes),
            ipfix::VERSION => parse_ipfix_msg(from, &buf[0..rcv_bytes], rcv_bytes, &mut template_list),
            _ => {
                error!("Invalid netflow version in packet from {}, read {}", from, version);
                continue;
            }
        };

        match result {
            Ok(list) => {
                for msg in list {
                    sender.send(msg).unwrap();
                }
            }
            Err(e) => error!("Error while parsing netflow msg {} from {} : {}", version, from, e)
        }
    }
}

fn parse_v5_msg(buf: &[u8], buf_len: usize) -> Result<Vec<Box<dyn NetflowMsg>>, String> {
    let header = v5::Header::read(&buf[0..v5::HEADER_SIZE]);

    // check if the size correspond to our structure
    let pdu_size = (buf_len - v5::HEADER_SIZE) as u16 / header.count;
    if pdu_size != v5::DATA_SET_SIZE as u16 {
        error!("Mismatch pud size, read {} but we expect a size of {} ", pdu_size, v5::HEADER_SIZE);
    }

    let mut pdu_list: Vec<Box<dyn NetflowMsg>> = vec!();
    let mut offset: usize = v5::HEADER_SIZE;

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
        return Err(format!("Mismatch size read from the ipfix header ({:?}) and the packet size ({})", header, buf_len));
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

            let mut field_list_str = String::new();
            for field in &field_list {
                write!(field_list_str, "\n\t{:?}", field).unwrap();
            }

            info!("{:?} received from {} {}", template_header, from, field_list_str);

            template_list.insert(RouteurTemplate { exporter: from, id: template_header.id }, field_list);
        } else if set.set_id == ipfix::OPTION_TEMPATE_SET_ID {
            let mut field_list: Vec<ipfix::TemplateField> = vec!();
            let option_template_header = ipfix::OptionTemplateHeader::read(&buf[offset..]);
            offset += ipfix::OPTTION_TEMPLATE_HEADER_SIZE;

            for _ in 0..option_template_header.field_count {
                field_list.push(ipfix::TemplateField::read(&buf[offset..]));
                offset += ipfix::TEMPLATE_FIELD_SIZE;
            }

            let mut field_list_str = String::new();
            for field in &field_list {
                write!(field_list_str, "\n\t{:?}", field).unwrap();
            }

            info!("{:?} received from {} {}", option_template_header, from, field_list_str);

            template_list.insert(RouteurTemplate { exporter: from, id: option_template_header.id }, field_list);
        } else if set.set_id >= ipfix::DATA_SET_ID_MIN {
            let key = RouteurTemplate{ exporter: from, id: set.set_id };
            match template_list.get(&key) {
                Some(template) => {
                    data_set_list.push(Box::new(ipfix::DataSet::read(&buf[offset..], &template)));
                },
                None => {
                    error!("No template found for data set from {} with id {}", key.exporter, key.id);
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