use core::convert::TryInto;
use log::{debug, error, info, trace};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::mpsc;

use crate::netflow::{ipfix, v5, NetflowMsg};

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
struct RouteurTemplate {
    exporter: SocketAddr,
    id: u16,
}

type MapTemplate = HashMap<RouteurTemplate, ipfix::TemplateFieldList>;

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

        // read the first 2 bytes to see what header we need to use
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
            Err(e) => error!("Error while parsing netflow msg {} from {} : {}", version, from, e),
        }
    }
}

fn parse_v5_msg(buf: &[u8], buf_len: usize) -> Result<Vec<Box<dyn NetflowMsg>>, String> {
    let header = v5::Header::read(&buf[0..v5::HEADER_SIZE])?;

    let nb_pdu = (buf_len - v5::HEADER_SIZE) / v5::DATA_SET_SIZE;
    if nb_pdu != header.count as usize {
        error!("Mismatch pdu number, we expect {} pdu but the header said {} ", nb_pdu, header.count);
    }

    let mut pdu_list: Vec<Box<dyn NetflowMsg>> = Vec::with_capacity(nb_pdu);
    let mut offset: usize = v5::HEADER_SIZE;

    while offset < buf_len {
        pdu_list.push(Box::new(v5::DataSet::read(&buf[offset..])?));
        offset += v5::DATA_SET_SIZE;
    }

    Ok(pdu_list)
}

fn parse_ipfix_msg(from: SocketAddr, buf: &[u8], buf_len: usize, template_list: &mut MapTemplate) -> Result<Vec<Box<dyn NetflowMsg>>, String> {
    let header = ipfix::Header::read(&buf[0..ipfix::HEADER_SIZE])?;
    // check if the size provied contains all the data
    if buf_len != header.length as usize {
        return Err(format!("Mismatch size read from the ipfix header ({:?}) and the packet size ({})", header, buf_len));
    }

    let mut offset = ipfix::HEADER_SIZE;
    let mut data_set_list: Vec<Box<dyn NetflowMsg>> = vec![];

    while offset < buf_len {
        let set = ipfix::SetHeader::read(&buf[offset..])?;
        offset += ipfix::SET_HEADER_SIZE;

        if set.set_id == ipfix::TEMPATE_SET_ID {
            let template_header = ipfix::TemplateHeader::read(&buf[offset..])?;
            if template_header.content_size() + ipfix::TEMPLATE_FIELD_SIZE != set.content_size() {
                return Err(format!(
                    "Mismatch template header size {} and set content size {},",
                    template_header.content_size() + ipfix::TEMPLATE_FIELD_SIZE,
                    set.content_size()
                ));
            }

            offset += ipfix::TEMPLATE_HEADER_SIZE;
            let mut template_field_list = ipfix::TemplateFieldList {
                from_type: ipfix::TEMPATE_SET_ID,
                fields: vec![],
            };

            for _ in 0..template_header.field_count {
                template_field_list.fields.push(ipfix::TemplateField::read(&buf[offset..])?);
                offset += ipfix::TEMPLATE_FIELD_SIZE;
            }

            info!("Received {:?} from {} {}", template_header, from, template_field_list);

            template_list.insert(
                RouteurTemplate {
                    exporter: from,
                    id: template_header.id,
                },
                template_field_list,
            );
        } else if set.set_id == ipfix::OPTION_TEMPATE_SET_ID {
            let option_template_header = ipfix::OptionTemplateHeader::read(&buf[offset..])?;

            if option_template_header.content_size() + ipfix::OPTION_TEMPLATE_HEADER_SIZE != set.content_size() {
                return Err(format!(
                    "Mismatch option template header size {} and set content size {},",
                    option_template_header.content_size() + ipfix::OPTION_TEMPLATE_HEADER_SIZE,
                    set.content_size()
                ));
            }

            offset += ipfix::OPTION_TEMPLATE_HEADER_SIZE;
            let mut template_field_list = ipfix::TemplateFieldList {
                from_type: ipfix::TEMPATE_SET_ID,
                fields: vec![],
            };

            for _ in 0..option_template_header.field_count {
                template_field_list.fields.push(ipfix::TemplateField::read(&buf[offset..])?);
                offset += ipfix::TEMPLATE_FIELD_SIZE;
            }

            info!("Received {:?} from {} {}", option_template_header, from, template_field_list);

            template_list.insert(
                RouteurTemplate {
                    exporter: from,
                    id: option_template_header.id,
                },
                template_field_list,
            );
        } else if set.set_id >= ipfix::DATA_SET_ID_MIN {
            let key = RouteurTemplate { exporter: from, id: set.set_id };

            match template_list.get(&key) {
                Some(template) => {
                    // we exporte only the data set for link to a template
                    if template.is_from_template() {
                        data_set_list.push(Box::new(ipfix::DataSet::read(&buf[offset..], &template)));
                    } else {
                        //TODO deal with a data set link to an option template
                        debug!("Skiping DATA set cause it's from an option template");
                    }
                }
                None => debug!("No template found for data set from {} with id {}", key.exporter, key.id),
            };

            offset += (set.length) as usize - ipfix::SET_HEADER_SIZE;
        } else {
            return Err(format!("Invalide set_id read : {}", set.set_id));
        }
    }

    Ok(data_set_list)
}
