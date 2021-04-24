use core::convert::TryInto;
use log::{error, info, trace};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::mpsc;

use crate::netflow::{ipfix, v5, NetflowMsg, Template};

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
struct Exporter {
    addr: IpAddr,   // ip source of the exporter
    domain_id: u32, // observation domain id unique to the exporter
}

struct ExporterInfos {
    pub sampling: u32,
    template: HashMap<u16, Template>,
}

impl Default for ExporterInfos {
    fn default() -> ExporterInfos {
        ExporterInfos {
            sampling: 1,
            template: HashMap::new(),
        }
    }
}

type ExporterList = HashMap<Exporter, ExporterInfos>;

pub fn listen(addr: SocketAddr, sender: mpsc::Sender<Vec<Box<dyn NetflowMsg>>>) {
    let socket = UdpSocket::bind(&addr).expect(&format!("Failed to bind UDP socket to {}", &addr));
    info!("Listening for UDP packet on {}", &addr);

    let mut buf = [0; 1500];
    let mut exporter_list: ExporterList = HashMap::new();

    loop {
        trace!("Waiting for data...");
        let (rcv_bytes, from) = socket.recv_from(&mut buf).expect("Didn't received data");
        trace!("Received {} bytes from {}", rcv_bytes, from);

        if rcv_bytes < v5::Header::SIZE {
            error!("Data to small for a netflow packet from {}, expected at least {} bytes", from, v5::Header::SIZE);
            continue;
        }

        // read the first 2 bytes to see what header we need to use
        let version = u16::from_be_bytes(buf[0..2].try_into().unwrap());
        let msg_list = match version {
            v5::VERSION => parse_v5_msg(&buf[0..rcv_bytes], rcv_bytes),
            ipfix::VERSION => parse_ipfix_msg(from.ip(), &buf[0..rcv_bytes], rcv_bytes, &mut exporter_list),
            _ => {
                error!("Invalid netflow version in packet from {}, read {}", from, version);
                continue;
            }
        };

        /*match msg_list {
            Ok(list) => {
                if !list.is_empty() {
                    sender.send(list).unwrap();
                }
            }
            Err(e) => error!("Error while parsing netflow msg {} from {} : {}", version, from, e),
        }*/
    }
}

fn parse_v5_msg(buf: &[u8], buf_len: usize) -> Result<Vec<Box<dyn NetflowMsg>>, String> {
    let header = v5::Header::read(&buf[0..v5::Header::SIZE])?;

    let nb_pdu = (buf_len - v5::Header::SIZE) / v5::DataSet::SIZE;
    if nb_pdu != header.count as usize {
        return Err(format!(
            "Mismatch pdu number, expect {} pdu but the count field in the header containes another value: {} ",
            nb_pdu, header
        ));
    }

    let mut pdu_list: Vec<Box<dyn NetflowMsg>> = Vec::with_capacity(nb_pdu);
    let mut offset: usize = v5::Header::SIZE;

    while offset < buf_len {
        let mut pdu = v5::DataSet::read(&buf[offset..])?;
        pdu.add_sampling(header.sampl_interval() as u32);
        pdu_list.push(Box::new(pdu));

        offset += v5::DataSet::SIZE;
    }

    Ok(pdu_list)
}

fn parse_ipfix_msg(from: IpAddr, buf: &[u8], buf_len: usize, exporter_list: &mut ExporterList) -> Result<Vec<Box<dyn NetflowMsg>>, String> {
    let header = ipfix::Header::read(&buf[0..])?;
    // check if the size provied contains all the data
    if buf_len != header.length as usize {
        return Err(format!("Mismatch size read from the ipfix header ({:?}) and the packet size ({})", header, buf_len));
    }

    let mut offset = ipfix::Header::SIZE;
    let mut data_set_list: Vec<Box<dyn NetflowMsg>> = vec![];
    let padding: usize = 4;

    while offset < buf_len {
        let set = ipfix::SetHeader::read(&buf[offset..])?;
        offset += ipfix::SetHeader::SIZE;
        let end_of_set = offset + set.content_size();

        if set.id == ipfix::DataSetTemplate::SET_ID {
            while (offset + padding) < end_of_set {
                let template = ipfix::DataSetTemplate::read(&buf[offset..])?;
                let exporter_key = Exporter {
                    addr: from,
                    domain_id: header.domain_id,
                };

                info!("Template received from {:?}\n{}", exporter_key, template);
                offset += template.offset;

                exporter_list.entry(exporter_key).or_default().template.insert(template.header.id, Template::IpfixDataSet(template));
            }
        } else if set.id == ipfix::OptionDataSetTemplate::SET_ID {
            while (offset + padding) < end_of_set {
                let option_template = ipfix::OptionDataSetTemplate::read(&buf[offset..])?;
                let exporter_key = Exporter {
                    addr: from,
                    domain_id: header.domain_id,
                };

                info!("Option template received from {:?}\n{}", exporter_key, option_template);
                offset += option_template.offset;

                exporter_list
                    .entry(exporter_key)
                    .or_default()
                    .template
                    .insert(option_template.header.id, Template::IpfixOptionDataSet(option_template));
            }
        } else if set.id >= ipfix::DataSet::MIN_SET_ID {
            let exporter_key = Exporter {
                addr: from,
                domain_id: header.domain_id,
            };

            if let Some(infos) = exporter_list.get_mut(&exporter_key) {
                if let Some(template) = infos.template.get(&set.id) {
                    match template {
                        Template::IpfixDataSet(t) => {
                            while (offset + padding) < end_of_set {
                                let mut msg = ipfix::DataSet::read(&buf[offset..], &t.fields, t.length)?;
                                msg.add_sampling(infos.sampling as u64);
                                data_set_list.push(Box::new(msg));
                                offset += t.length;
                            }
                        }
                        Template::IpfixOptionDataSet(t) => {
                            while (offset + padding) < end_of_set {
                                let msg = ipfix::DataSet::read(&buf[offset..], &t.fields, t.length)?;
                                info!("Option data set received : {}", msg);
                                offset += t.length;

                                // check if the sampling interval is set in this record
                                if let Some(&ipfix::FieldValue::U32(v)) = msg.fields.get(&ipfix::FieldType::SamplingInterval) {
                                    infos.sampling = v;
                                    info!("Setting the sampling for {:?} to {}", &exporter_key, infos.sampling);
                                }
                            }
                        }
                    }
                }
            }
        } else {
            return Err(format!("Invalide SetHeader id read : {}", set.id));
        }

        offset = end_of_set;
    }

    Ok(data_set_list)
}
