use core::convert::TryInto;
use log::{error, info, trace};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::mpsc;

use crate::flow::{self, Flow, Template};

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

pub fn listen(addr: SocketAddr, sender: mpsc::Sender<Vec<Box<dyn Flow>>>) {
    let socket = UdpSocket::bind(&addr).expect(&format!("Failed to bind UDP socket to {}", &addr));
    info!("Listening for UDP packet on {}", &addr);

    let mut buf = [0; 1500];
    let mut exporter_list: ExporterList = HashMap::new();
    const MIN_BUF_LEN: usize = 2;

    loop {
        trace!("Waiting for data...");
        let (rcv_bytes, from) = socket.recv_from(&mut buf).expect("Didn't received data");
        trace!("Received {} bytes from {}", rcv_bytes, from);

        if rcv_bytes < MIN_BUF_LEN {
            error!("Data to small for a netflow packet from {}, expected at least {} bytes", from, MIN_BUF_LEN);
            continue;
        }

        // read the first 2 bytes to see what header we need to use
        let version = u16::from_be_bytes(buf[0..MIN_BUF_LEN].try_into().unwrap());
        let msg_list = match version {
            flow::netflow5::VERSION => parse_v5_msg(&buf[0..rcv_bytes]),
            flow::ipfix::VERSION => parse_ipfix_msg(from.ip(), &buf[0..rcv_bytes], &mut exporter_list),
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

fn parse_v5_msg(buf: &[u8]) -> Result<Vec<Box<dyn Flow>>, String> {
    use flow::netflow5::*;
    let buf_len = buf.len();

    let header = Header::read(&buf[0..Header::SIZE])?;

    let nb_pdu = (buf_len - Header::SIZE) / DataSet::SIZE;
    if nb_pdu != header.count as usize {
        return Err(format!(
            "Mismatch pdu number, expect {} pdu but the count field in the header containes another value: {} ",
            nb_pdu, header
        ));
    }

    let mut pdu_list: Vec<Box<dyn Flow>> = Vec::with_capacity(nb_pdu);
    let mut offset: usize = Header::SIZE;

    while offset < buf_len {
        let mut pdu = DataSet::read(&buf[offset..])?;
        pdu.add_sampling(header.sampl_interval() as u32);
        pdu_list.push(Box::new(pdu));

        offset += DataSet::SIZE;
    }

    Ok(pdu_list)
}

fn parse_ipfix_msg(from: IpAddr, buf: &[u8], exporter_list: &mut ExporterList) -> Result<Vec<Box<dyn Flow>>, String> {
    use flow::ipfix::*;
    let buf_len = buf.len();

    let header = Header::read(&buf[0..])?;
    // check if the size provied contains all the data
    if buf_len != header.length as usize {
        return Err(format!("Mismatch size read from the ipfix header ({:?}) and the packet size ({})", header, buf_len));
    }

    let mut offset = Header::SIZE;
    let mut data_set_list: Vec<Box<dyn Flow>> = vec![];
    let padding: usize = 4;

    while offset < buf_len {
        let set = SetHeader::read(&buf[offset..])?;
        offset += SetHeader::SIZE;
        let end_of_set = offset + set.content_size();

        if set.id == DataSetTemplate::SET_ID {
            while (offset + padding) < end_of_set {
                let (template, size_read) = DataSetTemplate::read(&buf[offset..])?;
                let exporter_key = Exporter {
                    addr: from,
                    domain_id: header.domain_id,
                };

                info!("Template received from {:?}\n{}", exporter_key, template);
                offset += size_read;

                exporter_list.entry(exporter_key).or_default().template.insert(template.header.id, Template::IpfixDataSet(template));
            }
        } else if set.id == OptionDataSetTemplate::SET_ID {
            while (offset + padding) < end_of_set {
                let (option_template, size_read) = OptionDataSetTemplate::read(&buf[offset..])?;
                let exporter_key = Exporter {
                    addr: from,
                    domain_id: header.domain_id,
                };

                info!("Option template received from {:?}\n{}", exporter_key, option_template);
                offset += size_read;

                exporter_list
                    .entry(exporter_key)
                    .or_default()
                    .template
                    .insert(option_template.header.id, Template::IpfixOptionDataSet(option_template));
            }
        } else if set.id >= DataSet::MIN_SET_ID {
            let exporter_key = Exporter {
                addr: from,
                domain_id: header.domain_id,
            };

            if let Some(infos) = exporter_list.get_mut(&exporter_key) {
                if let Some(template) = infos.template.get(&set.id) {
                    match template {
                        Template::IpfixDataSet(t) => {
                            while (offset + padding) < end_of_set {
                                let mut msg = DataSet::read(&buf[offset..], &t.fields, t.length)?;
                                msg.add_sampling(infos.sampling as u64);
                                data_set_list.push(Box::new(msg));
                                offset += t.length;
                            }
                        }
                        Template::IpfixOptionDataSet(t) => {
                            while (offset + padding) < end_of_set {
                                let msg = DataSet::read(&buf[offset..], &t.fields, t.length)?;
                                info!("Option data set received : {}", msg);
                                offset += t.length;

                                // check if the sampling interval is set in this record
                                if let Some(&FieldValue::U32(v)) = msg.fields.get(&FieldType::SamplingInterval) {
                                    if infos.sampling != v {
                                        infos.sampling = v;
                                        info!("Setting the sampling for {:?} to {}", &exporter_key, infos.sampling);
                                    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // TODO
    const NETFLOW5_MSG: [u8; 168] = hex!(
        "00 05 00 03 00 00 2e ae 60 86 d4 c7 2c 4a 07 28
         00 00 00 16 01 00 00 00 70 0a 14 0a ac 1e be 0a
         ac c7 0f 01 00 00 00 00 00 00 00 1b 00 00 01 69
         00 00 2c 8e 00 00 2e 13 00 28 00 50 00 00 06 00
         a8 64 17 93 1d 05 00 00 c0 a8 14 0a ca 0c be 0a
         ac c7 0f 01 00 00 00 00 00 00 02 23 00 00 03 df
         00 00 2c 34 00 00 2d bb 00 28 01 bb 00 00 06 00
         ff 5c af 70 1a 03 00 00 0a 0a 14 7a 54 0c be d2
         c0 c7 0f 01 00 00 00 00 00 00 01 ab 00 00 00 8b
         00 00 2d 35 00 00 2e 84 2e e1 1f 90 00 00 06 00
         f4 97 e1 16 15 06 00 00"
    );

    const TEMPLATE_IPFIX_MSG: [u8; 132] = hex!(
        "00 0a 00 84 60 6c 55 89 df b2 ba d2 00 08 00 00
         00 02 00 74 01 00 00 1b 00 08 00 04 00 0c 00 04
         00 05 00 01 00 04 00 01 00 07 00 02 00 0b 00 02
         00 20 00 02 00 0a 00 04 00 3a 00 02 00 09 00 01
         00 0d 00 01 00 10 00 04 00 11 00 04 00 0f 00 04
         00 06 00 01 00 0e 00 04 00 01 00 08 00 02 00 08
         00 34 00 01 00 35 00 01 00 98 00 08 00 99 00 08
         00 88 00 01 00 3d 00 01 00 f3 00 02 00 f5 00 02
         00 36 00 04"
    );

    const OPTION_TEMPLATE_IPFIX_MSG: [u8; 72] = hex!(
        "00 0a 00 48 60 6c 55 a9 00 01 eb 6a 00 08 00 00
         00 03 00 38 02 00 00 0b 00 01 00 90 00 04 00 29
         00 08 00 2a 00 08 00 a0 00 08 00 82 00 04 00 83
         00 10 00 22 00 04 00 24 00 02 00 25 00 02 00 d6
         00 01 00 d7 00 01 00 00"
    );

    const DATA_SET_IPFIX_MSG: [u8; 190] = hex!(
        "00 0a 00 be 60 6c 55 a7 ff e5 ab d5 00 08 00 00
         01 00 00 ae 3e d4 68 d1 0d 20 db 4a 00 06 bc ee
         01 bb 00 00 00 00 03 3d 00 00 20 15 00 00 33 89
         00 00 40 7d 25 31 ec 76 18 00 00 02 f9 00 00 00
         00 00 00 00 40 00 00 00 00 00 00 00 01 79 79 00
         00 01 78 a7 2e 6f 00 00 00 01 78 a7 2e 6f 00 02
         ff 00 00 00 00 00 00 00 00 d5 d7 24 b2 c1 46 12
         90 00 06 13 74 00 19 00 00 00 00 03 3d 00 00 1e
         11 00 00 33 89 00 00 3f 94 25 31 ec 90 18 00 00
         02 f9 00 00 00 00 00 00 00 5a 00 00 00 00 00 00
         00 01 39 39 00 00 01 78 a7 2e 6e 00 00 00 01 78
         a7 2e 6e 00 02 ff 00 00 00 00 00 00 00 00"
    );

    const OPTION_DATA_SET_IPFIX_MSG: [u8; 80] = hex!(
        "00 0a 00 50 60 6c 55 a9 00 01 eb 6a 00 08 00 00
         02 00 00 40 00 00 00 02 00 00 00 09 31 c3 26 c6
         00 00 00 26 5b 7e cc 9b 00 00 01 4a a2 d7 85 28
         b2 84 10 20 00 00 00 00 00 00 00 00 00 00 00 00
         00 00 00 00 00 00 00 0a 00 0a 00 0a 0a 11 00 00"
    );

    #[test]
    fn read_netflow5_msg() {
        let pdu_list = parse_v5_msg(&NETFLOW5_MSG).unwrap();
        // expect 3 pdu in result
        assert_eq!(pdu_list.len(), 3);
    }

    #[test]
    fn read_ipfix_template() {
        let mut exporter_list: ExporterList = HashMap::new();
        let from = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let data_list = parse_ipfix_msg(from, &TEMPLATE_IPFIX_MSG, &mut exporter_list).unwrap();

        assert_eq!(exporter_list.len(), 1); // template should be stored in the map
        assert_eq!(data_list.len(), 0);
    }

    #[test]
    fn read_ipfix_option_template() {
        let mut exporter_list: ExporterList = HashMap::new();
        let from = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let data_list = parse_ipfix_msg(from, &OPTION_TEMPLATE_IPFIX_MSG, &mut exporter_list).unwrap();

        assert_eq!(exporter_list.len(), 1); // option template should be stored in the map
        assert_eq!(data_list.len(), 0);
    }

    #[test]
    fn read_ipfix_dataset() {
        let mut exporter_list: ExporterList = HashMap::new();
        let from = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // read and store the template for the dataset first
        parse_ipfix_msg(from, &TEMPLATE_IPFIX_MSG, &mut exporter_list).unwrap();
        assert_eq!(exporter_list.len(), 1);

        // then read the data set with the template
        let data_list = parse_ipfix_msg(from, &DATA_SET_IPFIX_MSG, &mut exporter_list).unwrap();
        assert_eq!(data_list.len(), 2);
    }

    #[test]
    fn read_ipfix_dataset_without_template() {
        let mut exporter_list: ExporterList = HashMap::new();
        let from = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let data_list = parse_ipfix_msg(from, &DATA_SET_IPFIX_MSG, &mut exporter_list).unwrap();

        // no template provied to read the dataset, so we expect 0 result
        assert_eq!(exporter_list.len(), 0);
        assert_eq!(data_list.len(), 0);
    }

    #[test]
    fn read_ipfix_dataset_with_template_from_difference_source() {
        let mut exporter_list: ExporterList = HashMap::new();
        let from_template = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        parse_ipfix_msg(from_template, &TEMPLATE_IPFIX_MSG, &mut exporter_list).unwrap();

        // change the source exporter for the flow data
        let from_data = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8));
        let data_list = parse_ipfix_msg(from_data, &DATA_SET_IPFIX_MSG, &mut exporter_list).unwrap();

        // template should't match for the parsing
        assert_eq!(data_list.len(), 0);
    }

    #[test]
    fn read_ipfix_option_dataset() {
        let mut exporter_list: ExporterList = HashMap::new();
        let from = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // read and store the option template for the dataset first
        parse_ipfix_msg(from, &OPTION_TEMPLATE_IPFIX_MSG, &mut exporter_list).unwrap();
        assert_eq!(exporter_list.len(), 1);

        // then read the data set with the template
        let data_list = parse_ipfix_msg(from, &OPTION_DATA_SET_IPFIX_MSG, &mut exporter_list).unwrap();

        // no result expected because the function just print the data parsed
        // TODO capture the output of the function and check if it contains the parsed data ?
        assert_eq!(data_list.len(), 0);
    }

    #[test]
    fn read_ipfix_option_dataset_without_template() {
        let mut exporter_list: ExporterList = HashMap::new();
        let from = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        let data_list = parse_ipfix_msg(from, &OPTION_DATA_SET_IPFIX_MSG, &mut exporter_list).unwrap();

        // no change expected
        assert_eq!(exporter_list.len(), 0);
        assert_eq!(data_list.len(), 0);
    }
}
