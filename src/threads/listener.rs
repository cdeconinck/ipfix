use std::net::UdpSocket;
use log::{info};
use std::sync::mpsc;

use crate::entity::udp_message::Message;

pub fn init(url: &String, sender: mpsc::Sender<Message>) {
    let socket = UdpSocket::bind(url).expect(&format!("Failed to bind udp socket to {}", url));
    info!{"Listening on {}", url}

    let mut buf = [0; 1500];

    loop {
        info!{"Waiting for data..."}
        let (nb_bytes, from) = socket.recv_from(&mut buf).unwrap();
        info!{"Reiceived Data"}

        // extract the data into a another array
        let mut data = vec![0; nb_bytes];
        &data[..nb_bytes].copy_from_slice(&buf[..nb_bytes]);

        sender.send(Message{src_addr: from.to_string(), size: nb_bytes, buf: data}).unwrap();
    }

    info!{"Closing UDP socket on {}", url}
    drop(socket)
}