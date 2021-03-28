use log::{info};
use std::sync::mpsc;

use crate::entity::udp_message::Message;

pub fn parse(receiver: mpsc::Receiver<Message>) {
    loop {
        info!{"{}", receiver.recv().unwrap()};
    }
}