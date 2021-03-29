use log::{info};
use std::sync::mpsc;

use crate::ipfixmsg::IpfixMsg;

pub fn exporte(receiver: mpsc::Receiver<IpfixMsg>){
    loop {
        info!("{}", receiver.recv().unwrap());
    }
}