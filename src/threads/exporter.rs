use log::{info};
use std::sync::mpsc;

use crate::ipfixmsg::IpfixMsg;

pub fn exporte(receiver: mpsc::Receiver<Box<dyn IpfixMsg>>){
    loop {
        let msg = receiver.recv().unwrap();
        info!("{}", msg.print());
    }
}