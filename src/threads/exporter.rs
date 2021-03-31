use log::{info};
use std::sync::mpsc;

use crate::ipfixmsg::NetflowMsg;

pub fn exporte(receiver: mpsc::Receiver<Box<dyn NetflowMsg>>){
    loop {
        let msg = receiver.recv().unwrap();
        info!("{}", msg.print());
    }
}