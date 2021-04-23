use log::info;
use std::sync::mpsc;

use crate::netflow::NetflowMsg;

pub fn exporte(receiver: mpsc::Receiver<Vec<Box<dyn NetflowMsg>>>) {
    loop {
        // TODO implémenter les différents exporters (json / stdout / ??)
        let msg_list = receiver.recv().unwrap();
    }
}
