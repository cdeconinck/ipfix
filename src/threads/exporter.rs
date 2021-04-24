use log::info;
use std::sync::mpsc;

use crate::flow::Flow;

pub fn exporte(receiver: mpsc::Receiver<Vec<Box<dyn Flow>>>) {
    loop {
        // TODO implémenter les différents exporters (json / stdout / ??)
        let msg_list = receiver.recv().unwrap();
    }
}
