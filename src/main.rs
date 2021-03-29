use log::{info, warn};
use std::thread;
use std::collections::HashMap;
use std::sync::mpsc::channel;

mod utils;
mod ipfixmsg;
mod threads;

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum ThreadType {
    Listener,
    Exporter
}

fn main() {
    // read config from file
    let config = utils::Settings::init().unwrap();

    // init the env logger 
    utils::init_logger(&config.log.level);

    warn!{"Starting APP"}

    let mut thread_maps: HashMap<ThreadType,_> = HashMap::new();
    let (sender, receiver) = channel();

    thread_maps.insert(ThreadType::Listener, thread::Builder::new().name("UDP1".to_string()).spawn(move || {
        threads::listener::listen(&config.listener.host, sender);
    }));

    thread_maps.insert(ThreadType::Exporter, thread::Builder::new().name("UDP2".to_string()).spawn(move || {
        threads::exporter::exporte(receiver);
    }));

    for (_, v) in thread_maps {
        v.unwrap().join().unwrap();
    }

    info!{"Closing APP"}
}