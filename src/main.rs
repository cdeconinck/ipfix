use log::{info, warn};
use std::thread;
use std::collections::HashMap;
use std::sync::mpsc::channel;

mod settings;
mod logger;
mod entity;
mod threads;

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum ThreadType {
    UdpListener,
    IpfixParser
}

fn main() {
    // read config from file
    let config = settings::Settings::init().unwrap();

    // init the env logger 
    logger::init(&config.log.level);

    warn!{"Starting APP"}

    let mut thread_maps: HashMap<ThreadType,_> = HashMap::new();
    let (sender, receiver) = channel();

    thread_maps.insert(ThreadType::UdpListener, thread::Builder::new().name("UdpListener".to_string()).spawn(move || {
        threads::listener::init(&config.listener.host, sender);
    }));

    thread_maps.insert(ThreadType::IpfixParser,  thread::Builder::new().name("IpfixParser".to_string()).spawn(move || {
        threads::ipfix_parser::parse(receiver);
    }));

    for (_, v) in thread_maps {
        v.unwrap().join().unwrap();
    }

    info!{"Closing APP"}
}