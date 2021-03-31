use log::{info};
use std::thread;
use std::collections::HashMap;
use std::sync::mpsc::channel;
use std::process;

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

#[macro_use]
extern crate serde_derive;

mod utils;
mod netflow;
mod threads;

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum ThreadType {
    Listener,
    Exporter
}

fn main() {
    // read config from file
    let config = match utils::Settings::init() {
        Ok(config) => config,
        Err(e) => {
            println!("Failed to init the programm config : {}", e);
            process::exit(0);
        }
    };

    // init the env logger 
    utils::init_logger(&config.log.level);

    info!("Starting APP");

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

    info!("Closing APP");
}