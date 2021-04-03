use log::{info};
use std::thread;
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

    let mut thread_list = vec!();
    let (sender, receiver) = channel();

    let listener_url = config.listener.host.clone();
    thread_list.push(thread::Builder::new().name("Listener".to_string()).spawn(move || {
        threads::listener::listen(listener_url, sender);
    }));

    thread_list.push(thread::Builder::new().name("Exporter".to_string()).spawn(move || {
        threads::exporter::exporte(receiver);
    }));

    if config.prometheus.enable {
        let prometheus_listener = config.prometheus.host.clone();
        thread_list.push(thread::Builder::new().name("Prometheus".to_string()).spawn(move || {
            threads::prometheus::listen(prometheus_listener);
        }));
    }

    for t in thread_list {
        t.unwrap().join().unwrap();
    }

    info!("Closing APP");
}