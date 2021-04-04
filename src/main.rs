use log::{info};
use std::thread;
use std::sync::mpsc::channel;
use structopt::StructOpt;
use log::{LevelFilter};
use std::net::{SocketAddr};

#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;

#[macro_use]
extern crate serde_derive;

mod utils;
mod netflow;
mod threads;

#[derive(Debug, StructOpt)]
struct Opts {
    /// Log level to use
    #[structopt(long= "-log", default_value = "Info")]
    log_level: LevelFilter,

    /// IP:port for the UDP listener
    #[structopt(short= "-l", long = "--listener", default_value= "0.0.0.0:9999")]
    listener: SocketAddr,

    /// IP:port for the prometheus exporter
    #[structopt(short= "-e", long = "--exporter")]
    exporter: Option<SocketAddr>,
}

fn main() {
    let opts = Opts::from_args();

    // init the app logger 
    utils::init_logger(&opts.log_level);

    info!("Starting APP");

    let mut thread_list = vec!();
    let (sender, receiver) = channel();

    let listener_url = opts.listener.clone();
    thread_list.push(thread::Builder::new().name("Listener".to_string()).spawn(move || {
        threads::listener::listen(listener_url, sender);
    }));

    thread_list.push(thread::Builder::new().name("Exporter".to_string()).spawn(move || {
        threads::exporter::exporte(receiver);
    }));

    if opts.exporter != None {
        let prometheus_listener = opts.exporter.unwrap().clone();
        thread_list.push(thread::Builder::new().name("Prometheus".to_string()).spawn(move || {
            threads::prometheus::listen(prometheus_listener);
        }));
    }

    for t in thread_list {
        t.unwrap().join().unwrap();
    }

    info!("Closing APP");
}