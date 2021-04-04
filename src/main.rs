use log::{info};
use std::thread;
use std::sync::mpsc::channel;
use std::process;
use structopt::StructOpt;
use std::path::PathBuf;

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
    #[structopt(long = "--cfg")]
    #[structopt(parse(from_os_str))]
    cfg: Option<PathBuf>,
}

fn main() {
    let opts = Opts::from_args();
    println!("{:?}", opts);

    // init the app config
    let config = match utils::Settings::init(opts.cfg) {
        Ok(config) => config,
        Err(e) => {
            println!("Failed to init the programm config : {}", e);
            process::exit(0);
        }
    };

    // init the app logger 
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