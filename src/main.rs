use std::net::UdpSocket;
use log::{info, warn};

mod settings;
mod logger;

fn wait(url: &String) {
    let socket = UdpSocket::bind(url).expect(&format!("Failed to bind udp socket to {}", url));
    info!{"Listening on {}", url}

    let mut buf = [0; 10];

    loop {
        info!{"Waiting for data..."}

        let (nb, from) = socket.recv_from(&mut buf).unwrap();
        info!{"Received {} from {}", nb, from}
    }

    info!{"Closing UDP socket on {}", url}
    drop(socket)
}

fn main() {
    // read config from file
    let config = settings::load_config();

    // init the env logger 
    logger::init(&config.get_str("log_level").unwrap());
    
    warn!{"Starting APP"}
    
    wait(&config.get_str("listener_host").unwrap());

    info!{"Closing APP"}
}