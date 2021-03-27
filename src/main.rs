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
    let config = settings::Settings::init().unwrap();

    // init the env logger 
    logger::init(&config.log.level);
    
    warn!{"Starting APP"}
    
    wait(&config.listener.host);

    info!{"Closing APP"}
}