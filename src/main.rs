use std::net::UdpSocket;
use log::{info, warn};

mod settings;
mod logger;

fn wait(url: &String) {
    let socket = UdpSocket::bind(url).expect(&format!("Failed to bind udp socket to {}", url));
    info!{"Listening on {}", url}

    let mut buf = [0; 1500];

    loop {
        info!{"Waiting for data..."}

        let (nb_bytes, from) = socket.recv_from(&mut buf).unwrap();
        let data = &buf[..nb_bytes];
        info!{"Received {} from {} : {} - ({:02X?})", nb_bytes, from, String::from_utf8_lossy(data), &data}
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