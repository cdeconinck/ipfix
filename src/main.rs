use std::net::UdpSocket;
use log::{info, warn};
use std::fmt;

mod settings;
mod logger;

struct Message {
    src_addr: String,
    size: usize,
    buf : Vec<u8>
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} - {} - {:02X?} - {}", &self.src_addr, self.size, &self.buf, String::from_utf8_lossy(&self.buf))
    }
}


fn wait(url: &String) {
    let socket = UdpSocket::bind(url).expect(&format!("Failed to bind udp socket to {}", url));
    info!{"Listening on {}", url}

    let mut buf = [0; 1500];

    loop {
        info!{"Waiting for data..."}
        let (nb_bytes, from) = socket.recv_from(&mut buf).unwrap();

        // extract the data into a another array
        let mut data = vec![0; nb_bytes];
        &data[..nb_bytes].copy_from_slice(&buf[..nb_bytes]);

        let m = Message { src_addr : from.to_string(), size: nb_bytes,  buf : data};
        info!{"{}", m};
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