use log::{error, info};
use std::io::prelude::*;
use std::net::{SocketAddr, TcpListener, TcpStream};

pub fn listen(addr: SocketAddr) {
    let listener = TcpListener::bind(&addr).unwrap();
    info!("Listening for TCP connection on {}", &addr);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => handle_connection(stream),
            Err(e) => error!("Connection failed : {}", e),
        }
    }
}

fn handle_connection(mut stream: TcpStream) {
    let contents = "
    <!DOCTYPE html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\">
    <title>Hello!</title>
  </head>
  <body>
    <h1>Hello!</h1>
    <p>Hi from Rust</p>
  </body>
</html>
    ";

    let response = format!("{}{}", "HTTP/1.1 200 OK\r\n\r\n", contents);

    stream.write(response.as_bytes()).unwrap();
    stream.flush().unwrap();
}
