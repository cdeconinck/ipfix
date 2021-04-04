use std::net::{TcpListener, TcpStream, SocketAddr};
use std::io::prelude::*;
use log::{info};

pub fn listen(url: SocketAddr) {
    let listener = TcpListener::bind(&url).unwrap();
    info!("Listening for TCP packet on {}", &url);

    for stream in listener.incoming() {
        let stream = stream.unwrap();

        handle_connection(stream);
    }
}

fn handle_connection(mut stream: TcpStream) {
    let mut buffer = [0; 1024];
    stream.read(&mut buffer).unwrap();

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
