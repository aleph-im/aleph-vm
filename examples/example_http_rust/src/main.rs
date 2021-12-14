use std::io::prelude::*;
use std::net::TcpListener;
use std::net::TcpStream;

fn main() {

    let listener = TcpListener::bind("0.0.0.0:8080").unwrap();
    println!("Running on 0.0.0.0:8080");
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        handle_connection(stream);
    }
}


fn handle_connection(mut stream: TcpStream) {
    println!("handling connection");

    const MSG: &str = "helloworld";
    let msg = MSG.as_bytes();

    let response = format!("{:x?}", msg);

    let mut buffer = [0; 1024];

    stream.read(&mut buffer).unwrap();

    let response = format!("HTTP/1.1 200 OK\nContent-Type: text/plain\n\nOKIDOK\n{}", response);

    stream.write(response.as_bytes()).unwrap();
    stream.flush().unwrap();
}
