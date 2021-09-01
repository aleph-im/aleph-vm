# Tutorial: Creating a non-Python program on Aleph-VM

> This tutorial follows up the first tutorial [Creating and hosting a program on Aleph-VM](./README.md).

## 0. Welcome

In this second tutorial, we will guide you on how to run programs written in any programming language on Aleph Virtual Machines.

In addition to running Python programs using ASGI as covered in the first tutorial, 
Aleph VMs also support any program that listens for HTTP requests on port 8080.

This can be used to run existing programs on Aleph VMs, or to use other programming languages to write programs and run them on Aleph-VM.

### What we will cover

Since Python is the only language currently supported, this tutorial we will cover two other languages: [Rust](https://www.rust-lang.org/) and Javascript ([NodeJS](https://nodejs.org/)).

## 1. Rust

In this first section, you will run a program written in Rust on an Aleph VM.

### 1.a. Requirements

You need a Rust compiler. You can install one using the [official Install Rust guide](https://www.rust-lang.org/tools/install) 
or via your favourite package manager.

  $ sudo apt install rustc cargo

### 1.b. Writing a Rust program

Let's use a very simple HTTP server inspired by the [Building a Single-Threaded Web Server](https://doc.rust-lang.org/book/ch20-01-single-threaded.html)
section of The Rust Programming Language Book:

```shell
$ cargo new example_http_rust
     Created binary (application) `example_http_rust` project
$ cd example_http_rust
```

Filename: `src/main.rs`
```rust
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

    let response = format!("HTTP/1.1 200 OK\n\nOKIDOK\n{}", response);

    stream.write(response.as_bytes()).unwrap();
    stream.flush().unwrap();
}
```

```shell
cargo run
```

Open http://127.0.0.1:8080 in your browser to test your new server.

### 1.c. Publishing a Rust program

Compile your program:
```shell
cargo build --release
```

Publish it on Aleph using the same procedure as with the Python example, except the entrypoint refers to the name of the binary to execute. 

```shell
aleph program ./target/release/example_http_rust example_http_rust
```

If your program takes some arguments, pass them in the entrypoint by using quotes: `"example_http_rust --help`.

ℹ️ If you get the error `Invalid zip archive`, you are probably missing the Squashfs user tool `mksquashfs`. In that case, first create the squashfs archive and then upload it using `aleph program ./target/release/example_http_rust.squashfs example_http_rust`
