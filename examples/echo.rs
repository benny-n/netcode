use std::{
    io::{self, BufRead},
    sync::mpsc::{self, RecvTimeoutError},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use env_logger::Builder;
use log::LevelFilter;

use netcode::{
    client::{Client, ClientState},
    server::{Server, ServerConfig},
};

fn time_now_secs_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}
fn main() {
    Builder::new().filter(None, LevelFilter::Info).init();

    let my_secret_private_key = [0u8; 32]; // TODO: generate a real private key
    let cfg = ServerConfig::with_context(42).on_connect(|client_idx, _| {
        log::info!("`on_connect` callback called for client {}", client_idx);
    });
    let mut server = Server::with_config(
        "127.0.0.1:12345".parse().unwrap(),
        0x11223344,
        Some(my_secret_private_key),
        cfg,
    )
    .unwrap();
    let client_id = 123u64;
    let token = server
        .token("127.0.0.1:12345", client_id)
        .expire_seconds(-1)
        .timeout_seconds(-1)
        .generate()
        .unwrap();

    let buf = token.try_into_bytes().unwrap();

    let server_thread = thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs_f64(1.0 / 60.0));
            let now = time_now_secs_f64();
            server.update(now).unwrap();

            let mut packet = [0; 1175];
            let received = server.recv(&mut packet).unwrap();
            if received > 0 {
                println!(
                    "server received: {}",
                    std::str::from_utf8(&packet[..received]).unwrap()
                );
                // echoing back
                server.send(&packet[..received], 0).unwrap();
            }
        }
    });

    let mut client = Client::new("127.0.0.1:12346")
        .unwrap()
        .connect(&buf)
        .unwrap();

    let (tx, rx) = mpsc::channel::<String>();
    let client_thread = thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs_f64(1.0 / 60.0));
            let now = time_now_secs_f64();
            client.update(now).unwrap();

            let mut packet = [0; 1175];
            let received = client.recv(&mut packet).unwrap();
            if received > 0 {
                println!(
                    "echoed back: {}",
                    std::str::from_utf8(&packet[..received]).unwrap()
                );
                // echoing back
            }
            if let ClientState::Connected = client.state() {
                match rx.recv_timeout(Duration::from_millis(16)) {
                    Ok(msg) => {
                        if !msg.is_empty() {
                            client.send(msg.as_bytes()).unwrap();
                        }
                    }
                    Err(RecvTimeoutError::Timeout) => continue,
                    Err(_) => break,
                }
            }
        }
    });

    for line in io::stdin().lock().lines() {
        let input = line.unwrap();
        tx.send(input.clone()).unwrap();
    }

    client_thread.join().unwrap();
    server_thread.join().unwrap();
}
