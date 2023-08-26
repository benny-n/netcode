use std::{
    io::{self, BufRead},
    sync::mpsc::{self, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use netcode::{Client, ClientState, Server, ServerConfig};

fn main() {
    env_logger::Builder::new()
        .filter(None, log::LevelFilter::Info)
        .init();

    let my_secret_private_key = netcode::generate_key();
    let cfg = ServerConfig::with_context(42).on_connect(|client_idx, _| {
        log::info!("`on_connect` callback called for client {}", client_idx);
    });
    let mut server = Server::with_config(
        "127.0.0.1:12345".parse().unwrap(),
        0x11223344,
        my_secret_private_key,
        cfg,
    )
    .unwrap();
    let client_id = 123u64;
    let token = server
        .token(client_id)
        .expire_seconds(-1)
        .timeout_seconds(-1)
        .generate()
        .unwrap();

    let buf = token.try_into_bytes().unwrap();

    let start = Instant::now();
    let tick_rate = 1.0 / 60.0;

    let server_thread = thread::spawn(move || loop {
        let now = start.elapsed().as_secs_f64();
        server.update(now).unwrap();

        let mut packet = [0; 1175];
        if let Ok(Some((received, client_idx))) = server.recv(&mut packet) {
            println!(
                "server received: {}",
                std::str::from_utf8(&packet[..received]).unwrap()
            );
            server.send(&packet[..received], client_idx).unwrap();
        }
        thread::sleep(Duration::from_secs_f64(tick_rate));
    });

    let mut client = Client::new(&buf).unwrap();
    client.connect();

    let (tx, rx) = mpsc::channel::<String>();
    let client_thread = thread::spawn(move || loop {
        let now = start.elapsed().as_secs_f64();
        client.update(now).unwrap();

        let mut packet = [0; 1175];
        let received = client.recv(&mut packet).unwrap();
        if received > 0 {
            println!(
                "echoed back: {}",
                std::str::from_utf8(&packet[..received]).unwrap()
            );
        }
        if let ClientState::Connected = client.state() {
            match rx.recv_timeout(Duration::from_secs_f64(tick_rate)) {
                Ok(msg) => {
                    if !msg.is_empty() {
                        client.send(msg.as_bytes()).unwrap();
                    }
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(_) => break,
            }
        }
        thread::sleep(Duration::from_secs_f64(tick_rate));
    });

    for line in io::stdin().lock().lines() {
        let input = line.unwrap();
        tx.send(input.clone()).unwrap();
    }

    client_thread.join().unwrap();
    server_thread.join().unwrap();
}
