use std::{
    io::{self, BufRead},
    sync::mpsc::{self, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use netcode::{Client, ClientIndex, ClientState, Server, ServerConfig};

enum Event {
    Connected(ClientIndex),
    Disconnected(ClientIndex),
}

fn main() {
    env_logger::Builder::new()
        .filter(None, log::LevelFilter::Info)
        .init();

    let my_secret_private_key = netcode::generate_key();
    let (tx, rx) = mpsc::channel::<Event>();
    let cfg = ServerConfig::with_context(tx.clone())
        .on_connect(move |client_idx, tx| {
            tx.send(Event::Connected(client_idx)).unwrap();
        })
        .on_disconnect(move |client_idx, tx| {
            tx.send(Event::Disconnected(client_idx)).unwrap();
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
    let tick_rate = Duration::from_secs_f64(1.0 / 60.0);

    let server_thread = thread::spawn(move || loop {
        let now = start.elapsed().as_secs_f64();
        server.update(now);

        while let Some((packet, client_idx)) = server.recv() {
            let s = std::str::from_utf8(&packet).unwrap();
            println!("server received: {s}",);
            server.send(&packet, client_idx).unwrap();
        }
        match rx.try_recv() {
            Ok(Event::Connected(idx)) => {
                log::info!("client {idx} connected");
            }
            Ok(Event::Disconnected(idx)) => {
                log::info!("client {idx} disconnected");
                break;
            }
            Err(_) => continue,
        }
        thread::sleep(tick_rate);
    });

    let mut client = Client::new(&buf).unwrap();
    client.connect();

    let (tx, rx) = mpsc::channel::<String>();
    let client_thread = thread::spawn(move || loop {
        let now = start.elapsed().as_secs_f64();
        client.update(now);

        if let Some(packet) = client.recv() {
            println!("echoed back: {}", std::str::from_utf8(&packet).unwrap());
        }
        if let ClientState::Connected = client.state() {
            match rx.recv_timeout(tick_rate) {
                Ok(msg) if msg == "q" => {
                    client.disconnect().unwrap();
                    break;
                }
                Ok(msg) => {
                    if !msg.is_empty() {
                        client.send(msg.as_bytes()).unwrap();
                    }
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(_) => break,
            }
        }
        thread::sleep(tick_rate);
    });

    for line in io::stdin().lock().lines() {
        let input = line.unwrap();
        tx.send(input.clone()).unwrap();
        if input == "q" {
            break;
        }
    }

    client_thread.join().unwrap();
    server_thread.join().unwrap();
}
