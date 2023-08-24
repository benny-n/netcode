use netcode::{client::Client, server::Server};

fn time_now_secs_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}
fn main() {
    // Start the server
    let mut server = Server::new(
        "127.0.0.1:12345",
        0x11223344,
        Some([0u8; 32]), // TODO: generate a real private key
    )
    .unwrap();

    // Generate a connection token for the client
    let token_bytes = server
        .token(123u64)
        .generate()
        .unwrap()
        .try_into_bytes()
        .unwrap();

    // Start the client
    let mut client = Client::new(&token_bytes).unwrap();
    client.connect().unwrap();

    // Run the server and client in parallel
    let server_thread = std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs_f64(1.0 / 60.0));
        let now = time_now_secs_f64();
        server.update(now).unwrap();
        let mut packet = [0; 1175];
        if let Ok(Some((received, _))) = server.recv(&mut packet) {
            println!("{}", std::str::from_utf8(&packet[..received]).unwrap());
            break;
        }
    });
    let client_thread = std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs_f64(1.0 / 60.0));
        let now = time_now_secs_f64();
        client.update(now).unwrap();
        let mut packet = [0; 1175];
        let _received = client.recv(&mut packet).unwrap();
        if client.is_connected() {
            client.send(b"Hello World!").unwrap();
            break;
        }
    });
    client_thread.join().unwrap();
    server_thread.join().unwrap();
}
