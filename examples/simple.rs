use netcode::{Client, Server, MAX_PAYLOAD_SIZE};

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
    client.connect();

    let start = std::time::Instant::now();
    let tick_rate_secs = 1.0 / 60.0;

    // Run the server and client in parallel
    let server_thread = std::thread::spawn(move || loop {
        server.update(start.elapsed().as_secs_f64()).unwrap();
        let mut packet = [0; MAX_PAYLOAD_SIZE];
        if let Ok(Some((received, _))) = server.recv(&mut packet) {
            println!("{}", std::str::from_utf8(&packet[..received]).unwrap());
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs_f64(tick_rate_secs));
    });
    let client_thread = std::thread::spawn(move || loop {
        client.update(start.elapsed().as_secs_f64()).unwrap();
        let mut packet = [0; MAX_PAYLOAD_SIZE];
        let _received = client.recv(&mut packet).unwrap();
        if client.is_connected() {
            client.send(b"Hello World!").unwrap();
            break;
        }
        std::thread::sleep(std::time::Duration::from_secs_f64(tick_rate_secs));
    });
    client_thread.join().unwrap();
    server_thread.join().unwrap();
}
