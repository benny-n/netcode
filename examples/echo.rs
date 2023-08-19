use std::time::{SystemTime, UNIX_EPOCH};

use netcode::server::{Server, ServerConfig};

fn time_now_secs_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}
fn main() {
    use env_logger::Builder;
    use log::LevelFilter;

    Builder::new().filter(None, LevelFilter::Debug).init();

    let my_secret_private_key = [0u8; 32]; // TODO: generate a real private key
    let cfg = ServerConfig::with_state(42)
        .on_connect(|_, _| {
            log::info!("on_connect");
        })
        .on_disconnect(|_, _| {
            log::info!("on_disconnect");
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
        // .internal_address_list(AddressList::new("127.0.0.1:9001").unwrap()) // default is equal to the addresses provided to `token` method
        // .token_expire_secs(30) // default is -1, which means the token never expires
        .timeout_seconds(15) // default is -1 which means the connection never times out
        .generate()
        .unwrap();

    let buf = token.try_into_bytes().unwrap();
    // write bytes to file
    std::fs::write("../netcode-rs/token.bin", buf).unwrap();

    let server_thread = std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs_f64(1.0 / 60.0));
            let now = time_now_secs_f64();
            server.update(now).unwrap();

            let mut packet = [0; 1175];
            let received = server.recv(&mut packet).unwrap();
            if received > 0 {
                println!(
                    "received: {}",
                    std::str::from_utf8(&packet[..received]).unwrap()
                );
                // echoing back
                server.send(&packet[..received], 0).unwrap();
            }
        }
    });

    server_thread.join().unwrap();
    // loop {
    //     std::thread::sleep(std::time::Duration::from_secs_f64(1.0 / 60.0));
    //     let now = time_now_secs_f64();
    //     server.update(now).unwrap();

    //     let mut packet = [0; 1175];
    //     let received = server.recv(&mut packet).unwrap();
    //     if received > 0 {
    //         println!(
    //             "received: {}",
    //             std::str::from_utf8(&packet[..received]).unwrap()
    //         );
    //         // echoing back
    //         server.send(&packet[..received], 0).unwrap();
    //     }
    // }
}
