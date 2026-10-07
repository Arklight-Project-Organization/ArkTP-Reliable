//! Loopback high-BDP throughput benchmark.
//!
//! Usage:
//!   cargo bench --bench high_bdp
//!
//! The benchmark deliberately uses a long transfer and measures application
//! goodput rather than UDP syscall throughput.

use arktp_reliable::{ArkTPConfig, ArkTPReliableClient, ArkTPReliableServer, EncryptionKey, KeyExchangeMethod, AuthenticationConfig};
use std::time::Instant;
use tokio::runtime::Runtime;

fn main() {
    let runtime = Runtime::new().expect("tokio runtime");
    runtime.block_on(async {
        let mut cfg = ArkTPConfig::default();
        cfg.encryption_key = Some(EncryptionKey::from_bytes(&[0x42; 32]).unwrap());
        cfg.key_exchange_method = KeyExchangeMethod::PreSharedKey;
        cfg.authentication = AuthenticationConfig::PreSharedKey;
        cfg.enable_nat_traversal = false;
        cfg.enable_multipath = false;
        cfg.enable_pmtud = false;
        cfg.fec_enabled = false;
        cfg.enable_smart_fec = false;
        cfg.send_buffer_size = 32 * 1024;
        cfg.receive_buffer_size = 32 * 1024;
        cfg.initial_max_data = 256 * 1024 * 1024;
        cfg.initial_max_stream_data = 64 * 1024 * 1024;
        cfg.recv_timeout = Some(std::time::Duration::from_secs(30));

        let server = ArkTPReliableServer::bind("127.0.0.1:0", cfg.clone()).await.unwrap();
        let client_factory = ArkTPReliableClient::new(cfg).unwrap();
        let client = client_factory.connect(&server.local_addr().unwrap().to_string()).await.unwrap();
        let server_conn = server.accept().await.unwrap();

        let total = std::env::var("ARKTP_BENCH_BYTES")
            .ok().and_then(|v| v.parse().ok()).unwrap_or(256usize * 1024 * 1024);
        let chunk = vec![0x5au8; 1200];
        let start = Instant::now();
        let receiver = tokio::spawn(async move {
            let mut received = 0usize;
            while received < total {
                received += server_conn.recv().await.unwrap().len();
            }
            received
        });
        let mut sent = 0usize;
        while sent < total {
            let n = (total - sent).min(chunk.len());
            client.send(&chunk[..n]).await.unwrap();
            sent += n;
        }
        let received = receiver.await.unwrap();
        let elapsed = start.elapsed();
        let mib = received as f64 / (1024.0 * 1024.0);
        let mbps = mib / elapsed.as_secs_f64();
        println!("ArkTP Reliable high-BDP loopback: {mib:.2} MiB in {:.3}s = {mbps:.2} MiB/s", elapsed.as_secs_f64());
    });
}
