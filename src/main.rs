use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use masking_room::server;
use masking_room::service::Vault;

#[tokio::main]
async fn main() {
    let mut addr = "127.0.0.1:5223".to_string();
    let mut data_dir = PathBuf::from("masking-room-data");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" if i + 1 < args.len() => {
                addr = args[i + 1].clone();
                i += 2;
            }
            "--data-dir" if i + 1 < args.len() => {
                data_dir = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            other => {
                eprintln!("未知参数: {other} (支持 --addr, --data-dir)");
                std::process::exit(2);
            }
        }
    }

    let vault = Vault::open_or_init(&data_dir).unwrap_or_else(|e| {
        eprintln!("无法初始化数据目录 {}: {e}", data_dir.display());
        std::process::exit(1);
    });
    let app = server::router(Arc::new(Mutex::new(vault)));
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap_or_else(|e| {
        eprintln!("无法绑定 {addr}: {e}");
        std::process::exit(1);
    });
    println!("脱敏映射室已启动: http://{addr}  (数据目录: {})", data_dir.display());
    axum::serve(listener, app).await.expect("server error");
}
