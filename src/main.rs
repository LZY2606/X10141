use gsb_maskroom::engine::Engine;
use std::path::PathBuf;
use std::sync::Arc;

mod server;

fn print_help() {
    eprintln!(
        "用法：gsb-maskroom --addr 127.0.0.1:5223 [--data-dir ./maskroom-data]\n\
         首次启动会在数据目录本地生成主密钥（0600），不调用任何外部密钥服务。"
    );
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut addr: Option<String> = None;
    let mut data_dir = PathBuf::from("maskroom-data");
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--addr" => addr = args.next(),
            "--data-dir" => {
                if let Some(d) = args.next() {
                    data_dir = PathBuf::from(d);
                }
            }
            "-h" | "--help" => {
                print_help();
                return;
            }
            other => {
                eprintln!("未知参数：{other}");
                print_help();
                std::process::exit(2);
            }
        }
    }
    let addr = addr.unwrap_or_else(|| {
        print_help();
        std::process::exit(2);
    });

    match Engine::open(&data_dir) {
        Ok(engine) => {
            println!("脱敏映射室已启动");
            println!("  监听地址 : http://{addr}");
            println!("  数据目录 : {}", data_dir.display());
            println!("  当前密钥代次 : G{}", engine.key_info()["current_generation"]);
            if let Err(e) = server::serve(addr, Arc::new(engine)) {
                eprintln!("服务器错误：{e}");
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("初始化失败：{e}");
            std::process::exit(1);
        }
    }
}
