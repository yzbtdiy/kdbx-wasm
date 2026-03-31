use axum::serve;
use kdbx_wasm::{api::create_router, api::state::AppState, Config};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 加载配置
    let config = Config::load().unwrap_or_default();

    // 初始化日志
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&config.log.level))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // 创建应用状态
    let state = AppState::new(config.session_timeout());

    // 启动会话清理任务
    let cleanup_store = Arc::new(kdbx_wasm::service::SessionStore::new(config.session_timeout()));
    kdbx_wasm::service::session::start_cleanup_task(cleanup_store, config.cleanup_interval());

    // 创建路由
    let app = create_router(state);

    // 绑定地址
    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .expect("Invalid address");

    tracing::info!("Starting KDBX Server on {}", addr);

    // 启动服务器
    let listener = TcpListener::bind(addr).await?;
    serve(listener, app).await?;

    Ok(())
}
