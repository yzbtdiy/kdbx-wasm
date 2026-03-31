use axum::{
    body::Body,
    http::{Request, Response},
    middleware::Next,
};
use tracing::{info, warn};

pub async fn request_logger(req: Request<Body>, next: Next) -> Response<Body> {
    let method = req.method().to_string();
    let uri = req.uri().to_string();

    // 过滤敏感路径（不记录密码等敏感数据）
    let is_sensitive = uri.contains("password") || uri.contains("master_key");

    if !is_sensitive {
        info!("Request: {} {}", method, uri);
    }

    let response = next.run(req).await;

    if !is_sensitive {
        let status = response.status();
        if status.is_success() {
            info!("Response: {} - {}", uri, status);
        } else {
            warn!("Response: {} - {}", uri, status);
        }
    }

    response
}
