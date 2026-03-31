pub mod core;
pub mod error;

// 只在非 WASM 目标时编译这些模块
#[cfg(not(target_arch = "wasm32"))]
pub mod api;
#[cfg(not(target_arch = "wasm32"))]
pub mod infrastructure;
#[cfg(not(target_arch = "wasm32"))]
pub mod service;

// WASM 模块
#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use error::KdbxError;

// 非 WASM 目标导出
#[cfg(not(target_arch = "wasm32"))]
pub use infrastructure::Config;

// WASM 目标导出
#[cfg(target_arch = "wasm32")]
pub use wasm::*;
