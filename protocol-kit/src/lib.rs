//! hypercast-protocol-kit —— 跨端纯函数协议工具包。
//!
//! ## 定位
//!
//! 同一套协议逻辑的四份实现(Rust / TS / Kotlin / Swift)中, 纯函数部分
//! (签名 transcript、邮箱派生、hex 工具)在此收敛为 **Rust 唯一实现**,
//! 由 `fixtures/` conformance 套件字节级锁定(Rust/Swift/TS/Kotlin 四端
//! 测试已绿)。各端经 platform-* crate 绑定输出。
//!
//! ## 已收拢(自 crates/rendezvous 移动, 2026-08-18)
//!
//! - `transcripts`: HCT1 / HHR1 / HCO1 / HCK1 / HPO1 / HPA1
//!   + `mailbox_id_for_token` + hex 工具
//!
//! ## 待收拢(见 README.md 迁移顺序)
//!
//! - HPC1 claim proof(demo/pairing.rs —— 待其编译恢复)
//! - HKDF 72B 会话密钥派生(同上)
//! - 输入帧编解码 / 配对 URI 解析 / 质量常量 / 设备目录合并
//!
//! ## 硬约束
//!
//! - `#![forbid(unsafe_code)]`, 纯函数, 不引入 tokio/IO/平台 API
//! - 改动任何字节布局: 先改协议文档 → 四端同步 → 重新生成 fixtures
#![forbid(unsafe_code)]

pub mod transcripts;
pub mod version;

pub use transcripts::*;
pub use version::*;
