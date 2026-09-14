//! 跨端版本与能力位常量 —— **唯一真源（Rust）**。
//!
//! Android / iOS / 未来 web 各持一份**字节一致**的镜像常量；镜像与本文件
//! 冲突时以本文件为准并立即修镜像。规范与升级策略见
//! `docs/design/2026-08-28-versioning-and-compat.md`。
//!
//! 硬约束（继承 crate 级）：纯常量、无 IO、无平台 API。

/// 线协议主版本。帧布局 / 信令语义发生**不兼容变更**时 +1。
/// 两端 major 不一致 = 拒绝建立会话（开发构建 fail-fast；正式构建给出
/// 可读的升级提示，不得静默错跑）。
pub const PROTOCOL_VERSION_MAJOR: u32 = 1;

/// 线协议次版本。**向后兼容**的新增（新消息类型 / 新可选字段）时 +1。
/// 仅用于诊断展示与日志，不做门禁。
/// 1.1（2026-09-09）：WindowControl 新增 `WindowCatalogRequest/Response` 与
/// `ActivateWindow/ActivateWindowResult`（P3 应用坞窗口目录与激活事务）。
pub const PROTOCOL_VERSION_MINOR: u32 = 1;

/// 线协议版本展示串（`"major.minor"`）。
pub const PROTOCOL_VERSION: &str = "1.1";

/// 端能力位。会话建立时交换；**缺位 = 对应功能优雅降级**（功能关闭），
/// 不得崩溃、不得错跑半支持的路径。
pub mod capability {
    /// 标准 RTP 视频轨（iOS / 浏览器消费的 H.265/H.264 track）。
    pub const RTP_VIDEO: u64 = 1 << 0;
    /// Android 0x01 DC 视频帧（hypercast-video 无序通道，HDP1 分片）。
    pub const DC_VIDEO_0x01: u64 = 1 << 1;
    /// offer/2 双 PC realtime input 通道（HostTCP 隧道形态）。
    pub const REALTIME_INPUT_PC: u64 = 1 << 2;
    /// 虚拟光标：host 采集隐藏真光标 + 端侧预测渲染。缺位 = host 必须保留
    /// 真光标采集，端侧不得本地预测（否则双光标/无光标）。
    pub const VIRTUAL_CURSOR: u64 = 1 << 3;
    /// 关键帧恢复协议（0x0F 请求 / 0x10 确认 / 0x11 已生产）。
    pub const VIDEO_RECOVERY: u64 = 1 << 4;
    /// 窗口目录与激活事务（0x03 WindowControl 的 WindowCatalog*/ActivateWindow*
    /// 消息族，P3 应用坞）。host 侧由常驻 helper 提供全显示器目录 + 精确窗口激活；
    /// 客户端 UI 接入应用坞时置位（Android P4 起；冻结版 iOS 不置位）。
    /// 缺位 = 端不展示应用坞入口（host 不主动推送目录）。
    pub const WINDOW_CATALOG: u64 = 1 << 5;
}

/// Host 端能力掩码（两个 host 二进制当前都支持全部六位）。
/// 端侧掩码：Android = DC_VIDEO_0x01 | REALTIME_INPUT_PC | VIRTUAL_CURSOR | VIDEO_RECOVERY
/// （WINDOW_CATALOG 待 P4 应用坞 UI 接入后置位）；
/// iOS = RTP_VIDEO | VIRTUAL_CURSOR | VIDEO_RECOVERY。镜像常量见各端。
pub const HOST_CAPABILITIES: u64 = capability::RTP_VIDEO
    | capability::DC_VIDEO_0x01
    | capability::REALTIME_INPUT_PC
    | capability::VIRTUAL_CURSOR
    | capability::VIDEO_RECOVERY
    | capability::WINDOW_CATALOG;

/// 解析 "major.minor" 的 major；解析失败返回 None（调用方按缺省兼容处理）。
pub fn version_major(version: &str) -> Option<u32> {
    version
        .split('.')
        .next()?
        .trim()
        .parse()
        .ok()
        .filter(|major| version.split('.').count() <= 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_major_parses_and_rejects_garbage() {
        assert_eq!(version_major("1.0"), Some(1));
        assert_eq!(version_major("2.3"), Some(2));
        assert_eq!(version_major("garbage"), None);
        assert_eq!(version_major(""), None);
    }

    use super::*;

    #[test]
    fn display_string_matches_components() {
        assert_eq!(
            PROTOCOL_VERSION,
            format!("{PROTOCOL_VERSION_MAJOR}.{PROTOCOL_VERSION_MINOR}")
        );
    }
}
