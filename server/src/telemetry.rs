//! 可选遥测上报（opt-in）：设置 `HYPERCAST_DIRECTORY_URL` 时，每 60 秒向
//! 社区中继目录上报一次聚合计数；未设置则完全关闭。
//!
//! 铁律（见 hypercast-relay-directory/schema/telemetry-report-v1.md）：
//! 只上报聚合计数，绝不上报任何用户粒度数据（IP、会话、身份、时间线）。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hypercast_protocol_kit::PROTOCOL_VERSION;

/// 邮箱注册累计次数（host 侧 register 调用）。
pub static MAILBOX_REGISTRATIONS: AtomicU64 = AtomicU64::new(0);
/// 会话请求累计次数（客户端 submit_session_request 调用）。
pub static SESSION_REQUESTS: AtomicU64 = AtomicU64::new(0);

/// 启动后台上报线程（生产入口，60 秒周期）。上报失败只记 warning，绝不影响服务本身。
pub fn spawn(directory_url: String, node_id: String) {
    spawn_with_interval(directory_url, node_id, Duration::from_secs(60))
}

/// 测试入口：可注入上报周期。
pub fn spawn_with_interval(directory_url: String, node_id: String, interval: Duration) {
    std::thread::spawn(move || {
        let started = SystemTime::now();
        loop {
            std::thread::sleep(interval);
            let uptime_s = started
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|_| started.elapsed().ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let signal_url = std::env::var("HYPERCAST_NODE_PUBLIC_URL").ok();
            // 已配置的 TURN 地址（目录据此做中继能力分级探测）
            let turn_urls: Vec<String> = std::env::var("HYPERCAST_TURN_URLS")
                .map(|v| {
                    v.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let body = serde_json::json!({
                "schema": "hc-telemetry/1",
                "node_id": node_id,
                "signal_url": signal_url,
                "turn_urls": turn_urls,
                "protocol_version": PROTOCOL_VERSION,
                "uptime_s": uptime_s,
                "metrics": {
                    "mailbox_registrations_total": MAILBOX_REGISTRATIONS.load(Ordering::Relaxed),
                    "session_requests_total": SESSION_REQUESTS.load(Ordering::Relaxed),
                },
            });
            match ureq::post(&format!("{directory_url}/api/v1/report"))
                .timeout(Duration::from_secs(10))
                .set("Content-Type", "application/json")
                .send_string(&body.to_string())
            {
                Ok(_) => {}
                Err(e) => tracing::warn!("telemetry report failed (non-fatal): {e}"),
            }
        }
    });
}
