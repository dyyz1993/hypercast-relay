//! 遥测上报 E2E：真实 telemetry 线程 → mock 目录 HTTP 服务。
//!
//! 回归背景：曾因缺 `Content-Type: application/json` 被 axum Json 提取器拒收
//! （415），且本地 curl 冒烟带头测不出——此测试用与生产完全相同的 ureq
//! 调用路径锁定该契约。

use std::io::{Read, Write};
use std::sync::mpsc;

use hypercast_rendezvous::telemetry;

/// 极简单请求 mock HTTP 服务：返回捕获到的 (path, content_type, body)。
fn spawn_mock_directory() -> (String, mpsc::Receiver<(String, String, String)>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 8192];
            let n = sock.read(&mut buf).unwrap_or(0);
            let raw = String::from_utf8_lossy(&buf[..n]).to_string();
            let header_end = raw.find("\r\n\r\n").unwrap_or(raw.len());
            let head = &raw[..header_end];
            let path = head
                .lines()
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .nth(1)
                .unwrap_or_default()
                .to_owned();
            let content_type = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-type: ")
                        .map(str::to_owned)
                })
                .unwrap_or_default();
            let body = raw[header_end + 4..].to_owned();
            let _ = tx.send((path, content_type, body));
            let _ = sock.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
        }
    });
    (format!("http://127.0.0.1:{port}"), rx)
}

#[test]
fn telemetry_report_carries_json_content_type_and_payload() {
    let (base, rx) = spawn_mock_directory();
    telemetry::spawn_with_interval(
        base.clone(),
        "e2e-node".into(),
        std::time::Duration::from_millis(50),
    );

    let (path, content_type, body) = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("telemetry report arrived within 5s");

    assert_eq!(path, "/api/v1/report");
    assert!(
        content_type.starts_with("application/json"),
        "Content-Type must be application/json (415 regression), got: {content_type}"
    );

    let v: serde_json::Value = serde_json::from_str(&body).expect("body is valid JSON");
    assert_eq!(v["node_id"], "e2e-node");
    assert_eq!(v["protocol_version"], "1.1");
    assert!(v["uptime_s"].is_u64(), "uptime_s present");
    assert!(v["metrics"]["mailbox_registrations_total"].is_u64());
    // 铁律：metrics 只能是聚合计数（schema v1 锁定）
    let metrics = v["metrics"].as_object().expect("metrics object");
    for (k, val) in metrics {
        assert!(
            val.is_u64(),
            "metric {k} must be aggregate u64 counter, got {val}"
        );
    }
}
