# 部署自托管中继节点

## 前置要求

- Docker（或自行编译：`cargo build --release -p hypercast-rendezvous`）
- 一个域名 + TLS 证书（信令走 HTTPS/WSS，见环境变量说明）
- 可选：coturn（UDP-only TURN），TURN 的 TCP 端口必须保持关闭

## 快速开始

```bash
cd deploy
cp docker-compose.example.yaml docker-compose.yaml
# 编辑 docker-compose.yaml：改域名、TURN secret；按需打开遥测三行
docker compose up -d
curl http://127.0.0.1:8443/healthz   # 应答 {"status":"ok"}（按 BIND 端口调整）
```

## 环境变量

| 变量 | 必填 | 说明 |
|---|---|---|
| `HYPERCAST_RELAY_BIND` | 否 | 监听地址，默认 `127.0.0.1:5443` |
| `HYPERCAST_RELAY_ENABLED` | 否 | 开启 ws relay 转发（要求 ADMIN_TOKEN ≥32 字符与 HTTPS 公网地址） |
| `HYPERCAST_RELAY_PUBLIC_URL` | 否 | 对外公布的 relay ws 地址 |
| `HYPERCAST_RELAY_ADMIN_TOKEN` | 条件 | relay 启用时必填 |
| `HYPERCAST_STUN_URLS` | 否 | 下发给客户端的 STUN，默认 `stun:relay.example.com:3478`（必改成自建） |
| `HYPERCAST_TURN_URLS` / `HYPERCAST_TURN_SHARED_SECRET` | 否 | TURN 下发（REST 凭证派生） |
| `HYPERCAST_RELAY_STATE_FILE` | 否 | 状态持久化绝对路径 |
| `HYPERCAST_DIRECTORY_URL` | 否 | **opt-in** 遥测上报目录地址；不设=关闭 |
| `HYPERCAST_NODE_ID` | 否 | 遥测节点标识（上报目录时使用） |
| `HYPERCAST_NODE_PUBLIC_URL` | 否 | 节点对外信令地址（随遥测上报，供目录展示/探测） |

## 加入社区中继目录（可选）

设置 `HYPERCAST_DIRECTORY_URL` + `HYPERCAST_NODE_ID` + `HYPERCAST_NODE_PUBLIC_URL` 三个变量后，节点每 60 秒向目录上报一次**聚合计数**（uptime、注册数、请求数）——绝不含任何用户粒度数据。详见目录仓库 `schema/telemetry-report-v1.md`。

## 传输边界（强制）

- 信令（控制面）：HTTPS/WSS，允许 TCP —— 仅限 bootstrap/协商/配对。
- 实时负载（视频/音频/输入）：UDP，TURN 必须 UDP-only。**禁止**以 TURN/TCP、TURN/TLS 承载实时负载。
