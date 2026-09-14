# hypercast-relay

Hypercast 自托管中继节点栈：rendezvous 服务端 + UDP-only TURN（coturn）部署 + 可选遥测上报。

**状态：M1（节点栈可部署）** —— rendezvous 服务端 + 协议核心 + Docker 部署就绪；coturn 配套与配置码生成器在后续里程碑。

## 这个仓库是什么

- 你可以用它**自建中继**：`docker compose up` 跑起 rendezvous（+ 你自己的 coturn），服务自己的 Hypercast 客户端与被控端（零依赖官方节点）。
- 你也可以**分享节点**：设置三个环境变量即加入社区中继目录，让其他人扫码使用你的节点（opt-in，默认关闭）。
- 所有实时负载走 **UDP**；TURN 为 UDP-only。内容端到端加密（DTLS-SRTP），**中继无法查看任何画面与操作**。

## 快速开始

```bash
cargo build --release -p hypercast-rendezvous
HYPERCAST_RELAY_BIND=0.0.0.0:8443 ./target/release/hypercast-rendezvous
curl http://127.0.0.1:8443/healthz
```

Docker 部署、环境变量全表与 TURN 配套见 [deploy/README.md](deploy/README.md)。

## 文档

- [生态仓库规划（奠基文档）](docs/2026-09-15-ecosystem-repo-plan.md) —— 仓库划分、协议真源、开源卫生、里程碑
- [部署指南](deploy/README.md) —— compose / 环境变量 / 加入社区目录

## 结构

```
server/          rendezvous 服务端（axum；含 opt-in 遥测上报 telemetry.rs）
protocol/        协议核心 hypercast-protocol-kit（纯函数：签名 transcript / 邮箱派生 / 版本能力位）
deploy/          Dockerfile + docker-compose 示例 + 部署文档
```

## 安全模型（一句话）

中继只搬运密文，密钥永不经过服务器；每个节点对使用者只是「门牌号」，信任建立在端到端加密之上，不建立在服务器运营者之上。
