# hypercast-relay

Hypercast 自托管中继节点栈：rendezvous 服务端 + UDP-only TURN（coturn）部署 + 服务配置码生成 + 可选遥测上报。

**状态：奠基期（M0）** —— 仓库骨架与规划已就位，代码抽取进行中。部署可用性以 [M1](docs/2026-09-15-ecosystem-repo-plan.md#6-里程碑) 为准。

## 这个仓库是什么

- 你可以用它**自建中继**：`docker compose up` 跑起 rendezvous + TURN，服务自己的 Hypercast 客户端与被控端（零依赖官方节点）。
- 你也可以**分享节点**：选择加入社区中继目录，让其他人扫码使用你的节点（opt-in，默认关闭）。
- 所有实时负载走 **UDP**；TURN 为 UDP-only。内容端到端加密（DTLS-SRTP），**中继无法查看任何画面与操作**。

## 文档

- [生态仓库规划（奠基文档）](docs/2026-09-15-ecosystem-repo-plan.md) —— 仓库划分、协议真源、开源卫生、里程碑

## 结构（M1 起填充）

```
server/          rendezvous 服务端
protocol/        协议核心（服务端依赖子集）
deploy/          docker compose + coturn + nginx + 证书脚本
telemetry-agent/ 节点遥测上报（opt-in，仅聚合计数）
config-code/     服务配置码生成器
```

## 安全模型（一句话）

中继只搬运密文，密钥永不经过服务器；每个节点对使用者只是「门牌号」，信任建立在端到端加密之上，不建立在服务器运营者之上。
