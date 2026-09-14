# Hypercast 开源中继生态 · 仓库规划（奠基文档）

日期：2026-09-15 · 状态：骨架已立，代码待抽取 · 上位规划：主仓库 `docs/design/2026-09-12-pairing-credential-provisioning-plan.html` V3 扩展

## 0. 目标

让任何人可以：

1. **自建中继**：克隆 `hypercast-relay`，`docker compose up` 一键跑起 rendezvous + TURN（UDP-only），扫码导入即可用。
2. **分享节点**：部署者可选择把自己的节点"踪迹"提交到目录，定时上报遥测（稳定性、带宽、连接数、用户数等聚合计数）。
3. **发现节点**：其他用户在目录网页上看到各社区中继的状态/带宽/负载，选择性扫码使用。

**安全模型不变**：端到端加密（DTLS-SRTP）使任何中继——官方、自建、社区——只见密文。目录改变的是"发现"，不是"信任"。

## 1. 仓库划分（2 个仓库）

| 仓库 | 角色 | 受众 | 内容 |
|---|---|---|---|
| **hypercast-relay** | 中继节点栈 | 想自建/分享中继的部署者 | rendezvous 服务端 + 协议核心子集 + coturn/nginx/compose/证书部署 + 服务配置码生成器 + 遥测上报器 |
| **hypercast-relay-directory** | 社区中继目录 | 官方（运营）与社区（可自托管目录） | 收录 registry API + 探测器 prober + 目录网页 + 遥测接收端 + **跨仓库协议 schema 真源** |

**为什么两个仓库而不是 monorepo**：

- 贡献者群体不同：节点栈的贡献者是运维向（部署脚本、coturn 调优），目录的贡献者是服务/网页向。
- 发布节奏不同：节点栈跟随线协议版本（§18 纪律），目录网页可以独立迭代。
- 目录是"专门给用户托管/发布第三方中继服务的地方"（产品定位上就是独立服务），独立仓库与独立运营对齐。

**为什么不现在拆第三个**：官网激活页（Device Flow，V2 范畴）含品牌资产暂不开源，需要时再立 `hypercast-website`。

## 2. 目录结构（目标态，M1 起填充）

```
hypercast-relay/
  README.md            部署者第一入口：一键部署 + 分享流程
  LICENSE              待拍板（见 §8）
  docs/                本规划 + 部署文档 + 收录协议说明
  server/              hypercast-rendezvous 服务端（自主仓库脱敏抽取）
  protocol/            protocol-kit 服务端依赖子集（配对协议/加密，脱敏抽取）
  deploy/              compose + coturn + nginx + DNS-01 证书脚本（自 deploy/relay 复制）
  telemetry-agent/     节点遥测上报器（opt-in，只报聚合计数）
  config-code/         服务配置码生成器（部署页用，版本化+签名+身份指纹）

hypercast-relay-directory/
  README.md
  LICENSE
  docs/
  schema/              ★ 跨仓库协议真源（见 §3）
  registry/            收录/除名/查询 API
  prober/              官方主动探测（uptime/RTT/丢包/TURN 分配）
  web/                 目录网页（状态灯/地区/版本/探测指标/负载/每条目二维码）
  ingress/             遥测接收端
```

## 3. 协议真源与版本纪律（§18 延伸）

三份跨仓库协议的**唯一真源放在 `hypercast-relay-directory/schema/`**（目录是这些协议的中心枢纽——它定义 API、接收上报、生成条目码内容）：

1. `directory-api`（收录/查询/除名，OpenAPI）
2. `telemetry-report`（节点上报格式，JSON Schema：聚合计数，**禁止出现任何用户粒度字段**）
3. `config-code`（服务配置码内容格式：服务地址 + 版本 + 签名 + 身份指纹）

对齐义务：

- `hypercast-relay`（生成配置码、上报遥测）实现按 schema 校验，CI 强制。
- 主仓库（闭源客户端/Host，扫码消费方）按 §18 纪律做**镜像同步 + 对拍 fixture**，冲突以 schema 真源为准。
- schema 变更走 minor 版本；不兼容变更升 major 并在目录条目上标最低要求客户端版本。

## 4. 开源卫生清单（从第一个 commit 就生效）

**原则：内容可以复制，历史绝不携带。** 主仓库历史含生产地址、内部战报、测试设备标识，一律不进开源仓库。

1. **全新 git 历史**：抽取代码以新提交进入，不 cherry-pick / 不 subtree 保留原史。
2. **脱敏 grep 门禁**：提交前跑敏感串清单（初始版）：生产域名 / 生产端口与分配口段 / 测试设备 serial / 本机绝对路径前缀（完整串见 worktree.sh 拼接定义，文档中不落明文）。示例一律用 `relay.example.com`。CI 落一条检查 job。
3. **LICENSE 第一个 commit 就位**（待拍板，见 §8）；无 LICENSE 前仓库不公开。
4. **不带内部宪法**：AGENTS.md（内部规章，含事故细节与生产信息）不复制；开源仓库用 README + CONTRIBUTING 表达规范。
5. **CI 从第一天绿**：`cargo test` + schema 校验 + 脱敏检查。
6. **同步纪律**：短期内服务端开发真源仍在主仓库（生产在跑），改动**复制**到开源仓库并重写提交信息 + 脱敏；M2 后服务端开发主场迁到开源仓库，方向反转（主仓库只消费）。
7. **生产与开源实例隔离**：开源仓库不含任何正在运行的生产节点配置；生产节点另行管理。

## 5. 与主仓库的关系及演进

```
现在（M0-M1）                     M2 之后
主仓库 = 服务端开发真源            hypercast-relay = 服务端开发真源
   │ 内容复制+脱敏                    ▲ 内容镜像
   ▼                                 │
hypercast-relay（开源发布）        主仓库（客户端/Host，消费协议）
```

- 主仓库闭源边界不动：客户端 App、Mac Host、画质/传输实现不开源。
- 开源边界：**服务端 + 部署 + 协议 schema**。protocol-kit 全量不开源，只抽服务端依赖子集（配对协议/加密握手）进 `hypercast-relay/protocol/`。

## 6. 里程碑

| 期 | 内容 | 完成标志 |
|---|---|---|
| **M0 奠基**（本轮） | 两仓库骨架 + 本规划 + README | 目录与 git 初始化完成 |
| **M1 节点栈可部署** | server + protocol + deploy 脱敏抽取；`docker compose up` 一键起 rendezvous+coturn+nginx；自托管诊断 | 干净 VPS 上从零部署成功，客户端扫码可用 |
| **M2 目录 MVP** | schema 三份定稿 v1；registry 收录 + 遥测接收 + 目录页（状态/地区/版本/带宽/负载 + 二维码）；telemetry-agent | 一个测试节点完成 分享→上报→展示 全链 |
| **M3 探测体系** | prober（uptime/RTT/丢包/TURN 分配）；自报/探测**双列展示**；离线自动除名 | 假数据节点在双列对照下现形 |
| **M4 客户端接线** | 主仓库侧：扫目录条目码导入社区中继 + 服务身份标识（§17） | Android 端扫码即用社区中继 |

对应上位方案的 V3 扩展；V4+ 可选中继池自动选优（不在本规划范围）。

## 7. 目录产品铁律（承接 2026-09-14 评审结论）

1. **收录 ≠ 背书**：条目必须标「社区中继 · 第三方运营」，加免责声明；禁止任何"官方认证"暗示。
2. **自报 ≠ 真相**：官方主动探测，自报值与探测值分列展示。
3. **遥测只收聚合计数**：schema 层禁止用户粒度字段；上报 opt-in 默认关。
4. **防枯竭**：条目展示实时负载与建议连接上限，引导分散。

## 8. 待拍板（5 项）

| # | 问题 | 建议 |
|---|---|---|
| 1 | LICENSE | **Apache-2.0**（专利授权条款对企业自托管采纳友好；MIT 亦可，一致性优先） |
| 2 | 仓库名/组织名 | 本规划用 `hypercast-relay` / `hypercast-relay-directory`；GitHub org 名 `hypercast` 可能被占，需选定组织名后统一前缀 |
| 3 | 托管平台 | GitHub 公开为主；国内可达性可后续加镜像（GitCode 等） |
| 4 | protocol 子集开源边界 | 服务端依赖部分（配对握手/加密）开源，protocol-kit 全量与客户端保持闭源——确认此边界 |
| 5 | 目录服务运营主体与部署地 | 合规敏感项（中心化收录公众中继），部署前必须定 |

## 9. 并行开发体系（worktree 隔离）

多任务/多 agent 并行开发采用 **git worktree 隔离**：每个任务一棵独立工作树，互不踩踏，完成后合并回 `main`。

```bash
# 两仓库均自带管理脚本（内容一致，敏感串清单须两边同步扩展）
scripts/worktree.sh new m1-server-extract   # 建工作树：../<repo>-worktrees/m1-server-extract，分支 wt/m1-server-extract
scripts/worktree.sh list                    # 状态总览 + 并发槽位
# ……在工作树内开发、测试
scripts/worktree.sh check                   # 脱敏门禁（合并前必跑，敏感串清单见脚本头）
# 回主仓库合并，然后清理
scripts/worktree.sh rm m1-server-extract
```

约定：

- **主分支 `main`**（开源惯例）；工作分支一律 `wt/<任务名>` 前缀，便于识别与批量清理。
- **并发软上限 10** 个工作树（脚本内置；确需超过 `FORCE=1`）。超过 10 个通常说明任务拆分过细或该合并了。
- **合并三件套**：工作树内测试绿 + `check` 脱敏门禁绿 + 主仓库 `git merge --no-ff wt/<name>`（保留任务边界可回溯）。推 GitHub 后切换 PR 工作流。
- **worktree 目录在仓库平级**（`../<repo>-worktrees/`），天然不进 git 历史，无需 gitignore。
- **每个工作树独立 `target/`/`node_modules`**（构建产物不共享），磁盘换隔离，10 并发规模完全可接受。

**目录迁移（本地 → GitHub / 换父目录）**：git 仓库自包含，`git remote add origin … && git push -u origin main` 即可随时上远端；本地目录改名/移动零成本，但 **worktree 的 `.git` 指针记录主仓库绝对路径——迁移后必须先跑 `git worktree repair`**，再继续用。

## 10. 公开前 checklist（仓库随时可开源的最后一道闸）

"从创建起即开源状态" 的例行审查点，逐项过完才 `git push` 到公开远端：

1. LICENSE 已定稿并落在仓库根（待拍板项 1）。
2. `scripts/worktree.sh check` 全绿（敏感串清单复核一遍，含新增 pattern）。
3. commit 历史走查：无生产地址/内部信息混入（奠基起全新史就是为这一步零成本）。
4. CI 配置就绪（`cargo test` + schema 校验 + 脱敏检查 job）。
5. README 可被陌生人理解：是什么/怎么部署/安全模型一句话。
6. 主仓库侧镜像账本已登记本次同步（避免双源漂移）。


## 12. 部署形态与 Cloudflare 边界（2026-09-15 定档）

**CF 能做 rendezvous（握手/信令），做不了 TURN（中继）**——两种自托管形态由此成立：

| 形态 | 载体 | 包含 | 打洞失败时 | 目录标注 |
|---|---|---|---|---|
| 完整中继节点 | VPS（docker compose） | rendezvous + coturn（UDP-only TURN） | TURN 中继兜底 | `capabilities.turn=true` |
| 仅信令节点 | CF Workers / PaaS | rendezvous only | 明确报错（配客户端「仅直连」模式） | `capabilities.turn=false`，网页标「无中继兜底」 |

- **为什么 CF 做不了中继**：TURN 需要 UDP socket + 中继分配端口段，Workers 无 UDP listener，平台模型无解；且 TCP 承载实时负载违反传输铁律。
- **为什么 CF 能做信令**：rendezvous 全部是 HTTP/WSS 控制面（协议边界允许 TCP 的部分）；Workers + Durable Objects 支持 ws，全球边缘 + 自带证书 + 免费额度适合公益碰头点。
- **移植成本（诚实口径）**：axum/tokio 长驻模型不能直接上 Workers——API 层需 Workers 版重写，邮箱/会话状态放 DO，落盘 JSON 换 KV/D1；**协议层零成本**（protocol-kit 纯函数禁 IO 即为 WASM 准备，编 WASM 后 transcript 逻辑原样复用，对拍 fixtures 继续锁定）。
- **schema 演进**：`register` 增加 `capabilities` 字段（v1.1，向后兼容）；目录网页展示中统能力，禁止信令节点被误读为有兜底。
- CF Workers 版实现排期在 M4 客户端接线之后（先立 VPS 形态，CF 形态第二波）。
