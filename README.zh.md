> 社区翻译（草稿）—— NTARI 政策 P2-002《全球多语言广播》。来源：README.md（英文原版，2026-07-29 快照）。本文件为机器辅助的社区草稿，依据 P2-002 §3.1 尚待区域维护者审校。根据 §2.2，核心技术规范仍以英文为准。
>
> 如发现译文有误，欢迎 fork 仓库并提交 Pull Request
> 来改进翻译：https://github.com/NTARI-RAND/Cloudy。翻译修正与代码贡献同样宝贵，我们诚挚欢迎。

# Cloudy

SoHoLINK / sohocloud 协调网络上的一个前端。Cloudy 是成员进行交易的地方；
它通过共享的 `sohocloud-protocol` 模块消费基底（substrate）层的协调能力，
并在其之上拥有自己的 JFA 成员经济。

## 现状（如实陈述）

Cloudy 所拥有、而协议刻意不拥有的三个 JFA 成员经济层，现已**构建完成，
并附带测试**。目前仍没有实时协调循环，也没有面向成员的界面。

- **`internal/record` —— 已构建。** 对话双方共同封印（dialog-sealed）、
  仅追加、有见证的记录：每条 Entry 都携带双方成员对规范化、域分离字节的
  封印，因此只封印了一半或自我交易的契约永远无法进入日志；按 operator
  划分的哈希链日志会在 `OpenLog` 时被完整重新校验；operator 检查点加上
  独立见证方的会签，使任何对已设检查点历史的改写在密码学上都可被检测
  （即 CT 式的职责分解），而单见证方部署会被如实标注为它本来的样子——
  一种临时替代。公共域（commons）中不存在任何 PII 形态——可识别身份的
  内容只存放在可擦除的、成员本地的 Locker 中。叶哈希 `Entry.ID()` 是唯一
  的跨层交换引用。
- **`internal/economy` —— 已构建。** 按平台自主的互助信用（mutual
  credit）：信用在消费发生的那一刻发行，受同一个统一的、受治理的借记上限
  约束，且所有余额之和始终恰好为零。铸币、法币字段、兑付或备注均无法被
  表示；从「先托管」到「后信用」（escrow-now/credit-later）的切换，恰好
  就是同一个仅追加存储上的一条经法定人数签名的 PolicyChange；`Open` 会
  完整重放并重新校验每一条记录。`Spend.ExchangeHash` 携带记录条目的叶 ID，
  但在 Post 时刻意保持不透明且不做检查——锚定属于组合根（composition
  root）的职责。
- **`internal/covenant` —— 已构建。** 基于 NTARI 的 Leveson-Based Trade
  Assessment Scale（LBTAS）的声誉系统：六个承载明确含义的等级，从
  -1 No Trust（不信任）到 +4 Delight（欣喜），双向进行（一次已封印交换的
  双方互相评估），在一份封闭词汇表上按类别分别呈现（默认类别：
  reliability、usability、performance、support），且只能以完整的按等级
  计数分布来读取——分类别分布、汇总整体分布，以及一个让每个 -1 都浮出
  水面的伤害计数——**绝不取平均**，任何地方都不存在分数、导出、修订、
  撤回或跨成员比较（两个绊线测试——一个反射方法集扫描和一个 go/ast 导出
  函数扫描——确保这一点持续成立）。给出 -1 的判定必须附上说明理由的评语；
  评语文本存放在可擦除的成员本地 Locker 中，公共域里只承载其哈希。每份
  评估都由评估方签名，并通过 Anchors 门控以一次已封印交换为代价计价；
  成员 ID 是平台作用域的密钥哈希，人为选择的 ID 会被直接拒绝。具有约束力
  的规范与参考实现位于
  `Development/Covenant/Leveson-Based-Trade-Assessment-Scale`。
- **真实但很薄：** `internal/coord` —— 一个建立在协议参考 HTTP+JSON 传输层
  之上的瘦客户端，用以证明 Cloudy 确实在消费 `sohocloud-protocol`。
  `cmd/cloudy` 会构造它并报告启动情况；目前还没有实时协调循环。

`cmd/cloudy` 现在会在启动时于内存中构造全部三层（ModeEscrow 创世状态、空的
operator 日志、建立在空的共享成员目录之上的空契约簿），并为每一层输出一行
如实的日志。每个包都在其包文档中列明了自己不可妥协的不变量。

## Cloudy 拥有什么（架构）

在已确定的架构下，作为前端的 Cloudy 拥有成员的整个世界。三项能力，一个
所有者：

- **JFA 成员经济 —— 已构建。** `internal/economy`（成员发行的信用）、
  `internal/covenant`（LBTAS 声誉）、`internal/record`（对话双方共同封印的
  记录），与上文所述完全一致。这些属于 Cloudy，并且刻意不属于协议：人从不
  出现在线路上。
- **节点代理（node agent）—— 归 Cloudy 所有，目前暂存于协调器仓库，待
  迁移。** 硬件检测、资源画像、能力清单生成、心跳、作业执行器、本地退出/
  许可名单（opt-out/allowlist）的执行、遥测，以及成员机器安装程序。这部分
  代码（`internal/agent`、`cmd/agent` 以及 MSI 安装程序）如今位于 SoHoLINK
  仓库并继续在那里运行——这是 SoHoLINK「前端+协调器」双重角色时代的遗留，
  并非 SoHoLINK 的长期角色。代理是成员在自己机器上的存在形态，因此归属于
  前端；一个把代理部署到成员硬件上的协调器，就是一个会触碰成员硬件的
  协调器，而这是 SoHoLINK 绝不可以做的事。
- **成员门户（member portal）—— 归 Cloudy 所有，目前暂存于协调器仓库，待
  迁移。** 注册、登录、仪表盘、作业提交与退出。此前被称为「参与者门户」的
  那个界面（SoHoLINK 仓库中的 `internal/portal`、`cmd/portal`、`web/`）自此
  成为 Cloudy 的成员门户——成员身份是前端的关切，因此成员走进来的那扇门
  必须是前端的门。

既然三层已在库级别完备，节点代理和成员门户就是接下来的构建里程碑。正如
上文现状部分所如实陈述的：两者在本仓库中都还没有入口，本仓库中也没有任何
内容假装迁移已经发生。

### 术语表

- **成员（Member）** —— 一个人，且始终相对于某个前端/平台而言。身份（平台
  作用域的 MemberID）、信用、LBTAS 评级状况、已封印的记录、PII（可擦除、
  成员本地存储）以及所贡献的机器，都是成员资格事实。成员资格是契约语言——
  对某个特定平台的相互义务；通过密码学构造，同一个人在每个平台上都是不同
  的成员。
- **参与者（Participant）** —— 一种角色，而非一个实体：在被协调的经济中
  行动的成员，贡献节点和/或提交作业——一个统一的身份，绝不拆分为生产者与
  消费者。协调器侧的人员记录（SoHoLINK 的 participants 表和门户账户）是双重
  角色时代留下的过渡性界面。
- **节点（Node）** —— 成员贡献的一台机器，由 NodeID 标识，SPIFFE 绑定为
  `/node/<id>`（协议的 `identity/` 包）。

### 面向协调器的身份

有两种身份会跨越前端/协调器边界，二者绝不能混为一谈。成员的机器携带的是
**工作负载身份**：`/node/<id>` 下的一份 SPIFFE SVID，在协调器侧严格按照协议
SPEC 授权——这是机器身份，保持不变。Cloudy 自身则以一个已登记的
**operator（运营方）** 身份进行认证：即「前端即 operator」模型，这是一个
**设计目标**，仿照 Agrinet 第 5 阶段（Phase 5）的 operator 方案（一个
operators + operator-keys 注册表；一组共七把、轮换使用的 Ed25519 密钥，每次
传输用其中两把签名；重放由时间戳窗口加 nonce 缓存加以约束——参见
`Development/Economy/Agrinet backend/lib/operatorKeys.js` 与
`backend/middleware/operatorAuth.js`）。轮换正是重点所在：一把静态的、从不
轮换的共享密钥，恰恰是该参考实现警告不要继承的反模式。这两种身份都永远不是
某个人：成员身份始终留在 Cloudy 内部。

## 导入图不变量

Cloudy 导入 `sohocloud-protocol`；**没有任何东西导入 Cloudy**。Cloudy 依赖
协议的核心及其参考传输层，且不会绕过其中任何一个。这个依赖方向正是让前端与
协调器保持可分离的关键：前端可以在不触碰基底层的情况下被替换，而基底层也
并不知晓任何特定前端的存在。

在 Cloudy 内部，三个 JFA 包从不互相导入；每个包只看得到标准库和协议的
`canon` 包，且所有导入都保持单向。它们只在组合根处相遇：`test/composition`
是唯一的组合根测试——唯一的共享成员目录、在 `Entry.ID()` 上把契约与记录
连接起来的 Anchors 谓词，以及完整的成员故事都在那里——而 `cmd/cloudy` 在
启动时执行同样的组合。

## 构建

协议模块目前是私有且未打标签的。本骨架通过一条 `replace` 指令，将其解析到
一个**本地同级检出目录**：

```
replace github.com/NTARI-RAND/sohocloud-protocol => ../sohocloud-protocol
```

因此 `sohocloud-protocol` 必须克隆到 `Cloudy` 旁边（两者位于同一个父目录
之下）。这条 `replace` 只是本地开发的便利手段——按现状其他人无法直接构建。
若要发布 Cloudy 供外部构建，需要为协议模块打标签（或配置 `GOPRIVATE` 加
认证拉取方案），并移除该 `replace`。

```
go build ./...
go test ./...
```

## 许可证

AGPL-3.0-or-later.

*Network Theory Applied Research Institute, Inc. — 501(c)(3) — EIN 92-3047136 — info@ntari.org*
