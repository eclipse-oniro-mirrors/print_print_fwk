# 产品差异、后端路由与跨仓契约

同名打印接口可以经过不同服务实现和后端。先确认“实际构建了什么、请求走哪条路、接口两端各是谁”，再讨论兼容性和修复范围。构建开关和服务路径用于说明产品差异，有效配置应在目标产品中确认。

跨仓分析前使用[仓库定位与代码上下文](../development/repository-context.md)确认本地路径、GitCode 来源及版本。CUPS 的 `backend/` 与 SANE 的 `third_party_backends` 分属不同组件；按当前构建和调用证据确定后端归属。

| 项目 | 说明 |
| --- | --- |
| 适用范围 | 需求影响分析、标准版／phone 对照、CUPS／扩展／Agent 和 SANE／AirScan 边界 |
| 使用边界 | 说明构建、路由和跨仓责任；产品组合可用性需结合有效构建配置、产物和设备验证 |
| 维护与触发 | 构建开关、后端选择、IPC／ABI、跨仓字段、依赖或协议语义改变时更新；复核人由维护者指定 |

## 一、产品与构建矩阵

| 条件 | 定义或选路 | 需要进一步确认 |
| --- | --- | --- |
| `print_fwk_feature_device_isolation` | `print.gni` 声明默认 false；`services/BUILD.gn` 为 true 时选择 `print_service_phone`，否则选择 `print_service` | 实际产品是否覆盖、最终编译目标；不能按设备名称猜测分支 |
| `cups_enable` | `print.gni` 中赋值 true；两个打印服务的构建文件均有条件加入 CUPS 源码、宏和依赖的逻辑 | 具体构建求值结果；这不是两个服务在所有禁用组合下都已验证可构建的证明 |
| `print_fwk_feature_remote_service` | 声明默认 false；服务中 `REMOTE_SERVICE_ENABLE` 包围远程打印机的扩展路由 | 实际远程服务实现、注册与设备选择 |
| `print_fwk_feature_print_fwk_agent_client` | 声明默认 false；标准版构建条件加入 Agent loader／manager 和 `PRINT_FWK_AGENT_CLIENT_ENABLE` | Agent 动态库、服务、后端环境与运行时是否匹配；不等于开关开启就已具备完整 VM 打印 |
| 企业、EDM、水印、SMB 等特性 | `print.gni` 分别声明，构建与调用处各自有条件处理 | 按涉及路径追踪，不能从一项开启推断其他依赖齐全 |
| 扫描与 SANE 服务 | `services/BUILD.gn` 有独立目标，不在打印标准版／phone 的二选一分支中 | 这只说明该文件组织方式；产品是否实际打包、后端与 SDK 是否支持仍需验证 |

### 1.1 标准版与 phone 的差异

| 比较点 | 标准版 | phone |
| --- | --- | --- |
| 源码位置 | `services/print_service/` | `services/print_service_phone/` |
| 内部提交入口 | `StartPrintJobInternal` | `StartPrintJobInternal` |
| 核对到的共同路由 | ePrint／启用时的远程打印机走扩展，其他请求进入 CUPS | 当前函数具有相同的基本选路结构 |
| Agent 准备 | 当前函数有 `PRINT_FWK_AGENT_CLIENT_ENABLE` 下的 `PreparePrintJob` | 单独核对 Agent 的构建与路由接入，不能照搬标准版能力声明 |
| CUPS 提交 | 标准版 `StartCupsPrintJob` 直接调用 CUPS 适配 | phone 的函数体中 CUPS 调用受 `CUPS_ENABLE` 包围 |
| 数据、取消与测试 | 必须继续检查标准版对应实现 | 同名函数不代表实现同步；逐项比对，测试还需检查 `test/phone_test/` |

本表用于比较关键路由；同名入口的其他行为仍需分别核对。

## 二、按运行时路由确定依赖

| 路由 | 当前可核实的边界 | 设计或定位时的限制 |
| --- | --- | --- |
| 打印扩展 | 服务构造 `CallbackInfo`，通过监听管理执行扩展回调 | 回调被安排不等于扩展已完成；还要看监听、扩展实现和状态回传 |
| CUPS | Framework 构造参数、创建下游任务、发送文档和查询状态 | 下游可能是设备、远程队列或其他 backend；记录实际 URI 与每一级 job-id |
| Agent 辅助打印 | 标准版在内部提交前准备后端和保活，之后仍执行既有路由 | 不能画成“Agent 返回成功后必然绕开本机 CUPS”的通用数据路径 |
| Agent 添加设备 | 完成回调读取 `ippUri`，登记 pending 元数据并上报 `DONE / PENDING_DISCOVERY` | 这是仍待后续发现关联的阶段，不是完整连接、持久化与 UI 流程已完成 |
| 通用扫描 | 扫描服务 → `SaneManagerClient` → SANE IPC → `SaneServerManager` → `SafeSANEAPI` → SANE 后端 | 服务返回与后端状态分层；具体后端是否支持选项需分别验证 |
| eSCL／AirScan 扫描 | 扫描服务生成 AirScan 设备 ID 并准备后端配置；图像读取沿通用 SANE 链路 | 不把 eSCL 发现／状态辅助逻辑误写成独立绕过 SANE 的图像传输实现 |

## 三、跨仓责任和证据边界

| 组件 | 职责与模块入口 | 跨仓契约需要记录什么 | 需要单独确认什么 |
| --- | --- | --- | --- |
| `print_print_fwk` | 接口、模型、IPC、服务路由、状态和资源处理 | 调用者、用户、设备／任务标识、参数、回调、FD 和错误 | 外部组件内部行为与设备结果 |
| `third_party_cups` | 文件包装与关闭、作业调度和 filter 进程启动 | 队列名、实例及 job-id、文档格式、IPP 返回、状态原因、FD 关闭责任 | 实际 backend、取消状态转换及目标设备的安装配置 |
| `third_party_cups-filters` | `cupsfilters` 库及 `imagetoraster`、`imagetopdf` 等格式转换程序 | 输入／输出格式、选项映射、实际选择的转换程序和错误 | 声明依赖不代表某任务一定运行某个 filter，也不证明所有源目录都进入产品 |
| SANE 核心与设备后端 | 框架 `sane_service/BUILD.gn` 依赖 `backends:sane`；包装层调用 SANE API | 设备名、句柄、选项描述、深度／格式／尺寸、读取长度、EOF、取消与关闭 | `third_party_backends` 的后端加载方式与产品集成配置 |
| `third_party_sane-airscan` | 提供 SANE 后端入口，衔接 eSCL／WSD 协议 | SANE 侧设备 ID 与后端协议、格式、读取／取消语义 | 上游后端支持列表不等于 OpenHarmony 产品启用了全部协议或设备组合 |
| `applications_print_spooler` | 应用侧交互、预览、临时文件和任务展示 | 需求涉及预览、临时文件、显示状态时，核对接口调用和回调消费 | 不能凭 Framework 的回调推断 UI 已显示、文件已删除或恢复策略生效 |
| Agent Client、`printer-agent`、VM CUPS | 通过 Framework 的 loader／manager 对接外部服务与 VM 打印环境 | ABI 版本、请求／结果字段、队列 URI、进度阶段、同步／异步回调及保活 | 外部后端安装、驱动选取、网络发现和真实打印能力 |

各组件的职责划分不代表任意版本组合都兼容。Spooler、VM Agent 和 SANE 核心的具体行为，应在相关需求或问题定位任务中核对。

## 四、跨层契约检查表

对具体需求填写下表涉及的字段，无影响项写明原因。接口两端需要各自的仓库、提交、路径和符号。

| 边界 | 输入与输出 | 状态与错误 | 资源与时序 |
| --- | --- | --- | --- |
| 应用／绑定 → Framework IPC | 参数、任务／设备标识、用户与权限 | 绑定异常、IPC 返回、服务错误分别解释 | FD 接收责任、异步回调对象、调用者退出 |
| Framework → CUPS | 队列目标、格式、作业选项、文档数据 | 创建、传输、监控和下游完成分别记录 | 同一文件 FD 的包装／关闭、参数对象与监控对象的不同存活期 |
| CUPS → filter／backend | 选择依据、目标格式、实际参数与设备 URI | 进程结果、协议返回、job-state 与原因的转换 | 输入输出流、取消传播、子进程和连接结束 |
| Scan SA → SANE SA | scannerId、选项／参数、读取请求 | IPC ErrCode 与 SANE status 两层结果 | 后端句柄、读取与取消／关闭交错 |
| SANE → 设备后端 | 后端设备名、参数、图像格式与读取缓冲区 | GOOD、EOF、无纸、取消、设备失败的转换 | 阻塞读取的终止方式与后端资源释放 |
| Framework → Agent ABI | 请求字段、返回 URI、进度和完成回调 | 请求提交、回调成功、PENDING_DISCOVERY 与最终添加分开 | 参数字符串生存期、userData、同步回调可能性和保活结束 |

变更前后应分别说明：旧调用者是否仍能工作，未升级的接收端如何处理新字段或状态，失败是否可重试，重复回调／取消是否安全，发布与回退顺序是什么。源码未能回答的行为列为待验证项。

## 五、产品事实怎样验证

按层保存证据：源文件的条件 → 实际构建参数与命令 → 产物中的服务／库／符号 → 设备加载和路由 → 业务结果。

| 问题 | 需要的证据 |
| --- | --- |
| 当前运行标准版还是 phone | 有效特性值、服务目标及实际生成命令；设备型号名称不足以判定 |
| Agent 是否真正接入 | 宏和 loader／manager 产物、外部库 ABI、运行状态、请求与回调记录 |
| 任务为何进入某个后端 | 源码选路、打印机记录／URI、实际队列、CUPS 或扩展日志 |
| AirScan 是否被加载 | 镜像后端库、配置和链接、SANE 设备名、打开／读取日志；只看到源码文件不够 |
| API 是否在目标产品可用 | SDK 声明、API version、系统接口及权限标记、目标实现与实际运行结果 |
| 参数跨仓是否正确 | 各层收到的值与转换、最终设备或结果文件；仅在入口写入 option 不足以证明下游生效 |

架构说明用于组织这些验证，不能替代各层的实际证据。有效编译命令、ELF、设备和端到端验证须由具体开发任务补齐。

## 六、维护与使用

新增产品或后端时，先在本文补一个有来源的条件与契约条目，再在[打印链路](../workflows/print-job.md)或[扫描链路](../workflows/scan.md)补相应阶段及回归场景。术语发生变化时同步[领域定义](../domain/overview.md)。保持入口兼容，避免复制出多份同名状态表。

成员从[架构导航](overview.md)进入相关主题。发现事实与当前源码不同，反馈时提供产品、源码提交、对应条目及证据，供维护者复核更新。
