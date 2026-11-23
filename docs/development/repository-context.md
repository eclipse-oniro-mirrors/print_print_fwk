# 仓库定位与代码上下文

在首次读取业务源码、跟踪跨仓调用、选择构建目录或定位不到依赖时，按本文定位源码。以当前业务检出为锚点，按任务加载相关仓库；目录名只提供候选，仓库身份、当前源码和构建关系共同构成上下文。

## 1. 确定当前检出与环境

1. 在当前目录执行 `git rev-parse --show-toplevel`，记为 `PROJECT_ROOT`。Git worktree 的 `.git` 可以是文件，不以 `.git` 是否为目录判断仓库。后续文档路径相对 `PROJECT_ROOT`。
2. 只检查 `PROJECT_ROOT` 的祖先目录。某祖先同时具有 `build.sh`、`build/`、`base/`、`third_party/`，且其中 `base/print/print_fwk` 的规范化真实路径等于当前检出，才记为 `OH_ROOT`。有多个匹配时先报告歧义。`.repo`/manifest 可辅助确认版本，不能单凭同名目录或 `.repo` 判定。
3. 满足上项为编译树布局；否则为独立检出布局。编译树布局只证明源码组织方式，工具链、产品配置和构建能力仍须按[编译命令](build.md)核实。远端构建机、WSL 和 Windows 的检出分别记录，不能把一个环境的绝对路径直接交给另一环境。

完成后得到当前检出绝对路径、布局及其依据。切换工作目录、worktree、分支或用户提供新的源码根后重新核实，不沿用旧会话的绝对路径。

## 2. 按任务选择仓库

表中源码树路径相对 `OH_ROOT`；独立目录候选相对 `PROJECT_ROOT` 的父目录。GitCode 列为团队上游位置，不替代本地实际 remote。`cups-filter` 统一按 `cups-filters` 定位，`sane` 指 SANE 核心，AirScan 是其另一个仓库中的后端。

| 组件与触发条件 | 源码树路径 | 独立目录候选 | GitCode 上游 | 身份与源码入口 |
| --- | --- | --- | --- | --- |
| 框架：API、IPC、服务与状态 | `base/print/print_fwk` | 当前检出 | [print_print_fwk](https://gitcode.com/openharmony/print_print_fwk) | `bundle.json` 的组件 `print_fwk`；`services/` |
| CUPS：队列、IPP、调度与传输 | `third_party/cups` | `third_party_cups`、`cups` | [third_party_cups](https://gitcode.com/openharmony/third_party_cups) | 组件 `cups`；`cups/`、`scheduler/`、`backend/` |
| 过滤器：格式转换、光栅和过滤链 | `third_party/cups-filters` | `third_party_cups-filters`、`cups-filters` | [third_party_cups-filters](https://gitcode.com/openharmony/third_party_cups-filters) | 组件 `cups-filters`；`filter/`、`cupsfilters/` |
| SANE 核心：加载后端、选项、读写与取消 | `third_party/backends` | `third_party_backends`、`backends` | [third_party_backends](https://gitcode.com/openharmony/third_party_backends) | 组件 `backends`；`include/sane/`、`backend/`，构建导出 `backends:sane` |
| AirScan：eSCL/WSD 协议扫描 | `third_party/sane-airscan` | `third_party_sane-airscan`、`sane-airscan` | [third_party_sane-airscan](https://gitcode.com/openharmony/third_party_sane-airscan) | 组件 `sane-airscan`；`airscan.c`、`BUILD.gn` |
| cups-backend：打印后端进程与设备传输 | 先定位 CUPS，再进入 `backend/` | 随已确认的 CUPS 检出 | 同 CUPS 上游 | 本表没有独立 `cups-backend` 仓库；具体 backend 依 URI、构建和安装配置核实 |

如果实际调用或构建依赖指向其他 backend/filter，沿该依赖确认归属，记录真实仓库地址与证据；不能从组件别名拼造一个 GitCode 仓库。其他依赖同样由当前调用或构建关系触发查找。

## 3. 定位与消除歧义

按下列顺序处理任务需要的每个组件：

1. **用户指定路径**：先检查用户明确指定的该组件检出。路径不存在、不可读或身份不匹配时报告具体原因，保留为未解决；不要静默换成另一个版本。
2. **编译树布局**：仅检查表中 `OH_ROOT` 下的路径，并用当前 manifest、`bundle.json`、`BUILD.gn` 复核映射。缺失表示当前树不完整；不自动用相邻独立检出补齐构建依赖。
3. **独立布局**：检查表中同级候选。未命中时，只列举当前父目录的一层子目录及用户已提供的其他 workspace roots，通过 remote 和组件标识查找改名检出。多个候选均匹配时输出路径、版本和 remote 差异，等待用户指定；不能按修改时间或名字最相似选取。
4. **仍未找到**：记为缺失、不可访问或身份待确认，说明已检查范围，向用户索取具体路径。继续可独立完成的本仓分析。定位本身不执行 clone、fetch、checkout 或全盘递归搜索。

验证每个候选时执行以下只读命令（将 `<候选路径>` 替换为当前环境的路径）：

```sh
git -C "<候选路径>" rev-parse --show-toplevel
git -C "<候选路径>" status --short
```

规范化首条结果并与候选目录比较，防止把外层 Git 仓内的普通文件夹当成独立仓库；链接目录按真实路径去重。检查该目录的 `bundle.json` 中 `component.name`、`segment.destPath` 与目标入口，再读取 Git remote 配置核对身份。展示 remote 前去掉 userinfo、查询串和令牌，不输出凭据；缺少 remote 时标记未配置，不能伪装为已验证的上游地址。

SSH/HTTPS 地址可归一化主机与仓库路径、去掉 `.git` 比较。fork 的 owner 可以不同：记录实际 fork 与本表上游，结合组件、入口和用户指定来源确认；不能只凭仓库 basename 或 `origin`/`upstream` 这个名字认定身份。身份冲突保留为待确认。

当前构建文件或 manifest 与表格冲突时，保留冲突证据，以用户目标版本的可核实映射继续定位，并反馈维护条目；本表不能覆盖当前源码事实。

## 4. 输出最小上下文并按需追踪

定位结束后，在当前任务记录以下字段；只记录本次需要的组件：

| 组件 | 布局 | 本地绝对路径 | 工作区修改 | 实际 remote／上游 | 定位依据 | 状态 |
| --- | --- | --- | --- | --- | --- | --- |
| 目标组件 | 编译树或独立检出 | 当前主机路径或未找到 | 相关修改或无修改 | 脱敏地址或未配置 | 组件、入口、构建依赖 | 已确认／缺失／歧义／不可访问／身份待确认 |

上下文中的本机路径留在当前任务，不回填共享文档。存在相关修改时，引用工作区文件并说明差异。版本兼容性由构建和接口验证判断，不能把同名分支当作兼容证明。

随后从[架构导航](../architecture/overview.md)选择主题，仅在受影响仓库的对应模块检索符号，追踪调用、接口和构建两端，引用仓库、文件、函数及当前行号。打印后端从队列 URI／配置和 `backend/` 入手；扫描从框架 `backends:sane` 依赖进入 SANE，再按实际后端进入 AirScan。找到源码不代表产品已打包或设备已运行。

## 5. 映射的源码依据

以下提供源码查找入口。每次使用时读取当前检出的文件与构建配置，不绑定固定 commit ID；目录定位无需采集 commit ID。

| 仓库 | 文件与定位 | 支持的映射 |
| --- | --- | --- |
| print_print_fwk | `bundle.json`；`services/print_service/BUILD.gn`；`services/sane_service/BUILD.gn` | 框架路径、CUPS/filters 依赖及 `backends:sane` |
| third_party_cups | `bundle.json`；`backend/ipp.c` | CUPS 源码树路径及仓内 backend |
| third_party_cups-filters | `bundle.json` | filters 源码树路径 |
| third_party_backends | `bundle.json` | SANE 核心路径与导出目标 |
| third_party_sane-airscan | `bundle.json`；`BUILD.gn` | AirScan 路径及 SANE 依赖 |
