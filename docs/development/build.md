# 打印扫描编译命令

本文提供打印扫描模块的常用编译命令，以 OpenHarmony `rk3568` 产品为例。

## 执行前提

- 在已准备好源码、依赖和工具链的 Linux 或 WSL Bash 中执行，工作目录为同时包含 `.gn` 和 `build.sh` 的 OpenHarmony 源码根目录，不是单独的 `print_print_fwk` 仓库。
- 示例产品为 `rk3568`。执行前确认需求产品、源码分支及产品包含的打印扫描部件；产品不匹配时先明确目标，再调整命令。
- 执行前用当前源码树的 `./build.sh --help` 核对参数。
- `--build-target` 接收 Ninja 目标名。部件使用 `print_fwk`，带路径的目标使用 `base/print/print_fwk/...:目标名`；GN 文件中以 `//` 开头的标签不能直接照搬到这里。目标必须已纳入当前产品的构建图。
- `--ccache` 用于启用编译缓存，需要构建环境能够找到 `ccache`；它不改变所选构建目标的覆盖范围。

## 常用命令

### print_fwk 部件构建

常规修改验证优先选择部件目标，覆盖产品配置纳入的打印扫描框架、服务及其依赖。部件名来自 `bundle.json` 的 `component.name`，不是仓库名 `print_print_fwk`。该命令不包含独立的测试目标，也不代表所有特性组合均已验证。

```bash
./build.sh --product-name rk3568 --build-target print_fwk --ccache
```

### 产品完整构建

需要验证整产品集成或生成系统镜像时使用。在源码根目录不指定 `--build-target` 时，构建入口选择产品镜像目标。

```bash
./build.sh --product-name rk3568 --ccache
```

### 打印或扫描服务定向构建（可选）

仅修改某个服务内部实现或定向复编失败目标时，按需选择以下命令。服务目标只构建该服务及其依赖，不覆盖整个部件；涉及公共接口、NAPI、客户端、跨模块依赖或部件级构建配置变化时，使用上面的部件构建，并按影响补充测试与集成验证。

```bash
# 打印服务
./build.sh --product-name rk3568 --build-target base/print/print_fwk/services:print_service --ccache

# 扫描服务
./build.sh --product-name rk3568 --build-target base/print/print_fwk/services:scan_service --ccache

# SANE 服务
./build.sh --product-name rk3568 --build-target base/print/print_fwk/services:sane_service --ccache
```

`services:print_service` 根据 `print_fwk_feature_device_isolation` 选择标准版或 phone 实现。执行前核对目标产品的有效配置，产品差异见[产品与跨仓边界](../architecture/variants-and-boundaries.md)。

### 打印扫描测试构建

```bash
./build.sh --product-name rk3568 --build-target base/print/print_fwk/test:test --ccache
```

该组包含单元测试和 fuzz 目标，并根据设备隔离开关选择对应测试目录；它不是仅单元测试目标，也不包含仓库所有独立登记的工具测试。只验证特定用例时，从对应 `BUILD.gn` 核实更小的目标。编译测试产物不代表已执行测试。

### 快速重编译

已有同一产品和目标的有效构建输出，且仅源码变化、构建配置及依赖均未变化时，可在原命令后追加 `--fast-rebuild`。该选项跳过预加载、加载及 GN 生成阶段。首次构建，或修改 `BUILD.gn`、`*.gni`、产品配置及部件依赖后，使用普通构建命令重新生成配置。

## 日志与验证

`rk3568` 示例先检查 `out/rk3568/build.log`；其他产品以构建工具输出的实际日志路径为准。失败时定位首个失败目标及其错误上下文，再选择定向重编译。

交付记录应包含源码版本、实际命令、产品与特性配置、退出码和日志位置。分别记录编译、测试执行及设备验证结果。
