# OpenHarmony 打印扫描框架

## 项目概述

OpenHarmony 打印扫描框架是一个为 OpenHarmony 操作系统提供打印和扫描功能的完整解决方案。该框架实现了打印服务和扫描服务，支持多种设备连接方式和协议，为应用程序提供统一的打印和扫描接口。

## 系统架构

### 打印系统架构

打印系统采用分层设计，主要包括：
- 接口层：提供 NAPI、JNI 等多种接口
- 框架层：实现打印核心逻辑和设备管理
- 服务层：提供系统能力服务
- 驱动层：支持 CUPS、IPP Everywhere 等多种打印协议

开发者可以基于[打印扫描驱动开发指南](https://gitcode.com/openharmony/applications_print_spooler/blob/master/OpenHarmony%E6%89%93%E5%8D%B0%E6%89%AB%E6%8F%8F%E9%A9%B1%E5%8A%A8%E5%BC%80%E5%8F%91%E6%8C%87%E5%8D%971.8.md)开发打印机和扫描仪的驱动。

**图 1**  打印部件架构图

![](figures/print-architecture.png)

**图 2**  打印流程图

![](figures/printSystemArchitecture.png)

打印逻辑流程如下：

首先，打印请求到打印框架，再从打印系统框架发送到打印预览界面（PrintSpooler），拉起打印预览界面到应用层。由PrintSpooler向打印服务(PrintSA)发送开启发现能力指令，再由PrintSA向打印扩展接口(PrintExtension)发送开启发现能力指令，然后PrintExtension向第三方打印扩展接口(CustomPrintExtension)发送开启发现能力发现打印机。CustomPrintExtension向打印服务（PrintServiceAbility）上报发现打印机信息并返回到PrintSpooler。由打印预览界面（PrintSpooler）发送打印任务到打印服务（PrintServiceAbility），再发送到打印扩展(PrintExtension)，之后发送给第三方打印扩展（CustomPrintExtension），再发送给打印机。

### 扫描系统架构

扫描系统同样采用分层设计：
- 接口层：提供统一的扫描 API
- 框架层：实现扫描核心逻辑
- 服务层：提供扫描系统能力
- 驱动层：基于 SANE 后端，支持多种扫描设备

**图 3**  扫描部件架构图

![](figures/scan-architecture.png)

**图 4**  扫描流程图

![](figures/scanSystemArchitecture.png)

扫描系统的后端是基于[SANE](https://gitcode.com/openharmony/third_party_backends)开发的驱动，驱动提供连接扫描仪的能力。
三方应用通过驱动安装应用将驱动安装到系统沙箱，应用通过系统API调用扫描框架，由扫描服务加载后端驱动连接扫描仪。

## 目录结构

```
print_print_fwk/
├── etc/             # 配置文件目录
│   ├── init/        # 初始化配置
│   └── param/       # 参数配置
├── figures/         # 架构图
├── frameworks/      # 框架代码
│   ├── ISaneBackends/   # SANE 后端接口
│   ├── ani_util/        # 动画工具
│   ├── helper/          # 辅助工具
│   ├── innerkitsimpl/   # 内部实现
│   ├── kits/            # 开发套件
│   ├── models/          # 数据模型
│   ├── ohprint/         # 打印接口
│   └── ohscan/          # 扫描接口
├── interfaces/      # 接口定义
│   └── kits/            # 开发接口
├── profile/         # 配置文件
├── services/        # 服务实现
│   ├── print_service/   # 打印服务
│   ├── sane_service/    # SANE 服务
│   └── scan_service/    # 扫描服务
└── test/            # 测试代码
```

## 核心功能

### 打印服务

- **设备管理**：支持 USB、网络打印机发现和管理
- **打印任务**：创建、提交、监控和取消打印任务
- **驱动支持**：集成 CUPS、IPP Everywhere 等多种打印驱动
- **打印选项**：支持页面大小、分辨率、边距等多种打印选项
- **状态监控**：实时监控打印机状态和任务进度

### 扫描服务

- **设备发现**：支持 USB、网络扫描仪发现
- **扫描控制**：设置扫描参数、启动和停止扫描
- **图像获取**：获取扫描图像数据
- **设备管理**：添加、删除和管理扫描设备
- **状态监控**：监控扫描进度和设备状态

## 技术栈

- **编程语言**：C++
- **系统框架**：OpenHarmony 系统能力
- **打印协议**：CUPS、IPP、USB
- **扫描协议**：SANE、USB、TCP/IP
- **构建系统**：GN、Ninja

## 配置说明

### 打印服务配置

- 配置文件位置：`etc/init/printservice.cfg`
- CUPS 配置：`etc/init/cupsd.conf`
- 企业模式配置：`etc/init/cups_enterprise-files.conf`

### 扫描服务配置

- 配置文件位置：`etc/init/scanservice.cfg`
- SANE 配置：`etc/init/saneservice.cfg`

## 使用指南

### 打印功能

1. **初始化打印服务**
   - 调用打印服务的初始化接口
   - 获取打印管理器实例

2. **发现打印机**
   - 调用设备发现接口
   - 监听打印机发现事件

3. **选择打印机**
   - 从发现的打印机列表中选择
   - 获取打印机能力和选项

4. **创建打印任务**
   - 设置打印参数（页面大小、分辨率等）
   - 提交打印文件

5. **监控打印任务**
   - 监听打印任务状态变化
   - 获取任务进度信息

### 扫描功能

1. **初始化扫描服务**
   - 调用扫描服务的初始化接口

2. **发现扫描仪**
   - 调用设备发现接口
   - 获取可用扫描仪列表

3. **打开扫描仪**
   - 选择目标扫描仪
   - 打开设备连接

4. **设置扫描参数**
   - 配置分辨率、格式等参数
   - 获取设备支持的选项

5. **执行扫描**
   - 启动扫描过程
   - 监控扫描进度
   - 获取扫描结果

## 开发说明

### 构建系统

项目使用 GN 和 Ninja 构建系统：

```bash
# 生成构建文件
gn gen out

# 构建项目
ninja -C out
```

### 依赖管理

- CUPS 打印系统
- SANE 扫描库
- OpenHarmony SDK

## 约束

- 如需使用打印框架完整功能，需要申请 `ohos.permission.PRINT`、`ohos.permission.MANAGE_PRINT_JOB` 权限。

## 测试

项目包含多种测试用例：
- 单元测试
- 功能测试
- 模糊测试

## 贡献指南

1. **Fork 仓库**
2. **创建特性分支**
3. **提交代码**
4. **创建 Pull Request**

## 相关仓

[cups](https://gitcode.com/openharmony/third_party_cups)

[backends](https://gitcode.com/openharmony/third_party_backends)

[applications_print_spooler](https://gitcode.com/openharmony/applications_print_spooler)

## 许可证

本项目采用 Apache License 2.0 许可证。详情请参阅 [LICENSE](LICENSE) 文件。

## 联系方式

如有问题或建议，请通过以下方式联系：
- 项目地址：https://gitcode.com/openharmony/print_print_fwk
- 邮件：[openharmony@openharmony.io](mailto:openharmony@openharmony.io)

## 贡献指南

[如何贡献](https://gitcode.com/openharmony/docs/blob/HEAD/zh-cn/contribute/参与贡献.md)

[Commit message规范](https://gitcode.com/openharmony/device_qemu/wikis/Commit%20message%E8%A7%84%E8%8C%83)
