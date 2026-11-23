# 打印扫描框架研发文档

首次阅读可从[架构总览](architecture/overview.md)了解应用如何经框架调用打印、扫描服务，再按手头的问题进入对应主题。

| 要解决的问题 | 阅读入口 |
| --- | --- |
| 打印机、队列、打印任务和扫描页分别由谁标识和持有？ | [领域对象与术语](domain/overview.md) |
| 标准版与 phone 如何选择？CUPS、过滤器、SANE 与框架的职责在哪里交接？ | [产品差异与跨仓契约](architecture/variants-and-boundaries.md) |
| 从提交到出纸经过哪些阶段？取消请求返回后如何判断任务已结束？ | [打印任务](workflows/print-job.md) · [取消控制与终态](workflows/print-job.md#四取消控制与终态) |
| 设备由谁打开？扫描页何时可领取，关闭或退出时如何清理？ | [扫描会话、执行与结果](workflows/scan.md) |
| 如何定位本地源码和依赖，选择部件、服务或测试目标？ | [仓库定位](development/repository-context.md) · [编译命令](development/build.md) |
| 某个 ArkTS 或 C 接口需要什么权限，适用于哪个 SDK？ | [打印扫描 API](api/README.md) · [官方文档版本与清单](api/SOURCE.md) |

代码修改影响产品条件、任务状态或资源归属时，在同一变更中更新对应章节。团队研发约定见仓库根目录的 [AGENTS.md](../AGENTS.md)。
