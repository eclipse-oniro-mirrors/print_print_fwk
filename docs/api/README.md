# 打印扫描 API 文档

本目录维护 [OpenHarmony 官方 docs 仓库](https://gitcode.com/openharmony/docs)的中文打印扫描 API 文档副本，供项目开发和接口审查使用。

## 阅读入口

- [全部 API 文档及来源提交](SOURCE.md)：ArkTS 公开/系统接口、打印扩展、C API 类型与函数、错误码。
- [打印 ArkTS API](print/js-apis-print.md)
- [打印系统 API](print/js-apis-print-sys.md)
- [扫描 ArkTS API](scan/js-apis-scan.md)
- [扫描系统 API](scan/js-apis-scan-sys.md)
- [打印 C API](print/capi-ohprint-h.md)
- [扫描 C API](scan/capi-ohscan-h.md)

默认来源为 `master` 开发分支。具体接口是否可用，以文档的 API version、系统接口标记和目标产品 SDK 为准；文档提交与业务源码提交独立，不代表实现已与最新文档一致。

## 更新副本

1. 在 OpenHarmony 官方 docs 仓库选定一个提交，核对该版本的打印、扫描接口和通用错误码清单。逐篇原文路径见 [SOURCE.md](SOURCE.md)。
2. 按现有分类更新正文。已收录文档互相引用时使用相对路径，并保留章节锚点。指向范围外文档或图片的链接使用同一上游提交的地址。
3. 在同一次提交中更新索引里的来源提交、原文链接和篇数，核对上游许可证与署名，并检查新增、移动和删除文档涉及的链接。API 技术内容的勘误应先反馈给上游。
