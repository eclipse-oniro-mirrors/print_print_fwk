// Copyright (c) 2026 Huawei Device Co., Ltd.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRINT_FWK_AGENT_CLIENT_API_H
#define PRINT_FWK_AGENT_CLIENT_API_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 当前开发阶段允许不兼容地调整错误码；发布后只能在枚举尾部追加。
 * print_fwk 在边界处将错误码映射为 E_PRINT_*。
 */
typedef enum {
    PRINT_FWK_AGENT_CLIENT_OK = 0,
    PRINT_FWK_AGENT_CLIENT_ERR_PARAM = 1,
    PRINT_FWK_AGENT_CLIENT_ERR_SERVER = 2,
    PRINT_FWK_AGENT_CLIENT_ERR_PRINTER_EXISTS = 3,
    PRINT_FWK_AGENT_CLIENT_ERR_NOT_FOUND = 4,
    PRINT_FWK_AGENT_CLIENT_ERR_RPC = 5,
    PRINT_FWK_AGENT_CLIENT_ERR_UNIMPLEMENTED = 6,
    PRINT_FWK_AGENT_CLIENT_ERR_BACKEND_CONFIG = 7,
    PRINT_FWK_AGENT_CLIENT_ERR_NO_PACKAGE_MGR = 8,
    PRINT_FWK_AGENT_CLIENT_ERR_INSTALL_FAILED = 9,
    PRINT_FWK_AGENT_CLIENT_ERR_INSTALL_BUSY = 10,
    PRINT_FWK_AGENT_CLIENT_ERR_TIMEOUT = 11,
} PrintFwkAgentClientError;

/* 不透明客户端句柄，其内存与生命周期由 .so 管理。 */
typedef struct PrintFwkAgentClient PrintFwkAgentClient;

typedef enum {
    PRINT_FWK_AGENT_PPD_UNSPECIFIED = 0,
    PRINT_FWK_AGENT_PPD_MATCHED = 1,
    PRINT_FWK_AGENT_PPD_FALLBACK = 2,
} PrintFwkAgentPpdSource;

typedef struct {
    const char *uri;            /* 必填 */
    const char *name;           /* 必填 */
    /*
     * 可选 JSON：
     * {
     *   "makeAndModel": "...",
     *   "candidates": [
     *     {"packageManager": "...", "packageName": "..."}
     *   ]
     * }
     * 上层只透传该字段，允许为 NULL。
     * candidates 仅描述候选包，不承诺具体包管理器选择或安装策略。
     */
    const char *driverInstall;
    const char *backendType;    /* 必填 */
} PrintAddPrinterParam;

/*
 * ippUri、ppdName 及本结构仅在 PrintAgentAddDoneCb 调用期间有效。
 * 调用方必须在回调内复制所需内容，不得保存或释放这些指针。
 */
typedef struct {
    const char *ippUri;
    const char *ppdName;
    int32_t ppdSource;
} PrintAddPrinterResult;

enum {
    PRINT_AGENT_PROGRESS_ENV_INIT = 0,
    PRINT_AGENT_PROGRESS_ADDING_PRINTER = 1,
    PRINT_AGENT_PROGRESS_INSTALLING_DRIVER = 2,
    PRINT_AGENT_PROGRESS_RETRYING_ADD = 3,
    PRINT_AGENT_PROGRESS_DONE = 4,
};

/*
 * addPrinter/removePrinter 异步契约：
 * - 函数返回前深拷贝所有输入字符串，调用方可在函数返回后释放输入。
 * - 同步返回非 PRINT_FWK_AGENT_CLIENT_OK 时，不触发任何回调。
 * - doneCb 必须非 NULL，progressCb 可为 NULL。
 * - 返回 PRINT_FWK_AGENT_CLIENT_OK 表示任务已受理，doneCb 恰好调用一次。
 * - userData 必须保持有效直到 doneCb 返回。doneCb 返回后，库不再访问
 *   userData 或本次调用的 PrintAddPrinterResult。
 */
typedef void (*PrintAgentAddDoneCb)(int32_t errCode, const PrintAddPrinterResult *result, void *userData);
typedef void (*PrintAgentRemoveDoneCb)(int32_t errCode, void *userData);
typedef void (*PrintAgentProgressCb)(int32_t progress, void *userData);

/*
 * Handle concurrency contract:
 * - destroy must be called exactly once for each non-NULL handle.
 * - destroy must not run concurrently with addPrinter, removePrinter, or
 *   another destroy for the same handle. The caller must provide external
 *   serialization for these calls.
 * - destroy must not be called from a callback for the same handle.
 * - destroy may invoke queued-task cancellation callbacks and wait for an
 *   active task's callback. After destroy returns, no callback for that handle
 *   will be invoked.
 */
/* 函数指针表（vtable）；abiVersion 供调用方拒绝不匹配的 .so。 */
typedef struct {
    uint32_t abiVersion; /* 当前为 1 */

    PrintFwkAgentClient *(*create)(void);
    void (*destroy)(PrintFwkAgentClient *self);

    int32_t (*addPrinter)(PrintFwkAgentClient *self, const PrintAddPrinterParam *param,
        PrintAgentAddDoneCb doneCb, PrintAgentProgressCb progressCb, void *userData);
    int32_t (*removePrinter)(PrintFwkAgentClient *self, const char *name, const char *backendType,
        PrintAgentRemoveDoneCb doneCb, void *userData);
} PrintFwkAgentClientApi;

/* 唯一导出符号，返回指向静态常量 vtable 的指针。 */
const PrintFwkAgentClientApi *GetPrintFwkAgentClientApi(void);

#ifdef __cplusplus
}
#endif

#endif /* PRINT_FWK_AGENT_CLIENT_API_H */
