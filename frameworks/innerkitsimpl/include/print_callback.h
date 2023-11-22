/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PRINT_CALLBACK_H
#define PRINT_CALLBACK_H

#include <mutex>
#include <uv.h>
#include <functional>
#include "napi/native_api.h"
#include "print_callback_stub.h"
#include "iprint_adapter.h"
#include "print_manager_client.h"

namespace OHOS::Print {
struct CallbackParam {
    napi_env env;
    napi_ref ref;
    std::mutex* mutexPtr;
    uint32_t state;
    PrinterInfo printerInfo;
    PrintJob jobInfo;

    std::string extensionId;
    std::string info;

    std::string jobId;
    PrintAttributes oldAttrs;
    PrintAttributes newAttrs;
    uint32_t fd;
};

struct Param {
    napi_env env;
    napi_ref callbackRef;
};

class PrintCallback : public PrintCallbackStub {
public:
    PrintCallback(napi_env env, napi_ref ref);
    explicit PrintCallback(PrintDocumentAdapter *adapter); // This interface is invoked by other domains.
    virtual ~PrintCallback();
    bool OnCallback() override;
    bool OnCallback(uint32_t state, const PrinterInfo &info) override;
    bool OnCallback(uint32_t state, const PrintJob &info) override;
    bool OnCallback(const std::string &extensionId, const std::string &info) override;
    bool OnCallbackAdapterLayout(const std::string &jobId, const PrintAttributes &oldAttrs,
        const PrintAttributes &newAttrs, uint32_t fd) override;
    bool onCallbackAdapterJobStateChanged(const std::string jobId, const uint32_t state,
        const uint32_t subState) override;
    bool OnCallbackAdapterGetFile(uint32_t state) override;

private:
    bool onBaseCallback(std::function<void(CallbackParam*)> paramFun, uv_after_work_cb after_work_cb);

private:
    napi_env env_ = nullptr;
    napi_ref ref_ = nullptr;
    std::mutex mutex_;
    PrintDocumentAdapter *adapter_ = nullptr;
};
}  // namespace OHOS::Print
#endif  // IPRINT_CALLBACK_H
