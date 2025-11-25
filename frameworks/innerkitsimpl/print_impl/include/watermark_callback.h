/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef WATERMARK_CALLBACK_H
#define WATERMARK_CALLBACK_H

#include <memory>
#include <mutex>
#include <uv.h>
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "watermark_callback_stub.h"

namespace OHOS::Print {
struct WatermarkCallbackParam {
    napi_env env;
    napi_ref ref;
    std::shared_ptr<std::mutex> mutexPtr;
    std::string jobId;
    uint32_t fd;
};

class WatermarkCallback : public WatermarkCallbackStub {
public:
    WatermarkCallback(napi_env env, napi_ref ref);
    ~WatermarkCallback();
    void OnCallback(const std::string &jobId, uint32_t fd) override;

private:
    static void ExecuteCallback(WatermarkCallbackParam *param);
    napi_env env_ = nullptr;
    napi_ref ref_ = nullptr;
    std::shared_ptr<std::mutex> mutex_;
};
}  // namespace OHOS::Print
#endif  // WATERMARK_CALLBACK_H
