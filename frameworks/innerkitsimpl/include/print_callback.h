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

#include "napi/native_api.h"
#include "print_callback_stub.h"
#include <mutex>

namespace OHOS::Print {
class PrintCallback : public PrintCallbackStub {
public:
    PrintCallback(napi_env env, napi_ref ref);
    virtual ~PrintCallback();
    bool OnCallback() override;
    bool OnCallback(uint32_t state, const PrinterInfo &info) override;
    bool OnCallback(uint32_t state, const PrintJob &info) override;
    bool OnCallback(const std::string &extensionId, const std::string &info) override;

private:
    napi_env env_;
    napi_ref ref_;
    std::mutex mutex_;
};
} // namespace OHOS::Print
#endif // IPRINT_CALLBACK_H