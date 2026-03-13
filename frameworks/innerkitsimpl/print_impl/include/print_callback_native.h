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

#ifndef PRINT_CALLBACK_NATIVE_H
#define PRINT_CALLBACK_NATIVE_H

#include "print_callback_stub.h"
#include "iprint_adapter.h"
#include "iprint_kia_interceptor.h"

namespace OHOS::Print {
class PrintCallbackNative : public PrintCallbackStub {
public:
    explicit PrintCallbackNative(PrintKiaInterceptor *kiaInterceptor);
    ~PrintCallbackNative();

    bool OnCallback() override;
    bool OnCallback(uint32_t state, const PrinterInfo &info) override;
    bool OnCallback(uint32_t state, const PrintJob &info) override;
    bool OnCallback(const std::string &extensionId, const std::string &info) override;
    bool OnCallback(const PrinterInfo &info, const std::vector<PpdInfo> &ppds) override;
    bool OnCallbackAdapterLayout(const std::string &jobId, const PrintAttributes &oldAttrs,
        const PrintAttributes &newAttrs, uint32_t fd) override;
    bool OnCallbackAdapterJobStateChanged(const std::string jobId, const uint32_t state,
        const uint32_t subState) override;
    bool OnCallbackAdapterGetFile(uint32_t state) override;
    bool OnCheckPrintEventsNeedReject(int32_t pid);

private:
    PrintKiaInterceptor *kiaInterceptor_ = nullptr;
};
} // namespace OHOS::Print
#endif // PRINT_CALLBACK_NATIVE_H