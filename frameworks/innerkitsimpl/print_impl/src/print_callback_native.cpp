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

#include "print_callback_native.h"
#include "print_log.h"
#include "print_constant.h"
#include "print_manager_client.h"

namespace OHOS::Print {
PrintCallbackNative::PrintCallbackNative(PrintKiaInterceptor *kiaInterceptor) : kiaInterceptor_(kiaInterceptor)
{
}

PrintCallbackNative::~PrintCallbackNative()
{
    if (kiaInterceptor_ != nullptr) {
        delete kiaInterceptor_;
        kiaInterceptor_ = nullptr;
    }
}

bool PrintCallbackNative::OnCallback()
{
    return false;
}

bool PrintCallbackNative::OnCallback(uint32_t state, const PrinterInfo &info)
{
    return false;
}

bool PrintCallbackNative::OnCallback(uint32_t state, const PrintJob &info)
{
    return false;
}

bool PrintCallbackNative::OnCallback(const std::string &extensionId, const std::string &info)
{
    return false;
}

bool PrintCallbackNative::OnCallback(const PrinterInfo &info, const std::vector<PpdInfo> &ppds)
{
    return false;
}

bool PrintCallbackNative::OnCallbackAdapterLayout(
    const std::string &jobId, const PrintAttributes &oldAttrs, const PrintAttributes &newAttrs, uint32_t fd)
{
    return false;
}

bool PrintCallbackNative::OnCallbackAdapterJobStateChanged(
    const std::string jobId, const uint32_t state, const uint32_t subState)
{
    return false;
}

bool PrintCallbackNative::OnCallbackAdapterGetFile(uint32_t state)
{
    return false;
}

bool PrintCallbackNative::OnCheckPrintEventsNeedReject(int32_t pid)
{
    PRINT_HILOGI("OnCheckPrintEventsNeedReject in");
    if (kiaInterceptor_ == nullptr) {
        PRINT_HILOGI("kiaInterceptor_ is nullptr");
        return false;
    }
    bool ret = kiaInterceptor_->OnCheckPrintEventsNeedReject(pid);
    PRINT_HILOGD("PrintCallback::OnCheckPrintEventsNeedReject End, ret = %{public}d", ret);
    return ret;
}
} // namespace OHOS::Print