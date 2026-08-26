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

#include "watermark_callback_stub.h"
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
WatermarkCallbackStub::WatermarkCallbackStub()
{
    cmdMap_[WATERMARK_CALLBACK_ADD] = &WatermarkCallbackStub::HandleAddWatermarkEvent;
}

int32_t WatermarkCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    PRINT_HILOGD("WatermarkCallbackStub::OnRemoteRequest started, code = %{public}d", code);
    auto descriptorToken = data.ReadInterfaceToken();
    if (descriptorToken != GetDescriptor()) {
        PRINT_HILOGE("Remote descriptor not the same as local descriptor.");
        return E_PRINT_RPC_FAILURE;
    }

    auto itFunc = cmdMap_.find(code);
    if (itFunc != cmdMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            bool result = (this->*requestFunc)(data, reply);
            return result ? E_PRINT_NONE : E_PRINT_SERVER_FAILURE;
        }
    }
    PRINT_HILOGW("WatermarkCallbackStub default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool WatermarkCallbackStub::HandleAddWatermarkEvent(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("WatermarkCallbackStub HandleAddWatermarkEvent start");
    std::string jobId = data.ReadString();
    int32_t fd = data.ReadFileDescriptor();
    if (fd < 0) {
        PRINT_HILOGE("Invalid file descriptor");
        return false;
    }
    PRINT_HILOGI("WatermarkCallbackStub jobId:%{public}s, fd:%{public}d",
        jobId.c_str(), fd);
    OnCallback(jobId, static_cast<uint32_t>(fd));
    PRINT_HILOGI("WatermarkCallbackStub HandleAddWatermarkEvent end");
    return true;
}
} // namespace OHOS::Print
