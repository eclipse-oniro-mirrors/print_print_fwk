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

#include "print_callback_stub.h"

#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
PrintCallbackStub::PrintCallbackStub()
{
    cmdMap_[PRINT_CALLBACK_TASK] = &PrintCallbackStub::HandlePrintTaskEvent;
    cmdMap_[PRINT_CALLBACK_PRINTER] = &PrintCallbackStub::HandlePrinterEvent;
    cmdMap_[PRINT_CALLBACK_PRINT_JOB] = &PrintCallbackStub::HandlePrintJobEvent;
    cmdMap_[PRINT_CALLBACK_EXTINFO] = &PrintCallbackStub::HandleExtEvent;
    cmdMap_[PRINT_CALLBACK_PRINT_JOB_ADAPTER] = &PrintCallbackStub::HandlePrintAdapterJobEvent;
    cmdMap_[PRINT_CALLBACK_PRINT_JOB_CHANGED_ADAPTER] = &PrintCallbackStub::HandlePrintAdapterJobChangedEvent;
    cmdMap_[PRINT_CALLBACK_PRINT_GET_FILE_ADAPTER] = &PrintCallbackStub::HandlePrintAdapterGetFileEvent;
}

int32_t PrintCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    PRINT_HILOGD("OnRemoteRequest started, code = %{public}d", code);
    auto descriptorToken = data.ReadInterfaceToken();
    if (descriptorToken != GetDescriptor()) {
        PRINT_HILOGE("Remote descriptor not the same as local descriptor.");
        return E_PRINT_RPC_FAILURE;
    }

    auto itFunc = cmdMap_.find(code);
    if (itFunc != cmdMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            return (this->*requestFunc)(data, reply);
        }
    }
    PRINT_HILOGW("default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool PrintCallbackStub::HandlePrintTaskEvent(MessageParcel &data, MessageParcel &reply)
{
    bool result = OnCallback();
    reply.WriteBool(result);
    return true;
}

bool PrintCallbackStub::HandlePrinterEvent(MessageParcel &data, MessageParcel &reply)
{
    uint32_t state = data.ReadUint32();
    auto info = PrinterInfo::Unmarshalling(data);
    bool result = false;
    if (info != nullptr) {
        result = OnCallback(state, *info);
        reply.WriteBool(result);
    }
    return result;
}

bool PrintCallbackStub::HandlePrintJobEvent(MessageParcel &data, MessageParcel &reply)
{
    uint32_t state = data.ReadUint32();
    auto info = PrintJob::Unmarshalling(data);
    bool result = false;
    if (info != nullptr) {
        result = OnCallback(state, *info);
        reply.WriteBool(result);
    }
    return result;
}

bool PrintCallbackStub::HandleExtEvent(MessageParcel &data, MessageParcel &reply)
{
    std::string extensionId = data.ReadString();
    std::string info = data.ReadString();
    bool result = OnCallback(extensionId, info);
    reply.WriteBool(result);
    return true;
}

bool PrintCallbackStub::HandlePrintAdapterJobEvent(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintCallbackStub HandlePrintAdapterJobEvent start");
    std::string jobId = data.ReadString();
    auto oldAttrs = PrintAttributes::Unmarshalling(data);
    auto newAttrs = PrintAttributes::Unmarshalling(data);
    if (newAttrs == nullptr) {
        PRINT_HILOGE("invalid print attributes object");
        return false;
    }
    uint32_t fd = static_cast<uint32_t>(data.ReadFileDescriptor());

    PRINT_HILOGI("PrintCallbackStub HandlePrintAdapterJobEvent jobId:%{public}s, fd:%{public}d", jobId.c_str(), fd);
    bool result = OnCallbackAdapterLayout(jobId, *oldAttrs, *newAttrs, fd);
    reply.WriteBool(result);
    PRINT_HILOGI("PrintCallbackStub HandlePrintAdapterJobEvent end");
    return true;
}

bool PrintCallbackStub::HandlePrintAdapterJobChangedEvent(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintCallbackStub HandlePrintAdapterJobChangedEvent start");
    std::string jobId = data.ReadString();
    uint32_t state = data.ReadUint32();
    uint32_t subState = data.ReadUint32();

    PRINT_HILOGI("PrintCallbackStub HandlePrintAdapterJobChangedEvent jobId:%{public}s, subState:%{public}d",
        jobId.c_str(), subState);
    bool result = onCallbackAdapterJobStateChanged(jobId, state, subState);
    reply.WriteBool(result);
    PRINT_HILOGI("PrintCallbackStub HandlePrintAdapterJobChangedEvent end");
    return true;
}

bool PrintCallbackStub::HandlePrintAdapterGetFileEvent(MessageParcel &data, MessageParcel &reply)
{
    PRINT_HILOGI("PrintCallbackStub HandlePrintAdapterGetFileEvent start");
    uint32_t state = data.ReadUint32();

    PRINT_HILOGI("PrintCallbackStub HandlePrintAdapterGetFileEvent state:%{public}d",
        state);
    bool result = OnCallbackAdapterGetFile(state);
    reply.WriteBool(result);
    PRINT_HILOGI("PrintCallbackStub HandlePrintAdapterGetFileEvent end");
    return true;
}
} // namespace OHOS::Print
