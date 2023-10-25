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

#include "print_extension_callback_stub.h"

#include "print_constant.h"
#include "print_log.h"
#include "print_resolution.h"

namespace OHOS::Print {
PrintExtensionCallbackStub::PrintExtensionCallbackStub() : extCb_(nullptr), jobCb_(nullptr),
    cb_(nullptr), capability_(nullptr)
{
    cmdMap_[PRINT_EXTCB] = &PrintExtensionCallbackStub::HandleExtCallback;
    cmdMap_[PRINT_EXTCB_PRINTER] = &PrintExtensionCallbackStub::HandlePrinterCallback;
    cmdMap_[PRINT_EXTCB_PRINTJOB] = &PrintExtensionCallbackStub::HandlePrintJobCallback;
    cmdMap_[PRINT_EXTCB_PRINTCAPABILITY] = &PrintExtensionCallbackStub::HandleCapabilityCallback;
}

int32_t PrintExtensionCallbackStub::OnRemoteRequest(
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

bool PrintExtensionCallbackStub::OnCallback()
{
    if (extCb_ != nullptr) {
        return extCb_();
    }
    return false;
}

bool PrintExtensionCallbackStub::OnCallback(const std::string &printerId)
{
    if (cb_ != nullptr) {
        return cb_(printerId);
    }
    return false;
}

bool PrintExtensionCallbackStub::OnCallback(const PrintJob &job)
{
    if (jobCb_ != nullptr) {
        return jobCb_(job);
    }
    return false;
}

bool PrintExtensionCallbackStub::OnCallback(const std::string &printerId, PrinterCapability &cap)
{
    if (capability_ != nullptr) {
        if (capability_(printerId, cap)) {
            return true;
        }
    }
    return false;
}

void PrintExtensionCallbackStub::SetExtCallback(PrintExtCallback cb)
{
    extCb_ = cb;
}

void PrintExtensionCallbackStub::SetPrintJobCallback(PrintJobCallback cb)
{
    jobCb_ = cb;
}

void PrintExtensionCallbackStub::SetPrinterCallback(PrinterCallback cb)
{
    cb_ = cb;
}

void PrintExtensionCallbackStub::SetCapabilityCallback(PrinterCapabilityCallback cb)
{
    capability_ = cb;
}

bool PrintExtensionCallbackStub::HandleExtCallback(MessageParcel &data, MessageParcel &reply)
{
    bool result = OnCallback();
    PRINT_HILOGI("Handle Print Extension Callback ret[%{public}d]", result);
    reply.WriteBool(result);
    return result;
}

bool PrintExtensionCallbackStub::HandlePrinterCallback(MessageParcel &data, MessageParcel &reply)
{
    std::string printerId = data.ReadString();
    bool result = OnCallback(printerId);
    PRINT_HILOGI("Handle Printer Extension Callback ret[%{public}d]", result);
    reply.WriteBool(result);
    return result;
}

bool PrintExtensionCallbackStub::HandlePrintJobCallback(MessageParcel &data, MessageParcel &reply)
{
    auto printJobPtr = PrintJob::Unmarshalling(data);
    bool result = false;
    if (printJobPtr != nullptr) {
        result = OnCallback(*printJobPtr);
        PRINT_HILOGI("Handle Print Job Extension Callback ret[%{public}d]", result);
        reply.WriteBool(result);
    }
    return result;
}

bool PrintExtensionCallbackStub::HandleCapabilityCallback(MessageParcel &data, MessageParcel &reply)
{
    std::string printerId = data.ReadString();
    PrinterCapability cap;
    bool result = OnCallback(printerId, cap);
    PRINT_HILOGI("Handle Printer Capability Extension Callback ret[%{public}d]", result);
    reply.WriteBool(result);
    cap.Marshalling(reply);
    return result;
}
} // namespace OHOS::Print
