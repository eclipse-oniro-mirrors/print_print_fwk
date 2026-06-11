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
            bool result = (this->*requestFunc)(data, reply);
            return result ? E_PRINT_NONE : E_PRINT_SERVER_FAILURE;
        }
    }
    PRINT_HILOGW("default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool PrintExtensionCallbackStub::OnCallback()
{
    PrintExtCallback localCb = nullptr;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        localCb = extCb_;
    }
    if (localCb != nullptr) {
        return localCb();
    }
    return false;
}

bool PrintExtensionCallbackStub::OnCallback(const std::string &printerId)
{
    PrinterCallback localCb = nullptr;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        localCb = cb_;
    }
    if (localCb != nullptr) {
        return localCb(printerId);
    }
    return false;
}

bool PrintExtensionCallbackStub::OnCallback(const PrintJob &job)
{
    PrintJobCallback localCb = nullptr;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        localCb = jobCb_;
    }
    if (localCb != nullptr) {
        return localCb(job);
    }
    return false;
}

bool PrintExtensionCallbackStub::OnCallback(const std::string &printerId, PrinterCapability &cap)
{
    PrinterCapabilityCallback localCb = nullptr;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        localCb = capability_;
    }
    if (localCb != nullptr) {
        if (localCb(printerId, cap)) {
            return true;
        }
    }
    return false;
}

void PrintExtensionCallbackStub::SetExtCallback(PrintExtCallback cb)
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    extCb_ = cb;
}

void PrintExtensionCallbackStub::SetPrintJobCallback(PrintJobCallback cb)
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    jobCb_ = cb;
}

void PrintExtensionCallbackStub::SetPrinterCallback(PrinterCallback cb)
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    cb_ = cb;
}

void PrintExtensionCallbackStub::SetCapabilityCallback(PrinterCapabilityCallback cb)
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    capability_ = cb;
}

bool PrintExtensionCallbackStub::HandleExtCallback(MessageParcel &data, MessageParcel &reply)
{
    bool result = OnCallback();
    PRINT_HILOGI("Handle Print Extension Callback ret[%{public}d]", result);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteBool(result), false);
    return result;
}

bool PrintExtensionCallbackStub::HandlePrinterCallback(MessageParcel &data, MessageParcel &reply)
{
    std::string printerId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerId), false);
    bool result = OnCallback(printerId);
    PRINT_HILOGI("Handle Printer Extension Callback ret[%{public}d]", result);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteBool(result), false);
    return result;
}

bool PrintExtensionCallbackStub::HandlePrintJobCallback(MessageParcel &data, MessageParcel &reply)
{
    auto printJobPtr = PrintJob::Unmarshalling(data);
    bool result = false;
    if (printJobPtr != nullptr) {
        result = OnCallback(*printJobPtr);
        PRINT_HILOGI("Handle Print Job Extension Callback ret[%{public}d]", result);
        CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteBool(result), false);
    }
    return result;
}

bool PrintExtensionCallbackStub::HandleCapabilityCallback(MessageParcel &data, MessageParcel &reply)
{
    std::string printerId;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadString(printerId), false);
    PrinterCapability cap;
    bool result = OnCallback(printerId, cap);
    PRINT_HILOGI("Handle Printer Capability Extension Callback ret[%{public}d]", result);
    CHECK_PARCEL_OP_AND_RETURN_VAL(reply.WriteBool(result), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(cap.Marshalling(reply), false);
    return result;
}
} // namespace OHOS::Print
