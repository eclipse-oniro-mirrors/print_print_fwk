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

#include "print_extcb_stub.h"

#include "print_common.h"
#include "print_log.h"

namespace OHOS::Print {
PrintExtcbStub::PrintExtcbStub() : extCb_(nullptr), jobCb_(nullptr), cb_(nullptr)
{
    cmdMap_[PRINT_EXTCB] = &PrintExtcbStub::HandleExtCallback;
    cmdMap_[PRINT_EXTCB_PRINTER] = &PrintExtcbStub::HandlePrinterCallback;
    cmdMap_[PRINT_EXTCB_PRINTJOB] = &PrintExtcbStub::HandlePrintJobCallback;
}

int32_t PrintExtcbStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    PRINT_HILOGD("OnRemoteRequest started, code = %{public}d", code);
    auto descriptorToken = data.ReadInterfaceToken();
    if (descriptorToken != GetDescriptor()) {
        PRINT_HILOGE("Remote descriptor not the same as local descriptor.");
        return E_PRINT_IPC_ERROR;
    }

    auto itFunc = cmdMap_.find(code);
    if (itFunc != cmdMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            return (this->*requestFunc)(data);
        }
    }
    PRINT_HILOGW("default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool PrintExtcbStub::OnCallback()
{
    if (extCb_ != nullptr) {
        return extCb_();
    }
    return false;
}

bool PrintExtcbStub::OnCallback(uint32_t printerId)
{
    if (cb_ != nullptr) {
        return cb_(printerId);
    }
    return false;
}

bool PrintExtcbStub::OnCallback(const PrintJob &job)
{
    if (jobCb_ != nullptr) {
        return jobCb_(job);
    }
    return false;
}

void PrintExtcbStub::SetExtCallback(PrintExtCallback cb)
{
    extCb_ = cb;
}

void PrintExtcbStub::SetPrintJobCallback(PrintJobCallback cb)
{
    jobCb_ = cb;
}

void PrintExtcbStub::SetPrinterCallback(PrinterCallback cb)
{
    cb_ = cb;
}

bool PrintExtcbStub::HandleExtCallback(MessageParcel &data)
{
    return OnCallback();
}

bool PrintExtcbStub::HandlePrinterCallback(MessageParcel &data)
{
    uint32_t printerId = data.ReadUint32();
    return OnCallback(printerId);
}

bool PrintExtcbStub::HandlePrintJobCallback(MessageParcel &data)
{
    PrintJob job; // = data.readuint32();
    return OnCallback(job);
}
} // namespace OHOS::Print
