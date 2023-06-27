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

#ifndef PRINT_EXTENSION_CALLBACK_STUB_H
#define PRINT_EXTENSION_CALLBACK_STUB_H

#include <memory>

#include "iprint_extension_callback.h"
#include "iremote_stub.h"
#include "print_job.h"
#include "printer_capability.h"

namespace OHOS::Print {
using PrintExtCallback = bool (*)();
using PrintJobCallback = bool (*)(const PrintJob&);
using PrinterCallback = bool (*)(const std::string&);
using PrinterCapabilityCallback = bool (*)(const std::string&, PrinterCapability&);

class PrintExtensionCallbackStub : public IRemoteStub<IPrintExtensionCallback> {
public:
    explicit PrintExtensionCallbackStub();
    virtual ~PrintExtensionCallbackStub() = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    bool OnCallback() override;
    bool OnCallback(const std::string &printerId) override;
    bool OnCallback(const PrintJob &job) override;
    bool OnCallback(const std::string &printerId, PrinterCapability &cap) override;

    void SetExtCallback(PrintExtCallback cb);
    void SetPrintJobCallback(PrintJobCallback cb);
    void SetPrinterCallback(PrinterCallback cb);
    void SetCapabilityCallback(PrinterCapabilityCallback cb);

private:
    bool HandleExtCallback(MessageParcel &data, MessageParcel &reply);
    bool HandlePrinterCallback(MessageParcel &data, MessageParcel &reply);
    bool HandlePrintJobCallback(MessageParcel &data, MessageParcel &reply);
    bool HandleCapabilityCallback(MessageParcel &data, MessageParcel &reply);
    void dataReadJob(MessageParcel &data, PrintJob &job);

private:
    using PRINT_EXT_HANDLER = bool (PrintExtensionCallbackStub::*)(MessageParcel &, MessageParcel &);
    PrintExtCallback extCb_;
    PrintJobCallback jobCb_;
    PrinterCallback cb_;
    PrinterCapabilityCallback capability_;
    std::map<uint32_t, PRINT_EXT_HANDLER> cmdMap_;
};
}  // namespace OHOS::Print
#endif  // PRINT_EXTCB_STUB_H
