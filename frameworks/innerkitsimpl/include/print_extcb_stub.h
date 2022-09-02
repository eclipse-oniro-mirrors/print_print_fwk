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

#ifndef PRINT_EXTCB_STUB_H
#define PRINT_EXTCB_STUB_H

#include <memory>
#include "iremote_stub.h"
#include "print_extcb_interface.h"
#include "print_job.h"

namespace OHOS::Print {

using PrintExtCallback = bool(*)();
using PrintJobCallback = bool(*)(const PrintJob&);
using PrinterCallback = bool(*)(uint32_t);

class PrintExtcbStub : public IRemoteStub<PrintExtcbInterface> {
public:
    explicit PrintExtcbStub();
    virtual ~PrintExtcbStub() = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    bool OnCallback() override;
    bool OnCallback(uint32_t printerId) override;
    bool OnCallback(const PrintJob &job) override;

    void SetExtCallback(PrintExtCallback cb);
    void SetPrintJobCallback(PrintJobCallback cb);
    void SetPrinterCallback(PrinterCallback cb);

private:
    bool HandleExtCallback(MessageParcel &data);
    bool HandlePrinterCallback(MessageParcel &data);     
    bool HandlePrintJobCallback(MessageParcel &data);

private:
    using PRINT_EXT_HANDLER = bool(PrintExtcbStub::*)(MessageParcel&);
    PrintExtCallback extCb_;
    PrintJobCallback jobCb_;
    PrinterCallback cb_;
    std::map<uint32_t, PRINT_EXT_HANDLER> cmdMap_;
};
} // namespace OHOS::Print
#endif // PRINT_EXTCB_STUB_H
