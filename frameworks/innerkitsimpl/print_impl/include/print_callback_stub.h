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

#ifndef PRINT_CALLBACK_STUB_H
#define PRINT_CALLBACK_STUB_H

#include <map>
#include "iprint_callback.h"
#include "iremote_stub.h"

namespace OHOS::Print {
class PrintCallbackStub : public IRemoteStub<IPrintCallback> {
public:
    PrintCallbackStub();
    virtual ~PrintCallbackStub() = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    bool HandlePrintTaskEvent(MessageParcel &data, MessageParcel &reply);
    bool HandlePrinterEvent(MessageParcel &data, MessageParcel &reply);
    bool HandlePrintJobEvent(MessageParcel &data, MessageParcel &reply);
    bool HandleExtEvent(MessageParcel &data, MessageParcel &reply);
    bool HandlePrintAdapterJobEvent(MessageParcel &data, MessageParcel &reply);
    bool HandlePrintAdapterJobChangedEvent(MessageParcel &data, MessageParcel &reply);
    bool HandlePrintAdapterGetFileEvent(MessageParcel &data, MessageParcel &reply);

private:
    using PRINT_EVENT_HANDLER = bool (PrintCallbackStub::*)(MessageParcel &, MessageParcel &);
    std::map<uint32_t, PRINT_EVENT_HANDLER> cmdMap_;
};
}  // namespace OHOS::Print
#endif  // PRINT_CALLBACK_STUB_H
