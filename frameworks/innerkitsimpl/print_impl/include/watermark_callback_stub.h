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

#ifndef WATERMARK_CALLBACK_STUB_H
#define WATERMARK_CALLBACK_STUB_H

#include <map>
#include "iwatermark_callback.h"
#include "iremote_stub.h"

namespace OHOS::Print {
class WatermarkCallbackStub : public IRemoteStub<IWatermarkCallback> {
public:
    WatermarkCallbackStub();
    virtual ~WatermarkCallbackStub() = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override;

private:
    bool HandleAddWatermarkEvent(MessageParcel &data, MessageParcel &reply);

private:
    using WATERMARK_EVENT_HANDLER = bool (WatermarkCallbackStub::*)(MessageParcel &, MessageParcel &);
    std::map<uint32_t, WATERMARK_EVENT_HANDLER> cmdMap_;
};
}  // namespace OHOS::Print
#endif  // WATERMARK_CALLBACK_STUB_H
