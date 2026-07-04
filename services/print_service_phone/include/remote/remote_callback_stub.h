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

#ifndef REMOTE_CALLBACK_STUB_H
#define REMOTE_CALLBACK_STUB_H

#include <map>
#include <string>
#include "iremote_callback.h"
#include "iremote_stub.h"
#include "json/json.h"

namespace OHOS::Print {

class RemoteCallbackStub : public IRemoteStub<IRemoteCallback> {
public:
    RemoteCallbackStub();
    virtual ~RemoteCallbackStub() = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    bool HandleGetPrinterStatus(const std::string &msg);
    bool HandleGetPrinterList(const std::string &msg);

private:
    using REMOTE_CALLBACK_HANDLER = bool (RemoteCallbackStub::*)(const std::string &);
    std::map<uint32_t, REMOTE_CALLBACK_HANDLER> cmdMap_;
};

} // namespace OHOS::Print

#endif // REMOTE_CALLBACK_STUB_H