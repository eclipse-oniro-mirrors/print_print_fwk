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

#ifndef MOCK_REMOTE_SERVICE_H
#define MOCK_REMOTE_SERVICE_H

#include <gmock/gmock.h>
#include "iremote_stub.h"
#include "iremote_callback.h"
#include "message_parcel.h"
#include "message_option.h"

namespace OHOS::Print {

class MockRemoteService : public IRemoteStub<IRemoteCallback> {
public:
    MockRemoteService() = default;
    virtual ~MockRemoteService() = default;

    MOCK_METHOD4(OnRemoteRequest, int32_t(uint32_t code, MessageParcel &data,
                                           MessageParcel &reply, MessageOption &option));
};

} // namespace OHOS::Print

#endif // MOCK_REMOTE_SERVICE_H