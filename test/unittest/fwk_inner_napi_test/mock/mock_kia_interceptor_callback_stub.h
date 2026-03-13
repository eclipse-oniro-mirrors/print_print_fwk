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

#ifndef MOCK_KIA_INTERCEPTOR_CALLBACK_STUB_H
#define MOCK_KIA_INTERCEPTOR_CALLBACK_STUB_H

#include <gmock/gmock.h>
#include "kia_interceptor_callback_stub.h"

namespace OHOS {
namespace Print {
class MockKiaInterceptorCallbackStub final : public KiaInterceptorCallbackStub {
public:
    MockKiaInterceptorCallbackStub() = default;
    virtual ~MockKiaInterceptorCallbackStub() = default;

    MOCK_METHOD2(OnCheckPrintJobNeedReject, bool(const int32_t &pid, const std::string &callerAppId));
};

}  // namespace Print
}  // namespace OHOS

#endif  // MOCK_KIA_INTERCEPTOR_CALLBACK_STUB_H