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
#ifndef MOCK_PRINT_CALLBACK_STUB_H
#define MOCK_PRINT_CALLBACK_STUB_H

#include <gmock/gmock.h>
#include "print_callback_stub.h"

namespace OHOS {
namespace Print {
class DummyPrintCallbackStub : public PrintCallbackStub {
public:
    bool OnCallback() override
    {
        return true;
    }
    bool OnCallback(uint32_t state, const PrinterInfo &info) override
    {
        return true;
    }
    bool OnCallback(uint32_t state, const PrintJob &info) override
    {
        return true;
    }
    bool OnCallback(const std::string &extensionId, const std::string &info) override
    {
        return true;
    }
    bool OnCallbackAdapterLayout(const std::string &jobId, const PrintAttributes &oldAttrs,
        const PrintAttributes &newAttrs, uint32_t fd) override
    {
        return true;
    }
    bool onCallbackAdapterJobStateChanged(const std::string jobId, const uint32_t state,
        const uint32_t subState) override
    {
        return true;
    }
    bool OnCallbackAdapterGetFile(uint32_t state) override
    {
        return true;
    }
};

class MockPrintCallbackStub final : public DummyPrintCallbackStub {
public:
    MOCK_METHOD0(OnCallback, bool());
    MOCK_METHOD2(OnCallback, bool(uint32_t, const PrinterInfo&));
    MOCK_METHOD2(OnCallback, bool(uint32_t, const PrintJob&));
    MOCK_METHOD2(OnCallback, bool(const std::string&, const std::string&));
};
}  // namespace Print
}  // namespace OHOS
#endif  // MOCK_PRINT_CALLBACK_STUB_H
