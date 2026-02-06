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

#ifndef MOCK_WATERMARK_CALLBACK_STUB_H
#define MOCK_WATERMARK_CALLBACK_STUB_H

#include <gmock/gmock.h>
#include "watermark_callback_stub.h"

namespace OHOS {
namespace Print {

/**
 * @brief Mock implementation of WatermarkCallbackStub for unit testing
 *
 * This mock class allows testing of:
 * - IPC message handling in WatermarkCallbackStub::OnRemoteRequest
 * - Parameter marshalling/unmarshalling
 * - Error handling in the stub layer
 */
class MockWatermarkCallbackStub final : public WatermarkCallbackStub {
public:
    MockWatermarkCallbackStub() = default;
    virtual ~MockWatermarkCallbackStub() = default;

    /**
     * @brief Mock method for OnCallback
     *
     * @param jobId The print job ID
     * @param fd The file descriptor
     */
    MOCK_METHOD2(OnCallback, void(const std::string &jobId, uint32_t fd));
};

}  // namespace Print
}  // namespace OHOS

#endif  // MOCK_WATERMARK_CALLBACK_STUB_H