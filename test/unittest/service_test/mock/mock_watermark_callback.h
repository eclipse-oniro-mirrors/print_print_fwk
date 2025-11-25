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

#ifndef MOCK_WATERMARK_CALLBACK_H
#define MOCK_WATERMARK_CALLBACK_H

#include <gmock/gmock.h>
#include "iwatermark_callback.h"
#include "iremote_stub.h"

namespace OHOS {
namespace Print {

/**
 * @brief Mock implementation of IWatermarkCallback for unit testing
 *
 * This mock class is used to verify the interaction between WatermarkManager
 * and the MDM application's callback. It allows tests to:
 * - Verify that OnCallback is called with correct parameters
 * - Track the number of callback invocations
 */
class MockWatermarkCallback : public IRemoteStub<IWatermarkCallback> {
public:
    MockWatermarkCallback() = default;
    virtual ~MockWatermarkCallback() = default;

    /**
     * @brief Mock method for OnCallback
     *
     * @param jobId The print job ID
     * @param fd The file descriptor of the file to add watermark
     */
    MOCK_METHOD2(OnCallback, void(const std::string &jobId, uint32_t fd));

    /**
     * @brief Handle remote request (required by IRemoteStub)
     */
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data,
                            MessageParcel &reply, MessageOption &option) override
    {
        return 0;
    }
};

}  // namespace Print
}  // namespace OHOS

#endif  // MOCK_WATERMARK_CALLBACK_H