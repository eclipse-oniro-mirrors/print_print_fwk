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

#ifndef IWATERMARK_CALLBACK_H
#define IWATERMARK_CALLBACK_H

#include "iremote_broker.h"
#include "iremote_object.h"

namespace OHOS::Print {
class IWatermarkCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Print.IWatermarkCallback");

    /**
     * @brief Callback for adding watermark to print file
     * @param jobId Print job ID
     * @param fd File descriptor of the print file
     * @note MDM application should call notifyWatermarkComplete() after processing
     */
    virtual void OnCallback(const std::string &jobId, uint32_t fd) = 0;
};

enum {
    WATERMARK_CALLBACK_ADD,
};
} // namespace OHOS::Print
#endif // IWATERMARK_CALLBACK_H
