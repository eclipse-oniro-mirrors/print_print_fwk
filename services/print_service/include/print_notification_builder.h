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

#ifndef PRINT_NOTIFICATION_BUILDER_H
#define PRINT_NOTIFICATION_BUILDER_H

#include <string>
#include "udmf.h"
#include "uds.h"
#include "udmf_capi_common.h"
#include "notification_request.h"

namespace OHOS::Print {

class UdmfDataGuard {
public:
    UdmfDataGuard();
    ~UdmfDataGuard();

    bool CreatePlainText(const std::string& content);
    std::string Serialize();

private:
    OH_UdmfData* udmfUnifiedData_{nullptr};
    OH_UdmfRecord* record_{nullptr};
    OH_UdsPlainText* plainText_{nullptr};
    OH_UdmfOptions* option_{nullptr};
};

class PrintNotificationBuilder {
public:
    static int32_t CreateNotification(uint32_t subState, const std::string& printerName);

private:
    PrintNotificationBuilder() = delete;
    ~PrintNotificationBuilder() = delete;
    PrintNotificationBuilder(const PrintNotificationBuilder&) = delete;
    PrintNotificationBuilder& operator=(const PrintNotificationBuilder&) = delete;

    static std::shared_ptr<Notification::NotificationActionButton> CreateAiButton(
        int32_t notiId, const std::string& askAiKey);
    static Notification::NotificationRequest BuildRequest(int32_t notiId,
        std::shared_ptr<Notification::NotificationContent>& content);
    static std::string SubStateToResourceKey(uint32_t subState);
};

} // namespace OHOS::Print

#endif // PRINT_NOTIFICATION_BUILDER_H
