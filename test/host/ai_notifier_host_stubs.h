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

#ifndef AI_NOTIFIER_HOST_STUBS_H
#define AI_NOTIFIER_HOST_STUBS_H

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include "print_constant.h"

struct OH_UdmfData {};
struct OH_UdmfRecord {};
struct OH_UdsPlainText {};
struct OH_UdmfOptions {};

namespace HostTest {
inline int32_t foregroundUser = 100;
inline bool accountQueryFails = false;
inline bool switchDuringButton = false;
inline bool switchAtPublish = false;
inline bool publishFails = false;
inline int32_t buttonUser = -1;
inline std::vector<int32_t> receivers;
inline std::map<uint32_t, int> faults;
}

namespace OHOS {
constexpr int ERR_OK = 0;
namespace AccountSA {
struct OsAccountManager {
    static int GetForegroundOsAccountLocalId(int32_t &userId)
    {
        userId = HostTest::foregroundUser;
        return HostTest::accountQueryFails ? -1 : ERR_OK;
    }
};
}
namespace AAFwk {
struct Want {
    static constexpr uint32_t FLAG_AUTH_READ_URI_PERMISSION = 1;
    static constexpr uint32_t FLAG_AUTH_WRITE_URI_PERMISSION = 2;
    void SetElementName(const std::string &, const std::string &) {}
    template<class T> void SetParam(const std::string &, T) {}
    void SetFlags(uint32_t) {}
};
}
namespace AbilityRuntime::WantAgent {
struct WantAgent {};
struct WantAgentConstant {
    enum class Flags { UPDATE_PRESENT_FLAG };
    enum class OperationType { START_ABILITY };
};
struct WantAgentInfo {
    WantAgentInfo(int, WantAgentConstant::OperationType, const std::vector<WantAgentConstant::Flags> &,
        const std::vector<std::shared_ptr<AAFwk::Want>> &, std::nullptr_t) {}
};
struct WantAgentHelper {
    static std::shared_ptr<WantAgent> GetWantAgent(const WantAgentInfo &, int32_t userId = -1)
    {
        HostTest::buttonUser = userId;
        if (HostTest::switchDuringButton) {
            HostTest::foregroundUser = 101;
        }
        return std::make_shared<WantAgent>();
    }
};
}
namespace Notification {
struct NotificationNormalContent {
    void SetText(const std::string &) {}
    void SetTitle(const std::string &) {}
};
struct NotificationContent {
    explicit NotificationContent(const std::shared_ptr<NotificationNormalContent> &) {}
};
struct NotificationActionButton {
    static std::shared_ptr<NotificationActionButton> Create(std::nullptr_t, const std::string &,
        const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> &)
    {
        return std::make_shared<NotificationActionButton>();
    }
};
struct NotificationConstant {
    enum class SlotType { SOCIAL_COMMUNICATION };
};
struct NotificationRequest {
    int32_t receiverUserId = -1;
    void SetNotificationId(int32_t) {}
    void SetContent(const std::shared_ptr<NotificationContent> &) {}
    void SetNotificationControlFlags(uint32_t) {}
    void SetLittleIcon(const std::shared_ptr<int> &) {}
    void SetSlotType(NotificationConstant::SlotType) {}
    void SetRemoveAllowed(bool) {}
    void SetTapDismissed(bool) {}
    void SetCreatorUid(int32_t) {}
    void SetReceiverUserId(int32_t userId) { receiverUserId = userId; }
    void AddActionButton(const std::shared_ptr<NotificationActionButton> &) {}
};
struct NotificationHelper {
    static int PublishNotification(const NotificationRequest &request)
    {
        if (HostTest::switchAtPublish) {
            HostTest::foregroundUser = 101;
        }
        if (HostTest::publishFails) {
            return -1;
        }
        HostTest::receivers.push_back(request.receiverUserId);
        return ERR_OK;
    }
};
}
namespace Print {
inline int getuid() { return 3813; }
enum class HisysEventType { PRINT_FAILURE };
struct HisysEventParams {
    HisysEventType eventType;
    std::string resourceKey;
    uint32_t subState;
};
struct HisysEventUtil {
    static void ReportPrintFailure(const std::string &, uint32_t state) { ++HostTest::faults[state]; }
    static void ReportFailureEvent(const HisysEventParams &params) { ++HostTest::faults[params.subState]; }
};
struct PrintResourceManager {
    static PrintResourceManager &GetInstance() { static PrintResourceManager instance; return instance; }
    std::shared_ptr<int> GetPixelMapByName(const std::string &) { return nullptr; }
    std::string GetStringByName(const std::string &key) { return key; }
};
struct PrintJob {
    std::string jobId = "A_job";
    std::string printerId = "printer";
    const std::string &GetJobId() const { return jobId; }
    const std::string &GetPrinterId() const { return printerId; }
};
struct PrinterInfo {
    std::string GetPrinterName() const { return "Printer"; }
};
struct PrintSystemData {
    bool exists = true;
    std::shared_ptr<PrinterInfo> QueryDiscoveredPrinterInfoById(const std::string &)
    {
        return exists ? std::make_shared<PrinterInfo>() : nullptr;
    }
};
struct PrintServiceAbility {
    int32_t currentUserId_ = 100;
    std::map<std::string, int32_t> userJobMap_ {{"A_job", 100}};
    PrintSystemData printSystemData_;
    int historyWrites = 0;
    void AddPrintJobToHistoryList(const std::shared_ptr<PrintJob> &) { ++historyWrites; }
    void ReportBlockedAuditEvent(const std::shared_ptr<PrintJob> &, uint32_t) {}
    bool isEprint(const std::string &id) { return id == "eprint"; }
    bool QueryAddedPrinterInfoByPrinterId(const std::string &, PrinterInfo &) { return printSystemData_.exists; }
    void HandleJobBlockedState(const std::shared_ptr<PrintJob> &, uint32_t);
};
}
}
#endif
