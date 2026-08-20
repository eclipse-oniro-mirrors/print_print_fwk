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

#ifndef PRINT_FWK_AGENT_MANAGER_H
#define PRINT_FWK_AGENT_MANAGER_H

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "agent/print_fwk_agent_client_loader.h"
#include "agent/print_fwk_agent_host.h"

namespace OHOS::Print {

class PrintSystemData;
class PrinterInfo;
class VendorManager;

class PrintFwkAgentManager {
public:
    using Clock = std::chrono::steady_clock;
    using NowProvider = std::function<Clock::time_point()>;

    PrintFwkAgentManager(PrintSystemData &systemData, VendorManager &vendorManager,
        PrintFwkAgentHost &host, std::unique_ptr<PrintFwkAgentClientLoader> loader = nullptr,
        NowProvider nowProvider = []() { return Clock::now(); });
    ~PrintFwkAgentManager();

    bool Init();
    void Shutdown();
    bool IsRunning() const;

    bool IsAgentRouteRequested(const std::string &options) const;
    bool IsAgentRoutedPrinterByName(const std::string &printerName) const;
    int32_t AddPrinterViaAgent(const std::string &printerName, const std::string &uri,
        const std::string &options);
    int32_t DeletePrinterFromAgent(const std::string &printerName);
    bool ClaimPendingAgentPrinter(const std::string &uri);
    bool AttachPendingAgentPrinter(PrinterInfo &printerInfo);

private:
    enum class State {
        STOPPED,
        RUNNING,
        STOPPING,
    };

    struct PendingAgentPrinter {
        std::string agentIppUri;
        std::string agentQueueName;
        std::string displayPrinterName;
        std::string sourceUri;
        std::string sourceKey;
        std::string backendType;
        Clock::time_point expiresAt;
    };

    enum class AddSlotResult {
        RESERVED,
        DUPLICATE_SOURCE,
        CAPACITY_REACHED,
    };

    struct AddPrinterContext;
    struct RemovePrinterContext;

    static void HandleAddDone(int32_t errCode, const PrintAddPrinterResult *result, void *userData);
    static void HandleAddProgress(int32_t progress, void *userData);
    static void HandleRemoveDone(int32_t errCode, void *userData);

    static bool IsAgentRouted(const std::string &options);
    static bool ExtractAgentAddOptions(
        const std::string &options, std::string &backendType, std::string &driverInstall);
    static bool ExtractAgentPrinterMetadata(
        const std::string &options, std::string &queueName, std::string &backendType,
        std::string &sourceUri);
    static std::string BuildUriMatchKey(const std::string &uri);
    static bool ExtractQueueNameFromIppUri(const std::string &uri, std::string &queueName);
    static bool ExtractPrinterIpFromUri(const std::string &uri, std::string &printerIp);
    int32_t SubmitAddPrinter(std::unique_ptr<AddPrinterContext> context);
    AddSlotResult TryReserveAddSlot(const std::string &sourceKey);
    void ReleaseAddSlot(const std::string &sourceKey);
    bool CompleteAddSlotWithPending(
        const std::string &queueUri, const std::string &queueName, const std::string &displayPrinterName,
        const std::string &sourceUri, const std::string &sourceKey, const std::string &backendType);
    bool IsSourceUriAdded(const std::string &sourceKey) const;
    void ReleaseSourceKey(const std::string &sourceKey);
    void PruneExpiredPendingLocked(Clock::time_point now);

    static constexpr size_t MAX_PENDING_AGENT_PRINTERS = 32;
    static constexpr std::chrono::seconds PENDING_TIMEOUT { 30 };

    PrintSystemData &systemData_;
    VendorManager &vendorManager_;
    PrintFwkAgentHost &host_;
    std::unique_ptr<PrintFwkAgentClientLoader> loader_;
    std::atomic<State> state_ { State::STOPPED };
    std::mutex pendingMutex_;
    std::unordered_map<std::string, PendingAgentPrinter> pendingPrinters_;
    std::unordered_set<std::string> activeSourceKeys_;
    size_t inFlightAddCount_ = 0;
    NowProvider nowProvider_;
};

} // namespace OHOS::Print

#endif // PRINT_FWK_AGENT_MANAGER_H
