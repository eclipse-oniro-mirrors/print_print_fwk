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
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "agent/print_fwk_agent_client_loader.h"
#include "agent/print_fwk_agent_host.h"

namespace OHOS::Print {

class PrintSystemData;
class PrinterInfo;

class PrintFwkAgentManager {
public:
    using Clock = std::chrono::steady_clock;
    using NowProvider = std::function<Clock::time_point()>;

    static PrintFwkAgentManager &GetInstance();

    bool Init(PrintSystemData &systemData, PrintFwkAgentHost &host,
        std::unique_ptr<PrintFwkAgentClientLoader> loader = nullptr,
        NowProvider nowProvider = []() { return Clock::now(); });
    void Shutdown();
    bool IsRunning() const;

    bool IsAgentRouteRequested(const std::string &options) const;
    bool IsAgentRoutedPrinterByName(const std::string &printerName) const;
    static bool IsAgentRouted(const std::string &options);
    std::optional<int32_t> TryAddPrinterViaAgent(const std::string &printerName, const std::string &uri,
        const std::string &options);
    int32_t AddPrinterViaAgent(const std::string &printerName, const std::string &uri,
        const std::string &options);
    int32_t DeletePrinterFromAgent(const std::string &printerName);
    bool ClaimPendingAgentPrinter(PrinterInfo &printerInfo);
    bool AttachPendingAgentPrinter(PrinterInfo &printerInfo);
    void ConfirmAgentPrinterPersisted(const PrinterInfo &printerInfo);

    // Agent backend lifecycle management
    int32_t EnsureAgentBackendReady();
    bool IsAgentBackendOnline();
    int32_t EnsureBackendReadyForPersistedPrinters();
    void PreparePrintJob(const std::string &jobId, const std::string &printerId);
    void OnPrintJobStateChanged(const std::string &jobId, uint32_t state, uint32_t subState);
    void StartAgentBackendKeepalive(const std::string &jobId, const std::string &printerId);
    void StopAgentBackendKeepalive(const std::string &jobId);
    void OnCupsJobMonitorTick(const std::string &jobId);

private:
    PrintFwkAgentManager() = default;
    ~PrintFwkAgentManager();
    PrintFwkAgentManager(const PrintFwkAgentManager &) = delete;
    PrintFwkAgentManager &operator=(const PrintFwkAgentManager &) = delete;

    enum class State {
        STOPPED,
        RUNNING,
        STOPPING,
    };

    // Keeps both the original URI for persistence and a canonical key for duplicate checks.
    struct SourcePrinterIdentity {
        std::string uri;
        std::string matchKey;
    };

    // The actual timestamped CUPS queue returned by the Agent.
    struct AgentQueueIdentity {
        std::string uri;
        std::string name;
    };

    struct AgentAddOptions {
        std::string backendType;
        std::string driverInstall;
    };

    struct PendingAgentPrinterMetadata {
        SourcePrinterIdentity source;
        AgentQueueIdentity queue;
        std::string displayName;
        std::string backendType;
    };

    struct PersistedAgentPrinterMetadata {
        SourcePrinterIdentity source;
        // Exact Agent queue name used by RemovePrinter; it must not be reconstructed.
        std::string queueName;
        std::string backendType;
    };

    struct PendingAgentPrinter {
        PendingAgentPrinterMetadata metadata;
        Clock::time_point expiresAt;
    };

    enum class AddSlotResult {
        RESERVED,
        DUPLICATE_SOURCE,
        CAPACITY_REACHED,
        NOT_RUNNING,
    };

    enum class RoutedAddOptionsResult {
        NOT_AGENT_ROUTE,
        INVALID_OPTIONS,
        VALID_OPTIONS,
    };

    class AgentPrinterOptionCodec;
    struct AddReservation;
    struct PrepareAddResult;
    struct AddPrinterContext;
    struct RemovePrinterContext;

    static void HandleAddDone(int32_t errCode, const PrintAddPrinterResult *result, void *userData);
    static void HandleAddProgress(int32_t progress, void *userData);
    static void HandleRemoveDone(int32_t errCode, void *userData);

    static std::string BuildUriMatchKey(const std::string &uri);
    static SourcePrinterIdentity BuildSourcePrinterIdentity(const std::string &uri);
    static bool ParseSourcePrinterUri(const std::string &uri, SourcePrinterIdentity &source);
    static bool BuildAgentQueueIdentity(const std::string &uri, AgentQueueIdentity &queue);
    int32_t AddPrinterViaAgent(
        const std::string &printerName, const std::string &uri, AgentAddOptions addOptions);
    int32_t SubmitAddPrinter(std::unique_ptr<AddPrinterContext> context);
    PrepareAddResult PrepareAgentAdd(
        const std::string &printerName, const SourcePrinterIdentity &source);
    AddSlotResult TryReserveAddSlot(const SourcePrinterIdentity &source);
    void ReleaseAddSlot(const SourcePrinterIdentity &source);
    bool CompleteAddSlotWithPending(PendingAgentPrinterMetadata metadata);
    bool IsAgentPrinter(const std::string &printerId) const;
    bool HasPersistedAgentPrinters() const;
    bool IsSourcePrinterAdded(const SourcePrinterIdentity &source) const;
    void ReleaseTrackedSource(const SourcePrinterIdentity &source);
    void PruneExpiredPendingLocked(Clock::time_point now);

    static constexpr size_t MAX_PENDING_AGENT_PRINTERS = 32;
    static constexpr std::chrono::seconds PENDING_TIMEOUT { 30 };
    static constexpr std::chrono::seconds BACKEND_KEEPALIVE_INTERVAL { 60 };

    PrintSystemData *systemData_ = nullptr;
    PrintFwkAgentHost *host_ = nullptr;
    std::unique_ptr<PrintFwkAgentClientLoader> loader_;
    std::atomic<State> state_ { State::STOPPED };
    std::mutex lifecycleMutex_;
    // Protects the following three add-state containers.
    std::mutex pendingMutex_;
    std::unordered_map<std::string, PendingAgentPrinter> pendingPrinters_; // queue key -> pending discovery
    std::unordered_set<std::string> inFlightSources_; // source keys reserved by active adds
    std::unordered_map<std::string, std::string> pendingQueueBySource_; // source key -> pending queue key
    NowProvider nowProvider_ = []() { return Clock::now(); };

    // Agent backend keepalive management
    std::mutex keepaliveMutex_;
    std::unordered_map<std::string, std::string> keepaliveJobs_; // jobId -> printerId
    // Shared throttle time for all active Agent jobs.
    Clock::time_point keepaliveLastTick_ {};
};

} // namespace OHOS::Print

#endif // PRINT_FWK_AGENT_MANAGER_H
