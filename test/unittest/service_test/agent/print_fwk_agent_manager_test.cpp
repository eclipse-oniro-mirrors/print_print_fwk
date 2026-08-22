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

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "print_constant.h"
#include "agent/print_fwk_agent_client_api.h"
#include "agent/print_fwk_agent_host.h"
#include "agent/print_fwk_agent_manager.h"
#include "print_json_util.h"
#include "print_system_data.h"
#include "vendor_manager.h"

using namespace OHOS::Print;

struct PrintFwkAgentClient {};

namespace {
constexpr const char *TEST_BACKEND_TYPE = "TEST_BACKEND";
constexpr std::chrono::seconds PENDING_TIMEOUT { 30 };
constexpr std::chrono::seconds BEFORE_PENDING_TIMEOUT = PENDING_TIMEOUT - std::chrono::seconds { 1 };
constexpr std::chrono::seconds PENDING_REPLACEMENT_DELAY { 10 };
constexpr size_t MAX_PENDING_AGENT_PRINTERS = 32;
constexpr const char *TIMESTAMPED_QUEUE_NAME = "Office_Printer_1786320000";
const std::string TIMESTAMPED_IPP_URI =
    std::string("ipp://10.0.0.2:631/printers/") + TIMESTAMPED_QUEUE_NAME;
const std::string VALID_AGENT_OPTIONS =
    R"({"driver":"AGENT","agentBackendType":"TEST_BACKEND"})";

struct PendingAddCall {
    PrintAgentAddDoneCb done = nullptr;
    PrintAgentProgressCb progress = nullptr;
    void *userData = nullptr;
};

struct DelayedTaskCall {
    PrintFwkAgentManager::DelayedTask task;
    std::string name;
    int64_t delayMs = 0;
};

struct FakeLoaderState {
    uint32_t destroyCount = 0;
    int32_t addReturn = PRINT_FWK_AGENT_CLIENT_OK;
    int32_t removeReturn = PRINT_FWK_AGENT_CLIENT_OK;
    int32_t ensureBackendReadyReturn = PRINT_FWK_AGENT_CLIENT_OK;
    uint32_t addCallCount = 0;
    uint32_t removeCallCount = 0;
    uint32_t ensureBackendReadyCallCount = 0;
    uint32_t backendKeepaliveTickCount = 0;
    bool completeAddSynchronously = false;
    bool completeRemoveSynchronously = false;
    PrintAgentAddDoneCb addDone = nullptr;
    PrintAgentProgressCb addProgress = nullptr;
    void *addUserData = nullptr;
    PrintAgentRemoveDoneCb removeDone = nullptr;
    void *removeUserData = nullptr;
    std::vector<PendingAddCall> pendingAdds;
    const char *removeNamePtr = nullptr;
    const char *removeBackendTypePtr = nullptr;
    std::string uri;
    std::string name;
    std::string driverInstall;
    std::string backendType;
    std::string nameReadAfterSyncDone;
    std::string backendTypeReadAfterSyncDone;
    std::string removeNameReadBeforeAsyncDone;
    std::string removeBackendTypeReadBeforeAsyncDone;
};

FakeLoaderState g_fakeLoaderState;
PrintFwkAgentClient g_fakeClient;

void ResetFakeLoaderState()
{
    g_fakeLoaderState = {};
}

PrintFwkAgentClient *FakeCreate()
{
    return &g_fakeClient;
}

void CompleteAdd(int32_t errCode, const PrintAddPrinterResult *result = nullptr);
void CompleteRemove(int32_t errCode);

void FakeDestroy(PrintFwkAgentClient *)
{
    ++g_fakeLoaderState.destroyCount;
}

int32_t FakeAddPrinter(PrintFwkAgentClient *, const PrintAddPrinterParam *param,
    PrintAgentAddDoneCb done, PrintAgentProgressCb progress, void *userData)
{
    ++g_fakeLoaderState.addCallCount;
    g_fakeLoaderState.uri = param->uri == nullptr ? "" : param->uri;
    g_fakeLoaderState.name = param->name == nullptr ? "" : param->name;
    g_fakeLoaderState.driverInstall = param->driverInstall == nullptr ? "" : param->driverInstall;
    g_fakeLoaderState.backendType = param->backendType == nullptr ? "" : param->backendType;
    if (g_fakeLoaderState.addReturn != PRINT_FWK_AGENT_CLIENT_OK) {
        return g_fakeLoaderState.addReturn;
    }
    if (g_fakeLoaderState.completeAddSynchronously) {
        static const char syncIppUri[] = "ipp://10.0.0.2:631/printers/sync";
        const PrintAddPrinterResult result { syncIppUri, nullptr, 0 };
        g_fakeLoaderState.addDone = nullptr;
        g_fakeLoaderState.addProgress = nullptr;
        g_fakeLoaderState.addUserData = nullptr;
        done(PRINT_FWK_AGENT_CLIENT_OK, &result, userData);
        g_fakeLoaderState.nameReadAfterSyncDone = param->name == nullptr ? "" : param->name;
        g_fakeLoaderState.backendTypeReadAfterSyncDone =
            param->backendType == nullptr ? "" : param->backendType;
        return g_fakeLoaderState.addReturn;
    }
    g_fakeLoaderState.pendingAdds.push_back({ done, progress, userData });
    g_fakeLoaderState.addDone = g_fakeLoaderState.pendingAdds.back().done;
    g_fakeLoaderState.addProgress = g_fakeLoaderState.pendingAdds.back().progress;
    g_fakeLoaderState.addUserData = g_fakeLoaderState.pendingAdds.back().userData;
    return g_fakeLoaderState.addReturn;
}

int32_t FakeRemovePrinter(PrintFwkAgentClient *, const char *name, const char *backendType,
    PrintAgentRemoveDoneCb done, void *userData)
{
    ++g_fakeLoaderState.removeCallCount;
    g_fakeLoaderState.name = name == nullptr ? "" : name;
    g_fakeLoaderState.backendType = backendType == nullptr ? "" : backendType;
    g_fakeLoaderState.removeNamePtr = name;
    g_fakeLoaderState.removeBackendTypePtr = backendType;
    if (g_fakeLoaderState.removeReturn != PRINT_FWK_AGENT_CLIENT_OK) {
        g_fakeLoaderState.removeNamePtr = nullptr;
        g_fakeLoaderState.removeBackendTypePtr = nullptr;
        return g_fakeLoaderState.removeReturn;
    }
    if (g_fakeLoaderState.completeRemoveSynchronously) {
        auto namePtr = g_fakeLoaderState.removeNamePtr;
        auto backendTypePtr = g_fakeLoaderState.removeBackendTypePtr;
        g_fakeLoaderState.removeNamePtr = nullptr;
        g_fakeLoaderState.removeBackendTypePtr = nullptr;
        g_fakeLoaderState.removeDone = nullptr;
        g_fakeLoaderState.removeUserData = nullptr;
        done(PRINT_FWK_AGENT_CLIENT_OK, userData);
        g_fakeLoaderState.nameReadAfterSyncDone = namePtr == nullptr ? "" : namePtr;
        g_fakeLoaderState.backendTypeReadAfterSyncDone = backendTypePtr == nullptr ? "" : backendTypePtr;
        return g_fakeLoaderState.removeReturn;
    }
    g_fakeLoaderState.removeDone = done;
    g_fakeLoaderState.removeUserData = userData;
    return g_fakeLoaderState.removeReturn;
}

int32_t FakeEnsureBackendReady(PrintFwkAgentClient *)
{
    ++g_fakeLoaderState.ensureBackendReadyCallCount;
    return g_fakeLoaderState.ensureBackendReadyReturn;
}

void FakeBackendKeepaliveTick(PrintFwkAgentClient *)
{
    ++g_fakeLoaderState.backendKeepaliveTickCount;
}

PrintFwkAgentClientApi CreateFakeLoaderApi()
{
    return {
        1,
        FakeCreate,
        FakeDestroy,
        FakeAddPrinter,
        FakeRemovePrinter,
        FakeEnsureBackendReady,
        FakeBackendKeepaliveTick,
    };
}

void CompleteAdd(int32_t errCode, const PrintAddPrinterResult *result)
{
    ASSERT_FALSE(g_fakeLoaderState.pendingAdds.empty());
    auto call = g_fakeLoaderState.pendingAdds.back();
    g_fakeLoaderState.pendingAdds.pop_back();
    auto done = call.done;
    auto userData = call.userData;
    if (g_fakeLoaderState.pendingAdds.empty()) {
        g_fakeLoaderState.addDone = nullptr;
        g_fakeLoaderState.addProgress = nullptr;
        g_fakeLoaderState.addUserData = nullptr;
    } else {
        g_fakeLoaderState.addDone = g_fakeLoaderState.pendingAdds.back().done;
        g_fakeLoaderState.addProgress = g_fakeLoaderState.pendingAdds.back().progress;
        g_fakeLoaderState.addUserData = g_fakeLoaderState.pendingAdds.back().userData;
    }
    ASSERT_NE(done, nullptr);
    done(errCode, result, userData);
}

void CompleteRemove(int32_t errCode)
{
    auto done = g_fakeLoaderState.removeDone;
    auto userData = g_fakeLoaderState.removeUserData;
    g_fakeLoaderState.removeNameReadBeforeAsyncDone =
        g_fakeLoaderState.removeNamePtr == nullptr ? "" : g_fakeLoaderState.removeNamePtr;
    g_fakeLoaderState.removeBackendTypeReadBeforeAsyncDone =
        g_fakeLoaderState.removeBackendTypePtr == nullptr ? "" : g_fakeLoaderState.removeBackendTypePtr;
    g_fakeLoaderState.removeNamePtr = nullptr;
    g_fakeLoaderState.removeBackendTypePtr = nullptr;
    g_fakeLoaderState.removeDone = nullptr;
    g_fakeLoaderState.removeUserData = nullptr;
    ASSERT_NE(done, nullptr);
    done(errCode, userData);
}

Json::Value GetAgentAddProgress(const PrinterInfo &info)
{
    Json::Value option;
    EXPECT_TRUE(PrintJsonUtil::Parse(info.GetOption(), option));
    return option["agentAddProgress"];
}

Json::Value GetOption(const PrinterInfo &info)
{
    Json::Value option;
    EXPECT_TRUE(PrintJsonUtil::Parse(info.GetOption(), option));
    return option;
}

class FakeAgentHost final : public PrintFwkAgentHost {
public:
    bool IsCallerSystemApp() override
    {
        ++isCallerSystemAppCount;
        return isSystemApp;
    }

    void NotifyPrinterInfoChanged(const PrinterInfo &info) override
    {
        ++notifyPrinterInfoChangedCount;
        lastInfo = info;
    }

    void CommitAgentPrinterDeleted(const std::string &printerId, const std::string &printerName) override
    {
        ++commitAgentPrinterDeletedCount;
        lastPrinterId = printerId;
        lastPrinterName = printerName;
    }

    bool isSystemApp = false;
    uint32_t isCallerSystemAppCount = 0;
    uint32_t notifyPrinterInfoChangedCount = 0;
    uint32_t commitAgentPrinterDeletedCount = 0;
    std::string lastPrinterId;
    std::string lastPrinterName;
    PrinterInfo lastInfo;
};

class PrintFwkAgentManagerTest : public testing::Test {
public:
    PrintFwkAgentManager::DelayedTaskPoster BuildDelayedTaskPoster()
    {
        return [this](PrintFwkAgentManager::DelayedTask task, const std::string &name, int64_t delayMs) {
            ++postTaskCallCount;
            if (!postTaskResult) {
                return false;
            }
            delayedTasks.push_back({ std::move(task), name, delayMs });
            return true;
        };
    }

    void RunNextDelayedTask()
    {
        ASSERT_FALSE(delayedTasks.empty());
        auto task = std::move(delayedTasks.front().task);
        delayedTasks.erase(delayedTasks.begin());
        task();
    }

    void SetUp() override
    {
        manager = &PrintFwkAgentManager::GetInstance();
        manager->Shutdown();
        ResetFakeLoaderState();
        api = CreateFakeLoaderApi();
        auto loader = std::make_unique<PrintFwkAgentClientLoader>();
        loader->SetApiForTest(&api, &g_fakeClient);
        ASSERT_TRUE(manager->Init(systemData, host, BuildDelayedTaskPoster(), std::move(loader),
            [this]() { return now; }));
    }

    void TearDown() override
    {
        while (!g_fakeLoaderState.pendingAdds.empty()) {
            CompleteAdd(PRINT_FWK_AGENT_CLIENT_ERR_RPC);
        }
        if (g_fakeLoaderState.removeDone != nullptr) {
            CompleteRemove(PRINT_FWK_AGENT_CLIENT_ERR_RPC);
        }
        manager->Shutdown();
    }

protected:
    PrintSystemData systemData;
    VendorManager vendorManager;
    FakeAgentHost host;
    PrintFwkAgentClientApi api {};
    PrintFwkAgentManager *manager = nullptr;
    PrintFwkAgentManager::Clock::time_point now {};
    std::vector<DelayedTaskCall> delayedTasks;
    uint32_t postTaskCallCount = 0;
    bool postTaskResult = true;
};

class FailingPrintFwkAgentClientLoader final : public PrintFwkAgentClientLoader {
public:
    bool Load() override
    {
        return false;
    }
};

void InsertAddedPrinter(PrintSystemData &systemData, const std::string &printerId,
    const std::string &printerName, const std::string &uri, const std::string &option)
{
    PrinterInfo info;
    info.SetPrinterId(printerId);
    info.SetPrinterName(printerName);
    info.SetUri(uri);
    info.SetOption(option);
    systemData.InsertAddedPrinter(printerId, info);
}

bool ClaimPendingPrinter(
    PrintFwkAgentManager &manager, const std::string &uri, PrinterInfo *claimedPrinter = nullptr)
{
    PrinterInfo printerInfo;
    printerInfo.SetUri(uri);
    bool claimed = manager.ClaimPendingAgentPrinter(printerInfo);
    if (claimedPrinter != nullptr) {
        *claimedPrinter = printerInfo;
    }
    return claimed;
}
} // namespace

TEST_F(PrintFwkAgentManagerTest, BackendLifecycleDelegatesToLoader)
{
    g_fakeLoaderState.ensureBackendReadyReturn = PRINT_FWK_AGENT_CLIENT_BACKEND_STOPPED;
    EXPECT_EQ(manager->EnsureAgentBackendReady(), E_PRINT_RPC_FAILURE);
    EXPECT_EQ(g_fakeLoaderState.ensureBackendReadyCallCount, 1u);

    manager->StartAgentBackendKeepalive("job-id");
    ASSERT_EQ(delayedTasks.size(), 1u);
    EXPECT_EQ(delayedTasks.front().name, "AgentBackendKeepalive");
    EXPECT_EQ(delayedTasks.front().delayMs, 60000);
    EXPECT_EQ(postTaskCallCount, 1u);
    EXPECT_EQ(g_fakeLoaderState.backendKeepaliveTickCount, 0u);

    manager->StartAgentBackendKeepalive("second-job-id");
    EXPECT_EQ(delayedTasks.size(), 1u);
    EXPECT_EQ(postTaskCallCount, 1u);

    RunNextDelayedTask();
    EXPECT_EQ(g_fakeLoaderState.backendKeepaliveTickCount, 1u);
    EXPECT_EQ(delayedTasks.size(), 1u);
    EXPECT_EQ(postTaskCallCount, 2u);

    manager->StopAgentBackendKeepalive("job-id");
    RunNextDelayedTask();
    EXPECT_EQ(g_fakeLoaderState.backendKeepaliveTickCount, 2u);
    EXPECT_EQ(delayedTasks.size(), 1u);
    EXPECT_EQ(postTaskCallCount, 3u);

    manager->StopAgentBackendKeepalive("second-job-id");
    RunNextDelayedTask();
    EXPECT_EQ(g_fakeLoaderState.backendKeepaliveTickCount, 2u);
    EXPECT_TRUE(delayedTasks.empty());
    EXPECT_EQ(postTaskCallCount, 3u);
}

TEST_F(PrintFwkAgentManagerTest, PersistedAgentPrinterDrivesBestEffortBackendAndJobLifecycle)
{
    EXPECT_EQ(manager->EnsureBackendReadyForPersistedPrinters(), E_PRINT_NONE);
    EXPECT_EQ(g_fakeLoaderState.ensureBackendReadyCallCount, 0u);

    InsertAddedPrinter(systemData, "agent-id", "Agent Printer", "ipp://10.0.0.1/printers/agent",
        R"({"driver":"AGENT"})");
    EXPECT_EQ(manager->EnsureBackendReadyForPersistedPrinters(), E_PRINT_NONE);
    EXPECT_EQ(g_fakeLoaderState.ensureBackendReadyCallCount, 1u);

    manager->PreparePrintJob("ordinary-job", "ordinary-id");
    EXPECT_EQ(g_fakeLoaderState.ensureBackendReadyCallCount, 1u);
    EXPECT_TRUE(delayedTasks.empty());

    g_fakeLoaderState.ensureBackendReadyReturn = PRINT_FWK_AGENT_CLIENT_BACKEND_RESUME_FAILED;
    manager->PreparePrintJob("agent-job", "agent-id");
    EXPECT_EQ(g_fakeLoaderState.ensureBackendReadyCallCount, 2u);
    ASSERT_EQ(delayedTasks.size(), 1u);

    RunNextDelayedTask();
    EXPECT_EQ(g_fakeLoaderState.backendKeepaliveTickCount, 1u);

    manager->OnPrintJobStateChanged("agent-job", PRINT_JOB_BLOCKED, PRINT_JOB_BLOCKED_OFFLINE);
    RunNextDelayedTask();
    EXPECT_EQ(g_fakeLoaderState.backendKeepaliveTickCount, 2u);

    manager->OnPrintJobStateChanged("agent-job", PRINT_JOB_COMPLETED, PRINT_JOB_COMPLETED_SUCCESS);
    RunNextDelayedTask();
    EXPECT_EQ(g_fakeLoaderState.backendKeepaliveTickCount, 2u);
    EXPECT_TRUE(delayedTasks.empty());
}

TEST_F(PrintFwkAgentManagerTest, KeepalivePostFailureCanRetryOnLaterRegistration)
{
    postTaskResult = false;
    manager->StartAgentBackendKeepalive("job-id");

    EXPECT_EQ(postTaskCallCount, 1u);
    EXPECT_TRUE(delayedTasks.empty());

    postTaskResult = true;
    manager->StartAgentBackendKeepalive("job-id");

    EXPECT_EQ(postTaskCallCount, 2u);
    EXPECT_EQ(delayedTasks.size(), 1u);
}

TEST_F(PrintFwkAgentManagerTest, ShutdownInvalidatesOldKeepaliveTaskAcrossReinit)
{
    manager->StartAgentBackendKeepalive("old-job");
    ASSERT_EQ(delayedTasks.size(), 1u);
    auto oldTask = std::move(delayedTasks.front().task);
    delayedTasks.clear();

    manager->Shutdown();
    auto loader = std::make_unique<PrintFwkAgentClientLoader>();
    loader->SetApiForTest(&api, &g_fakeClient);
    ASSERT_TRUE(manager->Init(systemData, host, BuildDelayedTaskPoster(), std::move(loader),
        [this]() { return now; }));
    manager->StartAgentBackendKeepalive("new-job");
    ASSERT_EQ(delayedTasks.size(), 1u);

    oldTask();
    EXPECT_EQ(g_fakeLoaderState.backendKeepaliveTickCount, 0u);
    EXPECT_EQ(delayedTasks.size(), 1u);

    RunNextDelayedTask();
    EXPECT_EQ(g_fakeLoaderState.backendKeepaliveTickCount, 1u);
}

TEST(PrintFwkAgentManagerLifecycleTest, InitFailureKeepsManagerStopped)
{
    auto loader = std::make_unique<FailingPrintFwkAgentClientLoader>();
    PrintSystemData systemData;
    FakeAgentHost host;
    auto &manager = PrintFwkAgentManager::GetInstance();
    manager.Shutdown();

    EXPECT_FALSE(manager.Init(systemData, host,
        [](PrintFwkAgentManager::DelayedTask, const std::string &, int64_t) { return true; },
        std::move(loader)));
    EXPECT_FALSE(manager.IsRunning());
    host.isSystemApp = true;
    auto result = manager.TryAddPrinterViaAgent("Office Printer",
        "ipp://192.168.1.10:631/printers/office", VALID_AGENT_OPTIONS);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, E_PRINT_RPC_FAILURE);
    manager.Shutdown();
}

TEST_F(PrintFwkAgentManagerTest, TryAddPrinterRoutesOnlyValidSystemAgentRequest)
{
    EXPECT_FALSE(manager->TryAddPrinterViaAgent("Office Printer",
        "ipp://192.168.1.10:631/printers/office", VALID_AGENT_OPTIONS).has_value());

    host.isSystemApp = true;
    EXPECT_FALSE(manager->TryAddPrinterViaAgent("Office Printer",
        "ipp://192.168.1.10:631/printers/office", "not a json").has_value());
    EXPECT_FALSE(manager->TryAddPrinterViaAgent("Office Printer",
        "ipp://192.168.1.10:631/printers/office", R"({"driver":123})").has_value());
    EXPECT_FALSE(manager->TryAddPrinterViaAgent("Office Printer",
        "ipp://192.168.1.10:631/printers/office", R"({"driver":"RAW"})").has_value());
    auto invalidResult = manager->TryAddPrinterViaAgent("Office Printer",
        "ipp://192.168.1.10:631/printers/office", R"({"driver":"AGENT"})");
    ASSERT_TRUE(invalidResult.has_value());
    EXPECT_EQ(*invalidResult, E_PRINT_INVALID_PARAMETER);

    auto result = manager->TryAddPrinterViaAgent("Office Printer",
        "ipp://192.168.1.10:631/printers/office", VALID_AGENT_OPTIONS);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, E_PRINT_NONE);
    EXPECT_EQ(g_fakeLoaderState.addCallCount, 1u);
}

TEST_F(PrintFwkAgentManagerTest, IsAgentRoutedPrinterByNameRequiresSystemAgentPrinter)
{
    InsertAddedPrinter(systemData, "agent-id", "Agent Printer", "ipp://10.0.0.1/printers/agent",
        R"({"driver":"AGENT"})");
    InsertAddedPrinter(systemData, "raw-id", "Raw Printer", "ipp://10.0.0.2/printers/raw",
        R"({"driver":"RAW"})");
    InsertAddedPrinter(systemData, "bad-id", "Bad Printer", "ipp://10.0.0.3/printers/bad", "not json");

    host.isSystemApp = true;
    EXPECT_TRUE(manager->IsAgentRoutedPrinterByName("Agent Printer"));
    EXPECT_FALSE(manager->IsAgentRoutedPrinterByName("Raw Printer"));
    EXPECT_FALSE(manager->IsAgentRoutedPrinterByName("Bad Printer"));
    EXPECT_FALSE(manager->IsAgentRoutedPrinterByName("Missing Printer"));

    host.isSystemApp = false;
    EXPECT_FALSE(manager->IsAgentRoutedPrinterByName("Agent Printer"));
}

TEST_F(PrintFwkAgentManagerTest, AddBuildsParameters)
{
    const std::string options =
        R"({"driver":"AGENT","agentBackendType":"TEST_BACKEND",)"
        R"("agentDriverInstall":{"makeAndModel":"Fake Laser Printer"}})";
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", "ipp://192.168.1.10:631/printers/office", options),
        E_PRINT_NONE);

    EXPECT_EQ(g_fakeLoaderState.addCallCount, 1u);
    EXPECT_EQ(g_fakeLoaderState.uri, "ipp://192.168.1.10:631/printers/office");
    EXPECT_EQ(g_fakeLoaderState.name, "Office Printer");
    EXPECT_EQ(g_fakeLoaderState.driverInstall, R"({"makeAndModel":"Fake Laser Printer"})");
    EXPECT_EQ(g_fakeLoaderState.backendType, TEST_BACKEND_TYPE);
    EXPECT_NE(g_fakeLoaderState.addDone, nullptr);
    EXPECT_NE(g_fakeLoaderState.addProgress, nullptr);
    EXPECT_NE(g_fakeLoaderState.addUserData, nullptr);
    g_fakeLoaderState.addProgress(PRINT_AGENT_PROGRESS_ENV_INIT, g_fakeLoaderState.addUserData);
    EXPECT_TRUE(host.lastInfo.GetPrinterId().empty());
    EXPECT_EQ(host.lastInfo.GetPrinterName(), "Office Printer");
    EXPECT_EQ(host.lastInfo.GetPrinterState(), PRINTER_UNKNOWN);
    CompleteAdd(PRINT_FWK_AGENT_CLIENT_ERR_RPC);
}

TEST_F(PrintFwkAgentManagerTest, AddSynchronousDoneKeepsParametersAliveAndCompletesOnce)
{
    g_fakeLoaderState.completeAddSynchronously = true;

    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", "ipp://192.168.1.10:631/printers/office",
        VALID_AGENT_OPTIONS), E_PRINT_NONE);

    EXPECT_EQ(g_fakeLoaderState.addCallCount, 1u);
    EXPECT_EQ(g_fakeLoaderState.nameReadAfterSyncDone, "Office Printer");
    EXPECT_EQ(g_fakeLoaderState.backendTypeReadAfterSyncDone, TEST_BACKEND_TYPE);
    EXPECT_EQ(host.notifyPrinterInfoChangedCount, 1u);
    EXPECT_TRUE(host.lastInfo.GetPrinterId().empty());
    EXPECT_EQ(host.lastInfo.GetPrinterName(), "Office Printer");
    EXPECT_EQ(host.lastInfo.GetUri(), "ipp://10.0.0.2:631/printers/sync");
    EXPECT_EQ(GetAgentAddProgress(host.lastInfo)["status"].asString(), "PENDING_DISCOVERY");
    EXPECT_EQ(g_fakeLoaderState.addDone, nullptr);
    EXPECT_EQ(g_fakeLoaderState.addProgress, nullptr);
    EXPECT_EQ(g_fakeLoaderState.addUserData, nullptr);
}

TEST_F(PrintFwkAgentManagerTest, DeleteBuildsParametersAndSuccessCommits)
{
    InsertAddedPrinter(systemData, "agent-id", "Renamed Printer", TIMESTAMPED_IPP_URI,
        R"({"driver":"AGENT","agent":{"queueName":"Office_Printer_1786320000",)"
        R"("uri":"ipp://10.0.0.1","backendType":"TEST_BACKEND"}})");

    EXPECT_EQ(manager->DeletePrinterFromAgent("Renamed Printer"), E_PRINT_NONE);
    EXPECT_EQ(g_fakeLoaderState.removeCallCount, 1u);
    EXPECT_EQ(g_fakeLoaderState.name, TIMESTAMPED_QUEUE_NAME);
    EXPECT_EQ(g_fakeLoaderState.backendType, TEST_BACKEND_TYPE);
    ASSERT_NE(g_fakeLoaderState.removeDone, nullptr);
    CompleteRemove(PRINT_FWK_AGENT_CLIENT_OK);

    EXPECT_EQ(g_fakeLoaderState.removeNameReadBeforeAsyncDone, TIMESTAMPED_QUEUE_NAME);
    EXPECT_EQ(g_fakeLoaderState.removeBackendTypeReadBeforeAsyncDone, TEST_BACKEND_TYPE);
    EXPECT_EQ(g_fakeLoaderState.removeNamePtr, nullptr);
    EXPECT_EQ(g_fakeLoaderState.removeBackendTypePtr, nullptr);
    EXPECT_EQ(host.commitAgentPrinterDeletedCount, 1u);
    EXPECT_EQ(host.lastPrinterId, "agent-id");
    EXPECT_EQ(host.lastPrinterName, "Renamed Printer");
}

TEST_F(PrintFwkAgentManagerTest, DeleteSuccessReleasesSourceForLaterReadd)
{
    const std::string sourceUri = "ipp://192.168.1.10:631/printers/office";
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", sourceUri, VALID_AGENT_OPTIONS), E_PRINT_NONE);
    const PrintAddPrinterResult result { TIMESTAMPED_IPP_URI.c_str(), nullptr, 0 };
    CompleteAdd(PRINT_FWK_AGENT_CLIENT_OK, &result);

    PrinterInfo added;
    added.SetPrinterId("agent-id");
    added.SetPrinterName("Office Printer");
    added.SetUri(TIMESTAMPED_IPP_URI);
    ASSERT_TRUE(manager->AttachPendingAgentPrinter(added));
    systemData.InsertAddedPrinter(added.GetPrinterId(), added);

    EXPECT_EQ(manager->DeletePrinterFromAgent(added.GetPrinterName()), E_PRINT_NONE);
    CompleteRemove(PRINT_FWK_AGENT_CLIENT_OK);
    systemData.DeleteAddedPrinter(added.GetPrinterId(), added.GetPrinterName());

    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", sourceUri, VALID_AGENT_OPTIONS), E_PRINT_NONE);
    EXPECT_EQ(g_fakeLoaderState.addCallCount, 2u);
}

TEST_F(PrintFwkAgentManagerTest, DeleteDoneFailureIsIdempotent)
{
    InsertAddedPrinter(systemData, "agent-id", "Office Printer", "ipp://10.0.0.1/printers/office",
        R"({"driver":"AGENT","agent":)"
        R"({"queueName":"Agent_Original_1786320000","backendType":"TEST_BACKEND"}})");

    EXPECT_EQ(manager->DeletePrinterFromAgent("Office Printer"), E_PRINT_NONE);
    CompleteRemove(PRINT_FWK_AGENT_CLIENT_ERR_RPC);

    EXPECT_EQ(host.commitAgentPrinterDeletedCount, 0u);
}

TEST_F(PrintFwkAgentManagerTest, DeleteNotFoundContinuesLocalDeletion)
{
    InsertAddedPrinter(systemData, "agent-id", "Office Printer", "ipp://10.0.0.1/printers/office",
        R"({"driver":"AGENT","agent":)"
        R"({"queueName":"Agent_Original_1786320000","backendType":"TEST_BACKEND"}})");

    EXPECT_EQ(manager->DeletePrinterFromAgent("Office Printer"), E_PRINT_NONE);
    CompleteRemove(PRINT_FWK_AGENT_CLIENT_ERR_NOT_FOUND);

    EXPECT_EQ(host.commitAgentPrinterDeletedCount, 1u);
    EXPECT_EQ(host.lastPrinterId, "agent-id");
    EXPECT_EQ(host.lastPrinterName, "Office Printer");
}

TEST_F(PrintFwkAgentManagerTest, DeleteRejectsInvalidPersistedMetadata)
{
    InsertAddedPrinter(systemData, "missing-id", "Missing Queue", "ipp://10.0.0.1/printers/missing",
        R"({"driver":"AGENT","agent":{"backendType":"TEST_BACKEND"}})");
    InsertAddedPrinter(systemData, "type-id", "Type Queue", "ipp://10.0.0.1/printers/type",
        R"({"driver":"AGENT","agent":{"queueName":123,"backendType":"TEST_BACKEND"}})");
    InsertAddedPrinter(systemData, "empty-id", "Empty Queue", "ipp://10.0.0.1/printers/empty",
        R"({"driver":"AGENT","agent":{"queueName":"","backendType":"TEST_BACKEND"}})");

    InsertAddedPrinter(systemData, "missing-backend-id", "Missing Backend",
        "ipp://10.0.0.1/printers/missing",
        R"({"driver":"AGENT","agent":{"queueName":"Missing_1786320000"}})");
    InsertAddedPrinter(systemData, "type-backend-id", "Type Backend",
        "ipp://10.0.0.1/printers/type",
        R"({"driver":"AGENT","agent":{"queueName":"Type_1786320000","backendType":123}})");
    InsertAddedPrinter(systemData, "empty-backend-id", "Empty Backend",
        "ipp://10.0.0.1/printers/empty",
        R"({"driver":"AGENT","agent":{"queueName":"Empty_1786320000","backendType":""}})");

    EXPECT_EQ(manager->DeletePrinterFromAgent("Missing Queue"), E_PRINT_INVALID_PRINTER);
    EXPECT_EQ(manager->DeletePrinterFromAgent("Type Queue"), E_PRINT_INVALID_PRINTER);
    EXPECT_EQ(manager->DeletePrinterFromAgent("Empty Queue"), E_PRINT_INVALID_PRINTER);
    EXPECT_EQ(manager->DeletePrinterFromAgent("Missing Backend"), E_PRINT_INVALID_PRINTER);
    EXPECT_EQ(manager->DeletePrinterFromAgent("Type Backend"), E_PRINT_INVALID_PRINTER);
    EXPECT_EQ(manager->DeletePrinterFromAgent("Empty Backend"), E_PRINT_INVALID_PRINTER);
    EXPECT_EQ(g_fakeLoaderState.removeCallCount, 0u);
}

TEST_F(PrintFwkAgentManagerTest, DeleteImmediateFailureDoesNotRetainCallback)
{
    InsertAddedPrinter(systemData, "agent-id", "Office Printer", "ipp://10.0.0.1/printers/office",
        R"({"driver":"AGENT","agent":)"
        R"({"queueName":"Agent_Original_1786320000","backendType":"TEST_BACKEND"}})");
    g_fakeLoaderState.removeReturn = PRINT_FWK_AGENT_CLIENT_ERR_RPC;

    EXPECT_EQ(manager->DeletePrinterFromAgent("Office Printer"), E_PRINT_RPC_FAILURE);
    EXPECT_EQ(g_fakeLoaderState.removeCallCount, 1u);
    EXPECT_EQ(g_fakeLoaderState.removeDone, nullptr);
    EXPECT_EQ(g_fakeLoaderState.removeUserData, nullptr);
}

TEST_F(PrintFwkAgentManagerTest, DeleteSynchronousDoneKeepsParametersAliveAndCompletesOnce)
{
    InsertAddedPrinter(systemData, "agent-id", "Office Printer", "ipp://10.0.0.1/printers/office",
        R"({"driver":"AGENT","agent":)"
        R"({"queueName":"Agent_Original_1786320000","backendType":"TEST_BACKEND"}})");
    g_fakeLoaderState.completeRemoveSynchronously = true;

    EXPECT_EQ(manager->DeletePrinterFromAgent("Office Printer"), E_PRINT_NONE);

    EXPECT_EQ(g_fakeLoaderState.removeCallCount, 1u);
    EXPECT_EQ(g_fakeLoaderState.nameReadAfterSyncDone, "Agent_Original_1786320000");
    EXPECT_EQ(g_fakeLoaderState.backendTypeReadAfterSyncDone, TEST_BACKEND_TYPE);
    EXPECT_EQ(g_fakeLoaderState.removeNamePtr, nullptr);
    EXPECT_EQ(g_fakeLoaderState.removeBackendTypePtr, nullptr);
    EXPECT_EQ(host.commitAgentPrinterDeletedCount, 1u);
    EXPECT_EQ(g_fakeLoaderState.removeDone, nullptr);
    EXPECT_EQ(g_fakeLoaderState.removeUserData, nullptr);
}

TEST_F(PrintFwkAgentManagerTest, InvalidUriRejectedBeforeClient)
{
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", "ipp://printer.example/printers/office",
        VALID_AGENT_OPTIONS), E_PRINT_INVALID_PRINTER);
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", "not a uri", VALID_AGENT_OPTIONS),
        E_PRINT_INVALID_PRINTER);
    EXPECT_EQ(g_fakeLoaderState.addCallCount, 0u);
}

TEST_F(PrintFwkAgentManagerTest, AddRejectsInvalidAgentOptionsBeforeClient)
{
    const std::string uri = "ipp://192.168.1.10:631/printers/office";
    EXPECT_EQ(manager->AddPrinterViaAgent(
        "Office Printer", uri, R"({"driver":"AGENT"})"), E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(manager->AddPrinterViaAgent(
        "Office Printer", uri, R"({"driver":"AGENT","agentBackendType":123})"),
        E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(manager->AddPrinterViaAgent(
        "Office Printer", uri, R"({"driver":"AGENT","agentBackendType":""})"),
        E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(manager->AddPrinterViaAgent(
        "Office Printer", uri,
        R"({"driver":"AGENT","agentBackendType":"TEST_BACKEND","agentDriverInstall":"invalid"})"),
        E_PRINT_INVALID_PARAMETER);
    EXPECT_EQ(g_fakeLoaderState.addCallCount, 0u);
}

TEST_F(PrintFwkAgentManagerTest, AddImmediateFailureDoesNotRetainCallback)
{
    g_fakeLoaderState.addReturn = PRINT_FWK_AGENT_CLIENT_ERR_RPC;
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", "ipp://192.168.1.10:631/printers/office",
        VALID_AGENT_OPTIONS), E_PRINT_RPC_FAILURE);
    EXPECT_EQ(g_fakeLoaderState.addDone, nullptr);
    EXPECT_EQ(g_fakeLoaderState.addUserData, nullptr);
}

TEST_F(PrintFwkAgentManagerTest, AddProgressNotifiesHost)
{
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", "ipp://192.168.1.10:631/printers/office",
        VALID_AGENT_OPTIONS), E_PRINT_NONE);
    ASSERT_NE(g_fakeLoaderState.addProgress, nullptr);
    g_fakeLoaderState.addProgress(PRINT_AGENT_PROGRESS_INSTALLING_DRIVER, g_fakeLoaderState.addUserData);

    EXPECT_EQ(host.notifyPrinterInfoChangedCount, 1u);
    EXPECT_TRUE(host.lastInfo.GetPrinterId().empty());
    EXPECT_EQ(host.lastInfo.GetPrinterName(), "Office Printer");
    EXPECT_EQ(host.lastInfo.GetPrinterState(), PRINTER_UNKNOWN);
    Json::Value option = GetOption(host.lastInfo);
    EXPECT_EQ(option["driver"].asString(), PRINT_DRIVER_AGENT);
    Json::Value progress = GetAgentAddProgress(host.lastInfo);
    EXPECT_EQ(progress["stage"].asString(), "INSTALLING_DRIVER");
    EXPECT_EQ(progress["status"].asString(), "RUNNING");
    CompleteAdd(PRINT_FWK_AGENT_CLIENT_ERR_RPC);
}

TEST_F(PrintFwkAgentManagerTest, AddDoneFailureNotifiesOriginalAgentErrorAndClears)
{
    struct ErrorCase {
        int32_t errorCode;
        const char *errorMessage;
    };
    const std::vector<ErrorCase> errorCases {
        { PRINT_FWK_AGENT_CLIENT_ERR_NO_PACKAGE_MGR, "No package manager" },
        { PRINT_FWK_AGENT_CLIENT_ERR_INSTALL_FAILED, "Driver install failed" },
        { PRINT_FWK_AGENT_CLIENT_ERR_INSTALL_BUSY, "Driver install busy" },
        { PRINT_FWK_AGENT_CLIENT_ERR_TIMEOUT, "Operation timeout" },
    };

    for (const auto &errorCase : errorCases) {
        EXPECT_EQ(manager->AddPrinterViaAgent(
            "Office Printer", "ipp://192.168.1.10:631/printers/office", VALID_AGENT_OPTIONS),
            E_PRINT_NONE);
        CompleteAdd(errorCase.errorCode);

        EXPECT_TRUE(host.lastInfo.GetPrinterId().empty());
        EXPECT_EQ(host.lastInfo.GetPrinterName(), "Office Printer");
        EXPECT_EQ(host.lastInfo.GetPrinterState(), PRINTER_UNKNOWN);
        Json::Value option = GetOption(host.lastInfo);
        EXPECT_EQ(option["driver"].asString(), PRINT_DRIVER_AGENT);
        Json::Value progress = GetAgentAddProgress(host.lastInfo);
        EXPECT_EQ(progress["stage"].asString(), "ENV_INIT");
        EXPECT_EQ(progress["status"].asString(), "FAILED");
        EXPECT_EQ(progress["errorCode"].asInt(), errorCase.errorCode);
        EXPECT_EQ(progress["errorMsg"].asString(), errorCase.errorMessage);
    }
    EXPECT_EQ(host.notifyPrinterInfoChangedCount, errorCases.size());
}

TEST_F(PrintFwkAgentManagerTest, AddDoneSuccessCopiesCallbackResultAndNotifiesPendingDiscovery)
{
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", "ipp://192.168.1.10:631/printers/office",
        VALID_AGENT_OPTIONS), E_PRINT_NONE);
    const std::string ippUri = TIMESTAMPED_IPP_URI;
    {
        const std::string callbackIppUri = ippUri;
        const PrintAddPrinterResult result { callbackIppUri.c_str(), nullptr, 0 };
        CompleteAdd(PRINT_FWK_AGENT_CLIENT_OK, &result);
    }

    EXPECT_EQ(host.notifyPrinterInfoChangedCount, 1u);
    EXPECT_TRUE(host.lastInfo.GetPrinterId().empty());
    EXPECT_EQ(host.lastInfo.GetPrinterName(), "Office Printer");
    EXPECT_EQ(host.lastInfo.GetUri(), ippUri);
    EXPECT_EQ(host.lastInfo.GetPrinterState(), PRINTER_UNKNOWN);
    Json::Value option = GetOption(host.lastInfo);
    EXPECT_EQ(option["driver"].asString(), PRINT_DRIVER_AGENT);
    Json::Value progress = GetAgentAddProgress(host.lastInfo);
    EXPECT_EQ(progress["stage"].asString(), "DONE");
    EXPECT_EQ(progress["status"].asString(), "PENDING_DISCOVERY");
    EXPECT_TRUE(systemData.QueryAddedPrinterIdList().empty());
    PrinterInfo claimedPrinter;
    EXPECT_TRUE(ClaimPendingPrinter(*manager, ippUri, &claimedPrinter));
    EXPECT_EQ(claimedPrinter.GetPrinterName(), "Office Printer");
}

TEST_F(PrintFwkAgentManagerTest, AddDoneMissingUriReportsServerFailure)
{
    const PrintAddPrinterResult nullUri { nullptr, nullptr, 0 };
    const PrintAddPrinterResult emptyUri { "", "drv:///unused.ppd", 0 };
    const std::vector<const PrintAddPrinterResult *> invalidResults = { nullptr, &nullUri, &emptyUri };
    for (const auto *result : invalidResults) {
        EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer",
            "ipp://192.168.1.10:631/printers/office", VALID_AGENT_OPTIONS), E_PRINT_NONE);
        CompleteAdd(PRINT_FWK_AGENT_CLIENT_OK, result);

        Json::Value progress = GetAgentAddProgress(host.lastInfo);
        EXPECT_EQ(progress["stage"].asString(), "DONE");
        EXPECT_EQ(progress["status"].asString(), "FAILED");
        EXPECT_EQ(progress["errorCode"].asInt(), PRINT_FWK_AGENT_CLIENT_ERR_SERVER);
        EXPECT_EQ(progress["errorMsg"].asString(), "Server error");
        EXPECT_TRUE(manager->pendingPrinters_.empty());
    }
}

TEST_F(PrintFwkAgentManagerTest, AddDoneInvalidQueueUriReportsServerFailureAndReleasesSource)
{
    const std::string sourceUri = "ipp://192.168.1.10:631/printers/office";
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", sourceUri, VALID_AGENT_OPTIONS), E_PRINT_NONE);
    const std::string invalidQueueUri = "ipp://10.0.0.2:631/not-printers/Office_Printer_1786320000";
    const PrintAddPrinterResult result { invalidQueueUri.c_str(), nullptr, 0 };
    CompleteAdd(PRINT_FWK_AGENT_CLIENT_OK, &result);

    Json::Value progress = GetAgentAddProgress(host.lastInfo);
    EXPECT_EQ(progress["status"].asString(), "FAILED");
    EXPECT_EQ(progress["errorCode"].asInt(), PRINT_FWK_AGENT_CLIENT_ERR_SERVER);
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", sourceUri, VALID_AGENT_OPTIONS), E_PRINT_NONE);
    EXPECT_EQ(g_fakeLoaderState.addCallCount, 2u);
}

TEST_F(PrintFwkAgentManagerTest, PendingAgentPrinterExpiresAfterThirtySeconds)
{
    const std::string ippUri = "ipp://10.0.0.2:631/printers/office";
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", "ipp://192.168.1.10:631/printers/office",
        VALID_AGENT_OPTIONS), E_PRINT_NONE);
    const PrintAddPrinterResult result { ippUri.c_str(), nullptr, 0 };
    CompleteAdd(PRINT_FWK_AGENT_CLIENT_OK, &result);

    now += PENDING_TIMEOUT;
    EXPECT_FALSE(ClaimPendingPrinter(*manager, ippUri));
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", "ipp://192.168.1.10:631/printers/office",
        VALID_AGENT_OPTIONS), E_PRINT_NONE);
    EXPECT_EQ(g_fakeLoaderState.addCallCount, 2u);
}

TEST_F(PrintFwkAgentManagerTest, DuplicateInFlightSourceReplaysLatestProgressWithoutSubmission)
{
    const std::string sourceUri = "ipp://192.168.1.10:631/printers/office";
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", sourceUri, VALID_AGENT_OPTIONS), E_PRINT_NONE);
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", sourceUri, VALID_AGENT_OPTIONS), E_PRINT_NONE);

    EXPECT_EQ(g_fakeLoaderState.addCallCount, 1u);
    EXPECT_EQ(g_fakeLoaderState.ensureBackendReadyCallCount, 1u);
    EXPECT_EQ(host.notifyPrinterInfoChangedCount, 1u);
    Json::Value progress = GetAgentAddProgress(host.lastInfo);
    EXPECT_EQ(progress["stage"].asString(), "ENV_INIT");
    EXPECT_EQ(progress["status"].asString(), "RUNNING");
    EXPECT_FALSE(progress.isMember("errorCode"));

    g_fakeLoaderState.addProgress(PRINT_AGENT_PROGRESS_INSTALLING_DRIVER, g_fakeLoaderState.addUserData);
    EXPECT_EQ(manager->AddPrinterViaAgent("Changed Name", sourceUri, VALID_AGENT_OPTIONS), E_PRINT_NONE);

    EXPECT_EQ(g_fakeLoaderState.addCallCount, 1u);
    EXPECT_EQ(host.notifyPrinterInfoChangedCount, 3u);
    EXPECT_EQ(host.lastInfo.GetPrinterName(), "Office Printer");
    progress = GetAgentAddProgress(host.lastInfo);
    EXPECT_EQ(progress["stage"].asString(), "INSTALLING_DRIVER");
    EXPECT_EQ(progress["status"].asString(), "RUNNING");
}

TEST_F(PrintFwkAgentManagerTest, DuplicatePendingSourceReplaysDiscoveryUsingEquivalentDefaultPortForm)
{
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", "ipp://192.168.1.10/printers/office",
        VALID_AGENT_OPTIONS), E_PRINT_NONE);
    const PrintAddPrinterResult result { TIMESTAMPED_IPP_URI.c_str(), nullptr, 0 };
    CompleteAdd(PRINT_FWK_AGENT_CLIENT_OK, &result);

    EXPECT_EQ(manager->AddPrinterViaAgent("Changed Name", "ipp://192.168.1.10:631/printers/office",
        VALID_AGENT_OPTIONS), E_PRINT_NONE);
    EXPECT_EQ(g_fakeLoaderState.addCallCount, 1u);
    EXPECT_EQ(host.notifyPrinterInfoChangedCount, 2u);
    EXPECT_EQ(host.lastInfo.GetPrinterName(), "Office Printer");
    EXPECT_EQ(host.lastInfo.GetUri(), TIMESTAMPED_IPP_URI);
    Json::Value progress = GetAgentAddProgress(host.lastInfo);
    EXPECT_EQ(progress["stage"].asString(), "DONE");
    EXPECT_EQ(progress["status"].asString(), "PENDING_DISCOVERY");
    EXPECT_FALSE(progress.isMember("errorCode"));
}

TEST_F(PrintFwkAgentManagerTest, DuplicatePersistedSourceNotifiesPrinterExists)
{
    InsertAddedPrinter(systemData, "agent-id", "Office Printer", TIMESTAMPED_IPP_URI,
        R"({"driver":"AGENT","agent":)"
        R"({"queueName":"Office_Printer_1786320000",)"
        R"("sourceUri":"ipp://192.168.1.10:631/printers/office",)"
        R"("backendType":"TEST_BACKEND"}})");

    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", "ipp://192.168.1.10/printers/office",
        VALID_AGENT_OPTIONS), E_PRINT_NONE);
    EXPECT_EQ(g_fakeLoaderState.addCallCount, 0u);
    EXPECT_EQ(GetAgentAddProgress(host.lastInfo)["errorCode"].asInt(),
        PRINT_FWK_AGENT_CLIENT_ERR_PRINTER_EXISTS);
}

TEST_F(PrintFwkAgentManagerTest, ClaimPendingAgentPrinterExtendsConnectingWindow)
{
    const std::string ippUri = "ipp://10.0.0.2:631/printers/office";
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", "ipp://192.168.1.10:631/printers/office",
        VALID_AGENT_OPTIONS), E_PRINT_NONE);
    const PrintAddPrinterResult result { ippUri.c_str(), nullptr, 0 };
    CompleteAdd(PRINT_FWK_AGENT_CLIENT_OK, &result);

    now += BEFORE_PENDING_TIMEOUT;
    EXPECT_TRUE(ClaimPendingPrinter(*manager, ippUri));
    now += BEFORE_PENDING_TIMEOUT;
    PrinterInfo info;
    info.SetUri(ippUri);
    EXPECT_TRUE(manager->AttachPendingAgentPrinter(info));
}

TEST_F(PrintFwkAgentManagerTest, DefaultIppPortFormsBuildEquivalentKeys)
{
    const std::vector<std::pair<std::string, std::string>> uriPairs = {
        { "ipp://10.0.0.2/printers/implicit", "ipp://10.0.0.2:631/printers/implicit" },
        { "ipp://10.0.0.2:631/printers/explicit", "ipp://10.0.0.2/printers/explicit" },
        { "ipps://10.0.0.2/printers/secure", "ipps://10.0.0.2:631/printers/secure" },
        { "ipp://[2001:db8::1]/printers/ipv6", "ipp://[2001:db8::1]:631/printers/ipv6" },
    };

    for (const auto &[implicitUri, explicitUri] : uriPairs) {
        SCOPED_TRACE(implicitUri);
        EXPECT_EQ(PrintFwkAgentManager::BuildUriMatchKey(implicitUri),
            PrintFwkAgentManager::BuildUriMatchKey(explicitUri));
    }
}

TEST_F(PrintFwkAgentManagerTest, PendingQueueNameFallbackMatchesDifferentAddressFamily)
{
    const std::string agentUri = "ipp://10.0.0.2/printers/office";
    const std::string discoveryUri = "ipp://[2001:db8::2]:631/printers/office";
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", "ipp://192.168.1.10:631/printers/office",
        VALID_AGENT_OPTIONS), E_PRINT_NONE);
    const PrintAddPrinterResult result { agentUri.c_str(), nullptr, 0 };
    CompleteAdd(PRINT_FWK_AGENT_CLIENT_OK, &result);

    EXPECT_TRUE(ClaimPendingPrinter(*manager, discoveryUri));
    PrinterInfo differentPath;
    differentPath.SetUri("ipp://10.0.0.2:631/printers/other");
    EXPECT_FALSE(manager->AttachPendingAgentPrinter(differentPath));

    PrinterInfo discovered;
    discovered.SetUri(discoveryUri);
    EXPECT_TRUE(manager->AttachPendingAgentPrinter(discovered));
    EXPECT_EQ(discovered.GetUri(), discoveryUri);
    Json::Value option = GetOption(discovered);
    EXPECT_EQ(option["agent"]["queueName"].asString(), "office");
    EXPECT_EQ(option["agent"]["queueUri"].asString(), agentUri);
}

TEST_F(PrintFwkAgentManagerTest, AttachPendingAgentPrinterPreservesOptionsUntilPersistenceConfirmed)
{
    const std::string ippUri = TIMESTAMPED_IPP_URI;
    const std::string sourceUri = "ipp://192.168.1.10:631/printers/office";
    EXPECT_EQ(manager->AddPrinterViaAgent("Agent Original", sourceUri,
        VALID_AGENT_OPTIONS), E_PRINT_NONE);
    const PrintAddPrinterResult result { ippUri.c_str(), nullptr, 0 };
    CompleteAdd(PRINT_FWK_AGENT_CLIENT_OK, &result);

    PrinterInfo unrelated;
    unrelated.SetUri("ipp://10.0.0.3:631/printers/other");
    EXPECT_FALSE(manager->AttachPendingAgentPrinter(unrelated));

    const std::string discoveryUri =
        std::string("ipp://[2001:db8::2]:631/printers/") + TIMESTAMPED_QUEUE_NAME;
    PrinterInfo info;
    info.SetUri(discoveryUri);
    info.SetOption(R"({"ipp":"original","duplex":true})");
    EXPECT_TRUE(manager->AttachPendingAgentPrinter(info));
    EXPECT_EQ(info.GetUri(), discoveryUri);
    Json::Value option = GetOption(info);
    EXPECT_EQ(option["ipp"].asString(), "original");
    EXPECT_TRUE(option["duplex"].asBool());
    EXPECT_EQ(option["driver"].asString(), PRINT_DRIVER_AGENT);
    EXPECT_FALSE(option["agent"].isMember("printerName"));
    EXPECT_EQ(option["agent"]["queueName"].asString(), TIMESTAMPED_QUEUE_NAME);
    EXPECT_EQ(option["agent"]["uri"].asString(), ippUri);
    EXPECT_EQ(option["agent"]["queueUri"].asString(), ippUri);
    EXPECT_EQ(option["agent"]["sourceUri"].asString(), sourceUri);
    EXPECT_EQ(option["agent"]["backendType"].asString(), TEST_BACKEND_TYPE);
    PrinterInfo mismatchedPersisted;
    mismatchedPersisted.SetOption(
        R"({"driver":"AGENT","agent":{"queueName":"other",)"
        R"("sourceUri":"ipp://192.168.1.10:631/printers/office",)"
        R"("backendType":"TEST_BACKEND"}})");
    manager->ConfirmAgentPrinterPersisted(mismatchedPersisted);
    EXPECT_EQ(manager->AddPrinterViaAgent("Reopened Process", sourceUri, VALID_AGENT_OPTIONS), E_PRINT_NONE);
    EXPECT_EQ(g_fakeLoaderState.addCallCount, 1u);
    manager->ConfirmAgentPrinterPersisted(info);
    EXPECT_EQ(manager->AddPrinterViaAgent("Reopened Process", sourceUri, VALID_AGENT_OPTIONS), E_PRINT_NONE);
    EXPECT_EQ(g_fakeLoaderState.addCallCount, 2u);

    PrinterInfo repeated;
    repeated.SetUri(discoveryUri);
    EXPECT_FALSE(manager->AttachPendingAgentPrinter(repeated));
}

TEST_F(PrintFwkAgentManagerTest, PendingQueueNameFallbackRejectsAmbiguousCandidates)
{
    const std::string firstAgentUri = "ipp://10.0.0.2:631/printers/shared";
    const std::string secondAgentUri = "ipp://10.0.0.3:631/printers/shared";
    EXPECT_EQ(manager->AddPrinterViaAgent("First Printer",
        "ipp://192.168.1.10:631/printers/first", VALID_AGENT_OPTIONS), E_PRINT_NONE);
    const PrintAddPrinterResult firstResult { firstAgentUri.c_str(), nullptr, 0 };
    CompleteAdd(PRINT_FWK_AGENT_CLIENT_OK, &firstResult);
    EXPECT_EQ(manager->AddPrinterViaAgent("Second Printer",
        "ipp://192.168.1.11:631/printers/second", VALID_AGENT_OPTIONS), E_PRINT_NONE);
    const PrintAddPrinterResult secondResult { secondAgentUri.c_str(), nullptr, 0 };
    CompleteAdd(PRINT_FWK_AGENT_CLIENT_OK, &secondResult);

    const std::string ambiguousUri = "ipp://[2001:db8::2]:631/printers/shared";
    EXPECT_FALSE(ClaimPendingPrinter(*manager, ambiguousUri));
    PrinterInfo ambiguous;
    ambiguous.SetUri(ambiguousUri);
    EXPECT_FALSE(manager->AttachPendingAgentPrinter(ambiguous));
    EXPECT_EQ(manager->pendingPrinters_.size(), 2u);

    EXPECT_TRUE(ClaimPendingPrinter(*manager, firstAgentUri));
    PrinterInfo exact;
    exact.SetUri(firstAgentUri);
    EXPECT_TRUE(manager->AttachPendingAgentPrinter(exact));
    EXPECT_EQ(GetOption(exact)["agent"]["sourceUri"].asString(),
        "ipp://192.168.1.10:631/printers/first");
}

TEST_F(PrintFwkAgentManagerTest, SameUriSuccessOverwritesPendingSource)
{
    const std::string ippUri = "ipp://10.0.0.2:631/printers/office";
    const PrintAddPrinterResult result { ippUri.c_str(), nullptr, 0 };
    const std::string firstOptions =
        R"({"driver":"AGENT","agentBackendType":"FIRST_BACKEND"})";
    const std::string secondOptions =
        R"({"driver":"AGENT","agentBackendType":"SECOND_BACKEND"})";
    EXPECT_EQ(manager->AddPrinterViaAgent("First Name", "ipp://192.168.1.10:631/printers/first", firstOptions),
        E_PRINT_NONE);
    CompleteAdd(PRINT_FWK_AGENT_CLIENT_OK, &result);
    now += PENDING_REPLACEMENT_DELAY;
    EXPECT_EQ(manager->AddPrinterViaAgent("Second Name", "ipp://192.168.1.11:631/printers/second", secondOptions),
        E_PRINT_NONE);
    CompleteAdd(PRINT_FWK_AGENT_CLIENT_OK, &result);

    now += BEFORE_PENDING_TIMEOUT;
    PrinterInfo info;
    info.SetUri(ippUri);
    EXPECT_TRUE(manager->AttachPendingAgentPrinter(info));
    Json::Value option = GetOption(info);
    EXPECT_FALSE(option["agent"].isMember("printerName"));
    EXPECT_EQ(option["agent"]["queueName"].asString(), "office");
    EXPECT_EQ(option["agent"]["backendType"].asString(), "SECOND_BACKEND");
    EXPECT_EQ(option["agent"]["sourceUri"].asString(),
        "ipp://192.168.1.11:631/printers/second");
}

TEST_F(PrintFwkAgentManagerTest, PendingCapacityIncludesInFlightRequests)
{
    for (size_t index = 0; index < MAX_PENDING_AGENT_PRINTERS; ++index) {
        EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer",
            "ipp://192.168.1.10:631/printers/office-" + std::to_string(index),
            VALID_AGENT_OPTIONS), E_PRINT_NONE);
    }

    EXPECT_EQ(g_fakeLoaderState.addCallCount, MAX_PENDING_AGENT_PRINTERS);
    EXPECT_EQ(manager->AddPrinterViaAgent("Overflow Printer",
        "ipp://192.168.1.11:631/printers/overflow", VALID_AGENT_OPTIONS), E_PRINT_SERVER_FAILURE);
    EXPECT_EQ(g_fakeLoaderState.addCallCount, MAX_PENDING_AGENT_PRINTERS);
    EXPECT_EQ(g_fakeLoaderState.ensureBackendReadyCallCount, MAX_PENDING_AGENT_PRINTERS);
}

TEST_F(PrintFwkAgentManagerTest, BackendReadyFailureReleasesSourceReservation)
{
    const std::string sourceUri = "ipp://192.168.1.10:631/printers/office";
    g_fakeLoaderState.ensureBackendReadyReturn = PRINT_FWK_AGENT_CLIENT_BACKEND_STOPPED;
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", sourceUri, VALID_AGENT_OPTIONS),
        E_PRINT_RPC_FAILURE);

    g_fakeLoaderState.ensureBackendReadyReturn = PRINT_FWK_AGENT_CLIENT_OK;
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", sourceUri, VALID_AGENT_OPTIONS), E_PRINT_NONE);
    EXPECT_EQ(g_fakeLoaderState.ensureBackendReadyCallCount, 2u);
    EXPECT_EQ(g_fakeLoaderState.addCallCount, 1u);
}

TEST_F(PrintFwkAgentManagerTest, ConcurrentAddsDoNotChangeVendorConnectingContext)
{
    vendorManager.SetConnectingPrinterName("Existing Printer");
    vendorManager.SetConnectingPrinter(IP_AUTO, "192.168.1.20");

    EXPECT_EQ(manager->AddPrinterViaAgent("First Printer",
        "ipp://192.168.1.10:631/printers/first", VALID_AGENT_OPTIONS), E_PRINT_NONE);
    EXPECT_EQ(manager->AddPrinterViaAgent("Second Printer",
        "ipp://192.168.1.11:631/printers/second", VALID_AGENT_OPTIONS), E_PRINT_NONE);
    CompleteAdd(PRINT_FWK_AGENT_CLIENT_ERR_RPC);

    EXPECT_EQ(vendorManager.GetConnectingPrinterName(), "Existing Printer");
    EXPECT_EQ(vendorManager.GetConnectingPrinter(), "192.168.1.20");
}

TEST_F(PrintFwkAgentManagerTest, ImmediateFailureReleasesPendingCapacity)
{
    g_fakeLoaderState.addReturn = PRINT_FWK_AGENT_CLIENT_ERR_RPC;
    EXPECT_EQ(manager->AddPrinterViaAgent("Rejected Printer",
        "ipp://192.168.1.10:631/printers/rejected", VALID_AGENT_OPTIONS), E_PRINT_RPC_FAILURE);

    g_fakeLoaderState.addReturn = PRINT_FWK_AGENT_CLIENT_OK;
    for (size_t index = 0; index < MAX_PENDING_AGENT_PRINTERS; ++index) {
        EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer",
            "ipp://192.168.1.10:631/printers/office-" + std::to_string(index),
            VALID_AGENT_OPTIONS), E_PRINT_NONE);
    }
}

TEST_F(PrintFwkAgentManagerTest, ConcurrentAttachConsumesPendingOnlyOnce)
{
    const std::string agentUri = "ipp://10.0.0.2/printers/office";
    const std::string discoveryUri = "ipp://10.0.0.2:631/printers/office";
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", "ipp://192.168.1.10:631/printers/office",
        VALID_AGENT_OPTIONS), E_PRINT_NONE);
    const PrintAddPrinterResult result { agentUri.c_str(), nullptr, 0 };
    CompleteAdd(PRINT_FWK_AGENT_CLIENT_OK, &result);

    std::atomic<uint32_t> successCount { 0 };
    auto attach = [this, &successCount](const std::string &uri) {
        PrinterInfo info;
        info.SetUri(uri);
        if (manager->AttachPendingAgentPrinter(info)) {
            ++successCount;
        }
    };
    std::thread first(attach, agentUri);
    std::thread second(attach, discoveryUri);
    first.join();
    second.join();

    EXPECT_EQ(successCount.load(), 1U);
}

TEST_F(PrintFwkAgentManagerTest, ShutdownStopsPendingAddBusinessSubmission)
{
    EXPECT_EQ(manager->AddPrinterViaAgent("Office Printer", "ipp://192.168.1.10:631/printers/office",
        VALID_AGENT_OPTIONS), E_PRINT_NONE);
    ASSERT_NE(g_fakeLoaderState.addDone, nullptr);

    manager->Shutdown();

    EXPECT_EQ(g_fakeLoaderState.destroyCount, 1u);
    ASSERT_NE(g_fakeLoaderState.addDone, nullptr);
    const std::string ippUri = "ipp://10.0.0.2:631/printers/office";
    const PrintAddPrinterResult result { ippUri.c_str(), nullptr, 0 };
    CompleteAdd(PRINT_FWK_AGENT_CLIENT_OK, &result);

    EXPECT_EQ(host.notifyPrinterInfoChangedCount, 0u);
    EXPECT_EQ(g_fakeLoaderState.addDone, nullptr);
    EXPECT_EQ(g_fakeLoaderState.addProgress, nullptr);
    EXPECT_EQ(g_fakeLoaderState.addUserData, nullptr);
    EXPECT_FALSE(ClaimPendingPrinter(*manager, ippUri));
}

TEST_F(PrintFwkAgentManagerTest, ShutdownStopsPendingRemoveBusinessSubmission)
{
    InsertAddedPrinter(systemData, "agent-id", "Office Printer", "ipp://10.0.0.1/printers/office",
        R"({"driver":"AGENT","agent":)"
        R"({"queueName":"Agent_Original_1786320000","backendType":"TEST_BACKEND"}})");
    EXPECT_EQ(manager->DeletePrinterFromAgent("Office Printer"), E_PRINT_NONE);
    ASSERT_NE(g_fakeLoaderState.removeDone, nullptr);

    manager->Shutdown();

    EXPECT_EQ(g_fakeLoaderState.destroyCount, 1u);
    ASSERT_NE(g_fakeLoaderState.removeDone, nullptr);
    CompleteRemove(PRINT_FWK_AGENT_CLIENT_OK);

    EXPECT_EQ(host.commitAgentPrinterDeletedCount, 0u);
    EXPECT_EQ(g_fakeLoaderState.removeDone, nullptr);
    EXPECT_EQ(g_fakeLoaderState.removeUserData, nullptr);
}

TEST(PrintFwkAgentManagerLifecycleTest, RepeatedShutdownUnloadsInjectedLoaderOnlyOnce)
{
    auto &manager = PrintFwkAgentManager::GetInstance();
    manager.Shutdown();
    ResetFakeLoaderState();
    auto api = CreateFakeLoaderApi();
    auto loader = std::make_unique<PrintFwkAgentClientLoader>();
    loader->SetApiForTest(&api, &g_fakeClient);

    PrintSystemData systemData;
    FakeAgentHost host;
    EXPECT_TRUE(manager.Init(systemData, host,
        [](PrintFwkAgentManager::DelayedTask, const std::string &, int64_t) { return true; },
        std::move(loader)));
    EXPECT_TRUE(manager.IsRunning());
    EXPECT_EQ(&manager, &PrintFwkAgentManager::GetInstance());

    manager.Shutdown();
    manager.Shutdown();
    EXPECT_EQ(g_fakeLoaderState.destroyCount, 1u);
}
