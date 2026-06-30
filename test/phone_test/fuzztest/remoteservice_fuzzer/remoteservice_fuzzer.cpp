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

#define private public
#define protected public
#include "remoteservice_fuzzer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "print_constant.h"
#include "print_log.h"
#include "remote_constants.h"
#include "singleton.h"
#include <functional>

namespace OHOS::Print {

constexpr uint8_t MAX_STRING_LENGTH = 20;
constexpr int MAX_SET_NUMBER = 128;
constexpr size_t U32_AT_SIZE = 4;

void TestRemoteServiceAdapterBindService(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto& adapter = RemoteServiceAdapter::GetInstance();
    adapter.BindService();
}

void TestRemoteServiceAdapterIsConnected(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto& adapter = RemoteServiceAdapter::GetInstance();
    adapter.IsConnected();
}

void TestRemoteServiceAdapterSendData(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto& adapter = RemoteServiceAdapter::GetInstance();
    uint32_t code = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    std::string msg = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    adapter.SendData(code, msg);
}

void TestRemoteServiceAdapterRequestPrinterStatus(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto& adapter = RemoteServiceAdapter::GetInstance();
    std::string devId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    adapter.RequestPrinterStatus(devId);
}

void TestRemoteServiceAdapterRequestPrinterList(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto& adapter = RemoteServiceAdapter::GetInstance();
    adapter.RequestPrinterList();
}

void TestRemoteServiceAdapterSetOnServiceDiedCallback(
    const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto& adapter = RemoteServiceAdapter::GetInstance();
    bool callbackCalled = false;
    adapter.SetOnServiceDiedCallback([&callbackCalled]() {
        callbackCalled = true;
    });
}

void TestRemoteServiceAdapterOnRemoteServiceDied(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto& adapter = RemoteServiceAdapter::GetInstance();
    adapter.OnRemoteServiceDied();
}

void TestRemotePrinterManagerStartDiscovery(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto manager = DelayedSingleton<RemotePrinterManager>::GetInstance();
    manager->StartPrinterDiscovery();
}

void TestRemotePrinterManagerStopDiscovery(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto manager = DelayedSingleton<RemotePrinterManager>::GetInstance();
    manager->StopPrinterDiscovery();
}

void TestRemotePrinterManagerGetPrinterInfo(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto manager = DelayedSingleton<RemotePrinterManager>::GetInstance();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    manager->GetPrinterInfo(printerId);
}

void TestRemotePrinterManagerUpdateStatus(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto manager = DelayedSingleton<RemotePrinterManager>::GetInstance();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterStatus status =
        static_cast<PrinterStatus>(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    manager->UpdatePrinterStatus(printerId, status);
}

void TestRemotePrinterManagerClearAllPrinters(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto manager = DelayedSingleton<RemotePrinterManager>::GetInstance();
    manager->ClearAllPrinters();
}

void TestRemotePrinterManagerConvertStatus(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string statusStr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    RemotePrinterManager::ConvertStatusToPrinterStatus(statusStr);
}

void TestPrintIpcConnectionIsConnected(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintIpcConnection connection;
    connection.IsConnected();
}

void TestPrintIpcConnectionGetRemoteObject(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintIpcConnection connection;
    connection.GetRemoteObject();
}

void TestPrintIpcConnectionWaitForConnection(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintIpcConnection connection;
    int32_t timeoutMs = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    connection.WaitForConnection(timeoutMs);
}

void TestAllFunction(const uint8_t *data, size_t size)
{
    PRINT_HILOGI("Multithreading is running at function TestAllFunction.");
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &TestRemoteServiceAdapterBindService,
        &TestRemoteServiceAdapterIsConnected,
        &TestRemoteServiceAdapterSendData,
        &TestRemoteServiceAdapterRequestPrinterStatus,
        &TestRemoteServiceAdapterRequestPrinterList,
        &TestRemoteServiceAdapterSetOnServiceDiedCallback,
        &TestRemoteServiceAdapterOnRemoteServiceDied,
        &TestRemotePrinterManagerStartDiscovery,
        &TestRemotePrinterManagerStopDiscovery,
        &TestRemotePrinterManagerGetPrinterInfo,
        &TestRemotePrinterManagerUpdateStatus,
        &TestRemotePrinterManagerClearAllPrinters,
        &TestRemotePrinterManagerConvertStatus,
        &TestPrintIpcConnectionIsConnected,
        &TestPrintIpcConnectionGetRemoteObject,
        &TestPrintIpcConnectionWaitForConnection,
    };

    FuzzedDataProvider dataProvider(data, size);
    auto taskIndex = dataProvider.ConsumeIntegralInRange<size_t>(0, sizeof(tasks) / sizeof(tasks[0]) - 1);
    tasks[taskIndex](data, size, &dataProvider);
}

void RemoteServiceFuzzer::TestRemoteServiceAdapter(const uint8_t *data, size_t size)
{
    TestAllFunction(data, size);
}

void RemoteServiceFuzzer::TestRemotePrinterManager(const uint8_t *data, size_t size)
{
    TestAllFunction(data, size);
}

void RemoteServiceFuzzer::TestRemoteCallbackStub(const uint8_t *data, size_t size)
{
    TestAllFunction(data, size);
}

void RemoteServiceFuzzer::TestPrintIpcConnection(const uint8_t *data, size_t size)
{
    TestAllFunction(data, size);
}

} // namespace OHOS::Print

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::Print::RemoteServiceFuzzer::TestRemoteServiceAdapter(data, size);
    OHOS::Print::RemoteServiceFuzzer::TestRemotePrinterManager(data, size);
    OHOS::Print::RemoteServiceFuzzer::TestRemoteCallbackStub(data, size);
    OHOS::Print::RemoteServiceFuzzer::TestPrintIpcConnection(data, size);
    return 0;
}