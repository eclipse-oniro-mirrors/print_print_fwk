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
#include "print_json_util.h"
#include "remote_constants.h"
#include "singleton.h"
#include "ipc_object_stub.h"
#include "json/json.h"
#include "message_parcel.h"
#include "message_option.h"
#include "element_name.h"
#include "printer_info.h"
#include <functional>
#include <vector>

namespace OHOS::Print {

constexpr uint8_t MAX_STRING_LENGTH = 64;
constexpr int MAX_SET_NUMBER = 128;
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr int MAX_PRINTER_COUNT = 5;

using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;

void WriteCallbackInterfaceToken(MessageParcel &datas)
{
    auto stub = sptr<RemoteCallbackStub>::MakeSptr();
    datas.WriteInterfaceToken(stub->GetDescriptor());
}

Json::Value BuildRandomPrinterJson(FuzzedDataProvider *dataProvider)
{
    Json::Value item(Json::objectValue);
    if (dataProvider->ConsumeBool()) {
        item["devId"] = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    }
    if (dataProvider->ConsumeBool()) {
        item["devName"] = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    }
    uint8_t statusChoice = dataProvider->ConsumeIntegralInRange<uint8_t>(0, 3);
    if (statusChoice == 0) {
        item["status"] = REMOTE_STATUS_ONLINE;
    } else if (statusChoice == 1) {
        item["status"] = REMOTE_STATUS_OFFLINE;
    } else if (statusChoice == 2) {
        item["status"] = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    }
    uint8_t devInfoChoice = dataProvider->ConsumeIntegralInRange<uint8_t>(0, 2);
    if (devInfoChoice == 0) {
        Json::Value devInfo(Json::objectValue);
        if (dataProvider->ConsumeBool()) {
            devInfo["sn"] = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        }
        if (dataProvider->ConsumeBool()) {
            devInfo["prodId"] = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        }
        item["devInfo"] = devInfo;
    } else if (devInfoChoice == 1) {
        item["devInfo"] = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    }
    if (dataProvider->ConsumeBool()) {
        Json::Value services(Json::objectValue);
        services["ip"] = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        services["port"] = dataProvider->ConsumeIntegralInRange<int>(0, 65535);
        item["services"] = services;
    }
    return item;
}

Json::Value BuildRandomStatusJson(FuzzedDataProvider *dataProvider)
{
    Json::Value item(Json::objectValue);
    if (dataProvider->ConsumeBool()) {
        item["devId"] = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    }
    uint8_t statusChoice = dataProvider->ConsumeIntegralInRange<uint8_t>(0, 3);
    if (statusChoice == 0) {
        item["status"] = REMOTE_STATUS_ONLINE;
    } else if (statusChoice == 1) {
        item["status"] = REMOTE_STATUS_OFFLINE;
    } else if (statusChoice == 2) {
        item["status"] = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    }
    return item;
}

Json::Value BuildRandomPrinterArray(FuzzedDataProvider *dataProvider)
{
    Json::Value jsonArray(Json::arrayValue);
    int count = dataProvider->ConsumeIntegralInRange<int>(0, MAX_PRINTER_COUNT);
    for (int i = 0; i < count; i++) {
        jsonArray.append(BuildRandomPrinterJson(dataProvider));
    }
    return jsonArray;
}

Json::Value BuildRandomStatusArray(FuzzedDataProvider *dataProvider)
{
    Json::Value jsonArray(Json::arrayValue);
    int count = dataProvider->ConsumeIntegralInRange<int>(0, MAX_PRINTER_COUNT);
    for (int i = 0; i < count; i++) {
        jsonArray.append(BuildRandomStatusJson(dataProvider));
    }
    return jsonArray;
}

std::string BuildRandomPrinterListMsg(FuzzedDataProvider *dataProvider)
{
    return PrintJsonUtil::WriteString(BuildRandomPrinterArray(dataProvider));
}

std::string BuildRandomPrinterStatusMsg(FuzzedDataProvider *dataProvider)
{
    return PrintJsonUtil::WriteString(BuildRandomStatusArray(dataProvider));
}

void TestAdapterBindService(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto& adapter = RemoteServiceAdapter::GetInstance();
    adapter.BindService();
}

void TestAdapterUnbindService(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto& adapter = RemoteServiceAdapter::GetInstance();
    adapter.UnbindService();
}

void TestAdapterIsConnected(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto& adapter = RemoteServiceAdapter::GetInstance();
    adapter.IsConnected();
}

void TestAdapterSendData(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto& adapter = RemoteServiceAdapter::GetInstance();
    uint32_t code = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    std::string msg = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    adapter.SendData(code, msg);
}

void TestAdapterRequestPrinterStatus(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto& adapter = RemoteServiceAdapter::GetInstance();
    std::string devId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    adapter.RequestPrinterStatus(devId);
}

void TestAdapterRequestPrinterList(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto& adapter = RemoteServiceAdapter::GetInstance();
    adapter.RequestPrinterList();
}

void TestAdapterSetOnServiceDiedCallback(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto& adapter = RemoteServiceAdapter::GetInstance();
    bool callbackCalled = false;
    adapter.SetOnServiceDiedCallback([&callbackCalled]() {
        callbackCalled = true;
    });
}

void TestAdapterOnRemoteServiceDied(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto& adapter = RemoteServiceAdapter::GetInstance();
    adapter.OnRemoteServiceDied();
}

void TestManagerStartDiscovery(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto manager = DelayedSingleton<RemotePrinterManager>::GetInstance();
    manager->StartPrinterDiscovery();
}

void TestManagerStopDiscovery(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto manager = DelayedSingleton<RemotePrinterManager>::GetInstance();
    manager->StopPrinterDiscovery();
}

void TestManagerGetPrinterInfo(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto manager = DelayedSingleton<RemotePrinterManager>::GetInstance();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    manager->GetPrinterInfo(printerId);
}

void TestManagerUpdateStatus(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto manager = DelayedSingleton<RemotePrinterManager>::GetInstance();
    std::string printerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    PrinterStatus status =
        static_cast<PrinterStatus>(dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER));
    manager->UpdatePrinterStatus(printerId, status);
}

void TestManagerClearAllPrinters(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto manager = DelayedSingleton<RemotePrinterManager>::GetInstance();
    manager->ClearAllPrinters();
}

void TestManagerConvertStatus(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    std::string statusStr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    RemotePrinterManager::ConvertStatusToPrinterStatus(statusStr);
}

void TestManagerDestroy(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto manager = DelayedSingleton<RemotePrinterManager>::GetInstance();
    manager->Destroy();
}

void TestManagerDisconnect(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto manager = DelayedSingleton<RemotePrinterManager>::GetInstance();
    manager->Disconnect();
}

void TestManagerOnPrinterListReceived(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto manager = DelayedSingleton<RemotePrinterManager>::GetInstance();
    Json::Value jsonArray = BuildRandomPrinterArray(dataProvider);
    manager->OnPrinterListReceived(jsonArray);
}

void TestManagerOnPrinterStatusReceived(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto manager = DelayedSingleton<RemotePrinterManager>::GetInstance();
    Json::Value jsonArray = BuildRandomStatusArray(dataProvider);
    manager->OnPrinterStatusReceived(jsonArray);
}

void TestManagerBuildPrinterInfo(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    Json::Value item = BuildRandomPrinterJson(dataProvider);
    PrinterInfo printerInfo;
    RemotePrinterManager::BuildPrinterInfo(item, printerInfo);
}

void TestConnectionIsConnected(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintIpcConnection connection;
    connection.IsConnected();
}

void TestConnectionGetRemoteObject(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintIpcConnection connection;
    connection.GetRemoteObject();
}

void TestConnectionWaitForConnection(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintIpcConnection connection;
    int32_t timeoutMs = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    connection.WaitForConnection(timeoutMs);
}

void TestConnectionOnAbilityConnectDone(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto connection = sptr<PrintIpcConnection>::MakeSptr();
    AppExecFwk::ElementName element;
    int32_t resultCode = dataProvider->ConsumeIntegralInRange<int32_t>(-1, MAX_SET_NUMBER);
    if (dataProvider->ConsumeBool()) {
        sptr<IPCObjectStub> stub = new IPCObjectStub(u"test_remote_service");
        connection->OnAbilityConnectDone(element, stub, resultCode);
    } else {
        sptr<IRemoteObject> nullObj = nullptr;
        connection->OnAbilityConnectDone(element, nullObj, resultCode);
    }
}

void TestConnectionOnAbilityDisconnectDone(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto connection = sptr<PrintIpcConnection>::MakeSptr();
    AppExecFwk::ElementName element;
    int32_t resultCode = dataProvider->ConsumeIntegralInRange<int32_t>(-1, MAX_SET_NUMBER);
    connection->OnAbilityDisconnectDone(element, resultCode);
}

void TestConnectionClearConnection(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintIpcConnection connection;
    connection.ClearConnection();
}

void TestConnectionSendData(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    PrintIpcConnection connection;
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    uint32_t code = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    connection.SendData(code, dataParcel, reply, option);
}

void TestStubOnRemoteRequest(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto stub = sptr<RemoteCallbackStub>::MakeSptr();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;

    if (dataProvider->ConsumeBool()) {
        WriteCallbackInterfaceToken(dataParcel);
    } else {
        std::string randomStr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        std::u16string invalidDescriptor(randomStr.begin(), randomStr.end());
        dataParcel.WriteInterfaceToken(invalidDescriptor);
    }

    std::vector<int32_t> errorCodes = {
        E_PRINT_NONE,
        E_PRINT_NETWORK_ERROR,
        E_PRINT_ACCOUNT_ERROR,
        E_PRINT_INVALID_PARAMETER,
        dataProvider->ConsumeIntegralInRange<int32_t>(-100, 1000)
    };
    int32_t errorCode = dataProvider->PickValueInArray(errorCodes);
    dataParcel.WriteInt32(errorCode);

    if (errorCode == E_PRINT_NONE) {
        int64_t rawDataSize;
        uint8_t sizeChoice = dataProvider->ConsumeIntegralInRange<uint8_t>(0, 3);
        if (sizeChoice == 0) {
            rawDataSize = 0;
        } else if (sizeChoice == 1) {
            rawDataSize = -1;
        } else if (sizeChoice == 2) {
            rawDataSize = REMOTE_MAX_RAW_DATA_SIZE + 1;
        } else {
            rawDataSize = static_cast<int64_t>(dataProvider->ConsumeIntegralInRange<size_t>(1, 1024));
        }
        dataParcel.WriteInt64(rawDataSize);

        if (rawDataSize > 0 && rawDataSize <= REMOTE_MAX_RAW_DATA_SIZE) {
            bool writeRawData = dataProvider->ConsumeBool();
            if (writeRawData) {
                uint8_t msgType = dataProvider->ConsumeIntegralInRange<uint8_t>(0, 3);
                std::string msg;
                if (msgType == 0) {
                    msg = BuildRandomPrinterListMsg(dataProvider);
                } else if (msgType == 1) {
                    msg = BuildRandomPrinterStatusMsg(dataProvider);
                } else if (msgType == 2) {
                    msg = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
                }
                if (static_cast<int64_t>(msg.size()) < rawDataSize) {
                    msg.append(static_cast<size_t>(rawDataSize) - msg.size(), '\0');
                } else if (static_cast<int64_t>(msg.size()) > rawDataSize) {
                    msg = msg.substr(0, static_cast<size_t>(rawDataSize));
                }
                dataParcel.WriteRawData(msg.c_str(), static_cast<size_t>(rawDataSize));
            }
        }
    }

    std::vector<uint32_t> codes = {
        static_cast<uint32_t>(RemoteRequestCode::COMMAND_REQUEST_PRINTER_STATUS),
        static_cast<uint32_t>(RemoteRequestCode::COMMAND_REQUEST_PRINTER_LIST),
        dataProvider->ConsumeIntegralInRange<uint32_t>(0, 5000)
    };
    uint32_t code = dataProvider->PickValueInArray(codes);
    stub->OnRemoteRequest(code, dataParcel, reply, option);
}

void TestStubHandleGetPrinterStatus(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto stub = sptr<RemoteCallbackStub>::MakeSptr();
    uint8_t msgType = dataProvider->ConsumeIntegralInRange<uint8_t>(0, 3);
    std::string msg;
    if (msgType == 0) {
        msg = BuildRandomPrinterStatusMsg(dataProvider);
    } else if (msgType == 1) {
        msg = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    } else if (msgType == 2) {
        msg = "[]";
    }
    stub->HandleGetPrinterStatus(msg);
}

void TestStubHandleGetPrinterList(const uint8_t *data, size_t size, FuzzedDataProvider *dataProvider)
{
    auto stub = sptr<RemoteCallbackStub>::MakeSptr();
    uint8_t msgType = dataProvider->ConsumeIntegralInRange<uint8_t>(0, 3);
    std::string msg;
    if (msgType == 0) {
        msg = BuildRandomPrinterListMsg(dataProvider);
    } else if (msgType == 1) {
        msg = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    } else if (msgType == 2) {
        msg = "[]";
    }
    stub->HandleGetPrinterList(msg);
}

void RemoteServiceFuzzer::TestRemoteServiceAdapter(const uint8_t *data, size_t size)
{
    FuzzedDataProvider dataProvider(data, size);
    TestHandler tasks[] = {
        &TestAdapterBindService,
        &TestAdapterUnbindService,
        &TestAdapterIsConnected,
        &TestAdapterSendData,
        &TestAdapterRequestPrinterStatus,
        &TestAdapterRequestPrinterList,
        &TestAdapterSetOnServiceDiedCallback,
        &TestAdapterOnRemoteServiceDied,
    };
    auto handler = dataProvider.PickValueInArray(tasks);
    handler(data, size, &dataProvider);
}

void RemoteServiceFuzzer::TestRemotePrinterManager(const uint8_t *data, size_t size)
{
    FuzzedDataProvider dataProvider(data, size);
    TestHandler tasks[] = {
        &TestManagerStartDiscovery,
        &TestManagerStopDiscovery,
        &TestManagerGetPrinterInfo,
        &TestManagerUpdateStatus,
        &TestManagerClearAllPrinters,
        &TestManagerConvertStatus,
        &TestManagerDestroy,
        &TestManagerDisconnect,
        &TestManagerOnPrinterListReceived,
        &TestManagerOnPrinterStatusReceived,
        &TestManagerBuildPrinterInfo,
    };
    auto handler = dataProvider.PickValueInArray(tasks);
    handler(data, size, &dataProvider);
}

void RemoteServiceFuzzer::TestRemoteCallbackStub(const uint8_t *data, size_t size)
{
    FuzzedDataProvider dataProvider(data, size);
    TestHandler tasks[] = {
        &TestStubOnRemoteRequest,
        &TestStubHandleGetPrinterStatus,
        &TestStubHandleGetPrinterList,
    };
    auto handler = dataProvider.PickValueInArray(tasks);
    handler(data, size, &dataProvider);
}

void RemoteServiceFuzzer::TestPrintIpcConnection(const uint8_t *data, size_t size)
{
    FuzzedDataProvider dataProvider(data, size);
    TestHandler tasks[] = {
        &TestConnectionIsConnected,
        &TestConnectionGetRemoteObject,
        &TestConnectionWaitForConnection,
        &TestConnectionOnAbilityConnectDone,
        &TestConnectionOnAbilityDisconnectDone,
        &TestConnectionClearConnection,
        &TestConnectionSendData,
    };
    auto handler = dataProvider.PickValueInArray(tasks);
    handler(data, size, &dataProvider);
}

} // namespace OHOS::Print

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < OHOS::Print::U32_AT_SIZE || size > OHOS::Print::FOO_MAX_LEN) {
        return 0;
    }
    OHOS::Print::RemoteServiceFuzzer::TestRemoteServiceAdapter(data, size);
    OHOS::Print::RemoteServiceFuzzer::TestRemotePrinterManager(data, size);
    OHOS::Print::RemoteServiceFuzzer::TestRemoteCallbackStub(data, size);
    OHOS::Print::RemoteServiceFuzzer::TestPrintIpcConnection(data, size);
    return 0;
}
