/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "securec.h"
#include "iremote_broker.h"
#include "napi_scan_utils.h"
#include "scan_constant.h"
#include "scan_log.h"
#include "scanner_info.h"
#include "scan_service_proxy.h"

namespace OHOS::Scan {
using namespace OHOS::HiviewDFX;

ScanServiceProxy::ScanServiceProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IScanService>(object) {}

int32_t ScanServiceProxy::GetResult(int32_t retCode, MessageParcel &reply)
{
    if (retCode != ERR_NONE) {
        SCAN_HILOGE("rpc error code = %{public}d", retCode);
        return E_SCAN_RPC_FAILURE;
    }

    retCode = reply.ReadInt32();
    SCAN_HILOGD("ScanServiceProxy end. ret = [%{public}d]", retCode);
    return retCode;
}

int32_t ScanServiceProxy::InitScan(int32_t &scanVersion)
{
    SCAN_HILOGD("ScanServiceProxy InitScan start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::InitScan remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(CMD_INIT_SCAN, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy InitScan failed");
        return ret;
    }
    scanVersion = reply.ReadInt32();
    SCAN_HILOGD("ScanServiceProxy InitScan end.");
    return ret;
}

int32_t ScanServiceProxy::ExitScan()
{
    SCAN_HILOGD("ScanServiceProxy ExitScan start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::ExitScan remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(CMD_EXIT_SCAN, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy ExitScan failed");
        return ret;
    }
    SCAN_HILOGD("ScanServiceProxy ExitScan end");
    return ret;
}

int32_t ScanServiceProxy::GetScannerList()
{
    SCAN_HILOGD("ScanServiceProxy GetScannerList start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::GetScannerList remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(CMD_GET_SCANNER_LIST, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy GetScannerList failed");
        return ret;
    }
    SCAN_HILOGD("ScanServiceProxy GetScannerList end");
    return ret;
}


int32_t ScanServiceProxy::StopDiscover()
{
    SCAN_HILOGD("ScanServiceProxy StopDiscover start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::StopDiscover remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(CMD_STOP_DISCOVER, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy StopDiscover failed");
        return ret;
    }
    SCAN_HILOGD("ScanServiceProxy StopDiscover end");
    return ret;
}


int32_t ScanServiceProxy::OpenScanner(const std::string scannerId)
{
    SCAN_HILOGD("ScanServiceProxy OpenScanner start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::OpenScanner remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    data.WriteString(scannerId);
    int32_t ret = remote->SendRequest(CMD_OPEN_SCANNER, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy OpenScanner failed");
        return ret;
    }
    SCAN_HILOGD("ScanServiceProxy OpenScanner end");
    return ret;
}

int32_t ScanServiceProxy::CloseScanner(const std::string scannerId)
{
    SCAN_HILOGD("ScanServiceProxy CloseScanner start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::CloseScanner remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    data.WriteString(scannerId);
    int32_t ret = remote->SendRequest(CMD_CLOSE_SCANNER, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy CloseScanner failed");
        return ret;
    }
    SCAN_HILOGD("ScanServiceProxy CloseScanner end");
    return ret;
}

int32_t ScanServiceProxy::GetScanOptionDesc(const std::string scannerId, const int32_t optionIndex,
    ScanOptionDescriptor &desc)
{
    SCAN_HILOGD("ScanServiceProxy GetScanOptionDesc start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::GetScanOptionDesc remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    data.WriteString(scannerId);
    data.WriteInt32(optionIndex);
    int32_t ret = remote->SendRequest(CMD_GET_SCAN_OPTION_DESC, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy GetScanOptionDesc failed");
        return ret;
    }
    auto scanOptionDescriptor = ScanOptionDescriptor::Unmarshalling(reply);
    desc = *scanOptionDescriptor;
    SCAN_HILOGD("ScanServiceProxy GetScanOptionDesc end");
    return ret;
}

int32_t ScanServiceProxy::OpScanOptionValue(const std::string scannerId,
    const int32_t optionIndex, const ScanOptionOpType op, ScanOptionValue &value, int32_t &info)
{
    SCAN_HILOGD("ScanServiceProxy OpScanOptionValue start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::OpScanOptionValue remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    data.WriteString(scannerId);
    data.WriteInt32(optionIndex);
    data.WriteUint32(op);
    value.Marshalling(data);
    int32_t ret = remote->SendRequest(CMD_OP_SCAN_OPTION_VALUE, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy OpScanOptionValue failed");
        return ret;
    }
    auto scanOptionValue = ScanOptionValue::Unmarshalling(reply);
    if (scanOptionValue == nullptr) {
        SCAN_HILOGE("ScanServiceProxy scanOptionValue is a nullptr");
        return E_SCAN_GENERIC_FAILURE;
    }
    value = *scanOptionValue;
    if (op == SCAN_ACTION_GET_VALUE) {
        info = reply.ReadInt32();
    }
    SCAN_HILOGD("ScanServiceProxy OpScanOptionValue end");
    return ret;
}

int32_t ScanServiceProxy::GetScanParameters(const std::string scannerId, ScanParameters &para)
{
    SCAN_HILOGD("ScanServiceProxy GetScanParameters start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::GetScanParameters remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    data.WriteString(scannerId);
    int32_t ret = remote->SendRequest(CMD_GET_SCAN_PARAMETERS, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy GetScanParameters failed");
        return ret;
    }
    auto scanParameters = ScanParameters::Unmarshalling(reply);
    para = *scanParameters;
    SCAN_HILOGD("ScanServiceProxy GetScanParameters end");
    return ret;
}

int32_t ScanServiceProxy::StartScan(const std::string scannerId, const bool &batchMode)
{
    SCAN_HILOGD("ScanServiceProxy StartScan start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::StartScan remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    data.WriteString(scannerId);
    data.WriteBool(batchMode);
    int32_t ret = remote->SendRequest(CMD_START_SCAN, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy StartScan failed");
        return ret;
    }
    SCAN_HILOGD("ScanServiceProxy StartScan end");
    return ret;
}

int32_t ScanServiceProxy::GetSingleFrameFD(const std::string scannerId, uint32_t &size, uint32_t fd)
{
    SCAN_HILOGE("ScanServiceProxy GetSingleFrameFD start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::GetSingleFrameFD remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    data.WriteString(scannerId);
    data.WriteFileDescriptor(fd);
    int32_t ret = remote->SendRequest(CMD_GET_SINGLE_FRAME_FD, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy GetSingleFrameFD failed");
        return ret;
    }
    size = reply.ReadUint32();
    SCAN_HILOGD("ScanServiceProxy GetSingleFrameFD end");
    return ret;
}

int32_t ScanServiceProxy::CancelScan(const std::string scannerId)
{
    SCAN_HILOGD("ScanServiceProxy CancelScan start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::CancelScan remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    data.WriteString(scannerId);
    int32_t ret = remote->SendRequest(CMD_CANCEL_SCAN, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy CancelScan failed");
        return ret;
    }
    SCAN_HILOGD("ScanServiceProxy CancelScan end");
    return ret;
}

int32_t ScanServiceProxy::SetScanIOMode(const std::string scannerId, const bool isNonBlocking)
{
    SCAN_HILOGD("ScanServiceProxy SetScanIOMode start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::SetScanIOMode remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    data.WriteString(scannerId);
    data.WriteBool(isNonBlocking);
    int32_t ret = remote->SendRequest(CMD_SET_SCAN_IO_MODE, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy SetScanIOMode failed");
        return ret;
    }
    SCAN_HILOGD("ScanServiceProxy SetScanIOMode end");
    return ret;
}

int32_t ScanServiceProxy::GetScanSelectFd(const std::string scannerId, int32_t &fd)
{
    SCAN_HILOGD("ScanServiceProxy GetScanSelectFd start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::GetScanSelectFd remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    data.WriteString(scannerId);
    int32_t ret = remote->SendRequest(CMD_GET_SCAN_SELECT_FD, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy GetScanSelectFd failed");
        return ret;
    }
    fd = reply.ReadInt32();
    SCAN_HILOGD("ScanServiceProxy GetScanSelectFd end");
    return ret;
}

int32_t ScanServiceProxy::On(const std::string taskId, const std::string &type, const sptr<IScanCallback> &listener)
{
    SCAN_HILOGD("ScanServiceProxy On start");
    if (listener == nullptr) {
        SCAN_HILOGE("listener is nullptr");
        return E_SCAN_INVALID_PARAMETER;
    }

    if (type.empty()) {
        SCAN_HILOGE("ScanServiceProxy::On type is null.");
        return E_SCAN_INVALID_PARAMETER;
    }

    CREATE_PRC_MESSAGE;
    data.WriteString(taskId);
    data.WriteString(type);
    data.WriteRemoteObject(listener->AsObject().GetRefPtr());

    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::On remote is null");
        return E_SCAN_RPC_FAILURE;
    }

    int32_t ret = remote->SendRequest(CMD_ON, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy On failed");
        return ret;
    }

    SCAN_HILOGD("ScanServiceProxy On end");
    return ret;
}

int32_t ScanServiceProxy::Off(const std::string taskId, const std::string &type)
{
    SCAN_HILOGD("ScanServiceProxy::Off start");

    if (type.empty()) {
        SCAN_HILOGE("ScanServiceProxy::Off type is null.");
        return E_SCAN_INVALID_PARAMETER;
    }

    CREATE_PRC_MESSAGE;
    data.WriteString(taskId);
    data.WriteString(type);

    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::SetScanIOMode remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(CMD_OFF, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy Off failed");
        return ret;
    }

    SCAN_HILOGD("ScanServiceProxy Off out");
    return ret;
}

int32_t ScanServiceProxy::GetScannerState(int32_t &scannerState)
{
    SCAN_HILOGD("ScanServiceProxy GetScannerState start");
    CREATE_PRC_MESSAGE;

    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::SetScanIOMode remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(CMD_GET_SCANNER_STATE, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy GetScannerState failed");
        return ret;
    }
    scannerState = reply.ReadInt32();
    SCAN_HILOGD("ScanServiceProxy GetScannerState end.");
    return ret;
}

int32_t ScanServiceProxy::GetScanProgress(const std::string scannerId, ScanProgress &prog)
{
    SCAN_HILOGI("ScanServiceProxy GetScanProgress start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::GetScanProgress remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    data.WriteString(scannerId);
    int32_t ret = remote->SendRequest(CMD_GET_SCAN_PROGRESS, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy GetScanProgress failed");
        return ret;
    }
    auto scanProgress = ScanProgress::Unmarshalling(reply);
    if (scanProgress != nullptr) {
        prog = *scanProgress;
    } else {
        SCAN_HILOGE("get scanProgress is a nullptr ptr.");
        return E_SCAN_GENERIC_FAILURE;
    }
    SCAN_HILOGI("ScanServiceProxy GetScanProgress end");
    return ret;
}

int32_t ScanServiceProxy::AddScanner(const std::string& serialNumber, const std::string& discoverMode)
{
    SCAN_HILOGD("ScanServiceProxy AddScanner start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::AddScanner remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    data.WriteString(serialNumber);
    data.WriteString(discoverMode);
    int32_t ret = remote->SendRequest(CMD_CONNECT_SCANNER, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy AddScanner failed");
        return ret;
    }
    SCAN_HILOGD("ScanServiceProxy AddScanner end");
    return ret;
}

int32_t ScanServiceProxy::DeleteScanner(const std::string& serialNumber, const std::string& discoverMode)
{
    SCAN_HILOGD("ScanServiceProxy DeleteScanner start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::DeleteScanner remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    data.WriteString(serialNumber);
    data.WriteString(discoverMode);
    int32_t ret = remote->SendRequest(CMD_DISCONNECT_SCANNER, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy DeleteScanner failed");
        return ret;
    }
    SCAN_HILOGD("ScanServiceProxy DeleteScanner end");
    return ret;
}

int32_t ScanServiceProxy::GetAddedScanner(std::vector<ScanDeviceInfo>& allAddedScanner)
{
    SCAN_HILOGD("ScanServiceProxy GetAddedScanner start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::GetAddedScanner remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    int32_t ret = remote->SendRequest(CMD_GET_CONNECTED_SCANNER, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy GetAddedScanner failed");
        return ret;
    }
    uint32_t len = reply.ReadUint32();
    if (len > SCAN_MAX_COUNT) {
        SCAN_HILOGE("len is out of range.");
        return E_SCAN_INVALID_PARAMETER;
    }
    for (uint32_t i = 0; i < len; i++) {
        auto infoPtr = ScanDeviceInfo::Unmarshalling(reply);
        if (infoPtr == nullptr) {
            SCAN_HILOGE("wrong scanDeviceInfo from data");
            return E_SCAN_GENERIC_FAILURE;
        }
        allAddedScanner.emplace_back(*infoPtr);
    }
    SCAN_HILOGD("ScanServiceProxy GetAddedScanner end");
    return ret;
}

int32_t ScanServiceProxy::UpdateScannerName(const std::string& serialNumber,
    const std::string& discoverMode, const std::string& deviceName)
{
    SCAN_HILOGD("ScanServiceProxy UpdateScannerName start");
    CREATE_PRC_MESSAGE;
    auto remote = Remote();
    if (remote == nullptr) {
        SCAN_HILOGE("ScanServiceProxy::UpdateScannerName remote is null");
        return E_SCAN_RPC_FAILURE;
    }
    data.WriteString(serialNumber);
    data.WriteString(discoverMode);
    data.WriteString(deviceName);
    int32_t ret = remote->SendRequest(CMD_UPDATE_SCANNER_NAME, data, reply, option);
    ret = GetResult(ret, reply);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("ScanServiceProxy UpdateScannerName failed");
        return ret;
    }
    SCAN_HILOGD("ScanServiceProxy UpdateScannerName end");
    return ret;
}

} // namespace OHOS::Scan
