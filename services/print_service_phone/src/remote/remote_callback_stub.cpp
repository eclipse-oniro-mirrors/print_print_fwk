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

#include "remote_callback_stub.h"
#include "remote_constants.h"
#include "remote_printer_manager.h"
#include "print_log.h"
#include "print_constant.h"
#include "print_json_util.h"
#include "singleton.h"

namespace OHOS::Print {

RemoteCallbackStub::RemoteCallbackStub()
{
    cmdMap_[static_cast<uint32_t>(RemoteRequestCode::COMMAND_REQUEST_PRINTER_STATUS)] =
        &RemoteCallbackStub::HandleGetPrinterStatus;
    cmdMap_[static_cast<uint32_t>(RemoteRequestCode::COMMAND_REQUEST_PRINTER_LIST)] =
        &RemoteCallbackStub::HandleGetPrinterList;
}

int32_t RemoteCallbackStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    PRINT_HILOGD("RemoteCallbackStub::OnRemoteRequest started, code = %{public}d", code);
    auto descriptorToken = data.ReadInterfaceToken();
    if (descriptorToken != GetDescriptor()) {
        PRINT_HILOGE("Remote descriptor not the same as local descriptor.");
        return E_PRINT_RPC_FAILURE;
    }

    int32_t errorCode = 0;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadInt32(errorCode), E_PRINT_RPC_FAILURE);
    if (errorCode == -5) {
        PRINT_HILOGE("RemoteCallbackStub account error: %{public}d", errorCode);
        return errorCode;
    }
    if (errorCode == -3) {
        PRINT_HILOGE("RemoteCallbackStub network error: %{public}d", errorCode);
        DelayedSingleton<RemotePrinterManager>::GetInstance()->ClearAllPrinters();
        return errorCode;
    }
    if (errorCode != E_PRINT_NONE) {
        PRINT_HILOGE("RemoteCallbackStub read errorCode failed: %{public}d, remote unreachable", errorCode);
        DelayedSingleton<RemotePrinterManager>::GetInstance()->ClearAllPrinters();
        return errorCode;
    }

    int64_t rawDataSize = 0;
    CHECK_PARCEL_OP_AND_RETURN_VAL(data.ReadInt64(rawDataSize), E_PRINT_RPC_FAILURE);
    if (rawDataSize < 0 || rawDataSize > REMOTE_MAX_RAW_DATA_SIZE) {
        PRINT_HILOGE("RemoteCallbackStub read rawDataSize invalid: %{public}ld", rawDataSize);
        return E_PRINT_SERVER_FAILURE;
    }

    std::string msg;
    if (rawDataSize > 0) {
        const char* rawData = (const char*)data.ReadRawData(static_cast<size_t>(rawDataSize));
        if (rawData == nullptr) {
            PRINT_HILOGE("RemoteCallbackStub read rawData failed");
            return E_PRINT_SERVER_FAILURE;
        }
        msg.assign(rawData, static_cast<size_t>(rawDataSize));
    }

    auto itFunc = cmdMap_.find(code);
    if (itFunc != cmdMap_.end()) {
        auto requestFunc = itFunc->second;
        if (requestFunc != nullptr) {
            bool result = (this->*requestFunc)(msg);
            return result ? E_PRINT_NONE : E_PRINT_SERVER_FAILURE;
        }
    }
    PRINT_HILOGW("RemoteCallbackStub default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool RemoteCallbackStub::HandleGetPrinterStatus(const std::string &msg)
{
    PRINT_HILOGI("RemoteCallbackStub HandleGetPrinterStatus");
    
    Json::Value jsonObject;
    if (!PrintJsonUtil::Parse(msg, jsonObject)) {
        PRINT_HILOGE("Failed to parse printer status response");
        return false;
    }
    
    if (!jsonObject.isArray()) {
        PRINT_HILOGE("Printer status response is not an array");
        return false;
    }
    
    return DelayedSingleton<RemotePrinterManager>::GetInstance()->OnPrinterStatusReceived(jsonObject);
}

bool RemoteCallbackStub::HandleGetPrinterList(const std::string &msg)
{
    PRINT_HILOGI("RemoteCallbackStub HandleGetPrinterList");
    
    Json::Value jsonObject;
    if (!PrintJsonUtil::Parse(msg, jsonObject)) {
        PRINT_HILOGE("Failed to parse printer list response");
        return false;
    }
    
    if (!jsonObject.isArray()) {
        PRINT_HILOGE("Printer list response is not an array");
        return false;
    }
    
    return DelayedSingleton<RemotePrinterManager>::GetInstance()->OnPrinterListReceived(jsonObject);
}

} // namespace OHOS::Print