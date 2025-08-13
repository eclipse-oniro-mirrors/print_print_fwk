/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <set>
#include <map>
#include <cstring>
#include <string>
#include <thread>
#include "securec.h"
#include "refbase.h"
#include "scan_callback.h"
#include "scan_manager_client.h"
#include "scan_constant.h"
#include "scan_log.h"
#include "scan_util.h"
#include "scanner_info.h"
#include "scan_option_value.h"
#include "scan_context.h"
#include "ohscan.h"

using namespace OHOS::Scan;

int32_t OH_Scan_Init()
{
    SCAN_HILOGI("Enter OH_Scan_Init");
    auto client = ScanManagerClient::GetInstance();
    if (client == nullptr) {
        SCAN_HILOGE("client is a nullptr");
        return SCAN_ERROR_GENERIC_FAILURE;
    }
    int32_t ret = client->InitScan();
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("InitScan failed, ErrorCode: [%{public}d]", ret);
        return ScanContext::StatusConvert(ret);
    } else {
        SCAN_HILOGI("InitScan successfully");
        return SCAN_ERROR_NONE;
    }
}

int32_t OH_Scan_StartScannerDiscovery(Scan_ScannerDiscoveryCallback callback)
{
    if (callback == nullptr) {
        SCAN_HILOGE("callback is a nullptr");
        return SCAN_ERROR_INVALID_PARAMETER;
    }
    auto& context = ScanContext::GetInstance();
    context.SetDiscoverCallback(callback);
    auto client = ScanManagerClient::GetInstance();
    if (client == nullptr) {
        SCAN_HILOGE("client is a nullptr");
        return SCAN_ERROR_GENERIC_FAILURE;
    }
    int32_t ret = SCAN_ERROR_NONE;
    auto scannerDiscoveryCallback = [](std::vector<ScanDeviceInfo> &infos) {
        ScanContext::GetInstance().ExecuteCallback(infos);
    };
    OHOS::sptr<IScanCallback> call = new (std::nothrow) ScanCallback(scannerDiscoveryCallback);
    if (call == nullptr) {
        SCAN_HILOGE("call is null");
        return SCAN_ERROR_GENERIC_FAILURE;
    }
    ret = client->On("", context.GetRegisterType(), call);
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("Failed to register event");
        return ScanContext::StatusConvert(ret);
    }
    ret = client->GetScannerList();
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("Failed to GetScannerList");
        return ScanContext::StatusConvert(ret);
    }
    return SCAN_ERROR_NONE;
}

int32_t OH_Scan_OpenScanner(const char* scannerId)
{
    if (scannerId == nullptr) {
        SCAN_HILOGE("Invalid parameter.");
        return SCAN_ERROR_INVALID_PARAMETER;
    }
    auto client = ScanManagerClient::GetInstance();
    if (client == nullptr) {
        SCAN_HILOGE("client is a nullptr");
        return SCAN_ERROR_GENERIC_FAILURE;
    }
    int32_t ret = client->OpenScanner(std::string(scannerId));
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("OpenScanner failed, ErrorCode: [%{public}d]", ret);
        return ScanContext::StatusConvert(ret);
    } else {
        SCAN_HILOGI("OpenScanner successfully");
        return SCAN_ERROR_NONE;
    }
}

int32_t OH_Scan_CloseScanner(const char* scannerId)
{
    if (scannerId == nullptr) {
        SCAN_HILOGE("Invalid parameter.");
        return SCAN_ERROR_INVALID_PARAMETER;
    }
    auto client = ScanManagerClient::GetInstance();
    if (client == nullptr) {
        SCAN_HILOGE("client is a nullptr");
        return SCAN_ERROR_GENERIC_FAILURE;
    }
    int32_t ret = client->CloseScanner(std::string(scannerId));
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("CloseScanner failed, ErrorCode: [%{public}d]", ret);
        return ScanContext::StatusConvert(ret);
    } else {
        SCAN_HILOGI("CloseScanner successfully");
        return SCAN_ERROR_NONE;
    }
}

Scan_ScannerOptions* OH_Scan_GetScannerParameter(const char* scannerId, int32_t* errorCode)
{
    if (scannerId == nullptr || errorCode == nullptr) {
        SCAN_HILOGE("Invalid parameter.");
        return nullptr;
    }
    auto& context = ScanContext::GetInstance();
    std::string deviceId(scannerId);
    auto cachedOptions = context.GetScannerOptions(deviceId);
    if (cachedOptions != nullptr) {
        SCAN_HILOGI("Device parameters have been obtained.");
        *errorCode = SCAN_ERROR_NONE;
        return cachedOptions;
    }
    int32_t scannerParaCount = 0;
    int32_t status = context.GetScannerParaCount(deviceId, scannerParaCount);
    if (status != SCAN_ERROR_NONE) {
        SCAN_HILOGE("Failed to get scanner GetScannerParaCount value.");
        *errorCode = status;
        return nullptr;
    }
    std::unique_ptr<ScanParaTable> paraTable = std::make_unique<ScanParaTable>();
    if (paraTable == nullptr) {
        SCAN_HILOGE("paraTable is a nullptr");
        *errorCode = SCAN_ERROR_GENERIC_FAILURE;
        return nullptr;
    }
    status = context.GetScannerParameter(deviceId, scannerParaCount, *paraTable);
    if (status != SCAN_ERROR_NONE) {
        SCAN_HILOGE("Failed to get scanner GetScannerParameter paraTable.");
        *errorCode = status;
        return nullptr;
    }
    Scan_ScannerOptions* scaParaOptions = context.ConvertToScannerOptions(*paraTable);
    if (scaParaOptions == nullptr) {
        *errorCode = SCAN_ERROR_GENERIC_FAILURE;
        return nullptr;
    }
    context.SetScanParaTable(scannerId, std::move(paraTable));
    context.SetScannerOptions(deviceId, scaParaOptions);
    *errorCode = SCAN_ERROR_NONE;
    return scaParaOptions;
}

int32_t OH_Scan_SetScannerParameter(const char* scannerId, const int32_t option, const char* value)
{
    if (scannerId == nullptr || value == nullptr) {
        SCAN_HILOGE("Invalid parameter.");
        return SCAN_ERROR_INVALID_PARAMETER;
    }
    std::string deviceId(scannerId);
    ScanOptionValue optionValue;
    auto& context = ScanContext::GetInstance();
    int32_t ret = context.GetOptionValueFromTable(deviceId, option, value, optionValue);
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("GetOptionValueFromTable error");
        return ret;
    }
    auto client = ScanManagerClient::GetInstance();
    if (client == nullptr) {
        SCAN_HILOGE("client is a nullptr");
        return SCAN_ERROR_GENERIC_FAILURE;
    }
    int32_t innerOption = option;
    if (!context.ParaIndexConvert(option, innerOption, deviceId)) {
        SCAN_HILOGE("index [%{private}d] is error", option);
        return SCAN_ERROR_INVALID_PARAMETER;
    }
    ret = client->OpScanOptionValue(deviceId, innerOption,
        SCAN_ACTION_SET_VALUE, optionValue);
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("SetScannerParameter failed, ErrorCode: [%{public}d]", ret);
        return ScanContext::StatusConvert(ret);
    }
    return SCAN_ERROR_NONE;
}

int32_t OH_Scan_StartScan(const char* scannerId, bool batchMode)
{
    if (scannerId == nullptr) {
        SCAN_HILOGE("Invalid parameter.");
        return SCAN_ERROR_INVALID_PARAMETER;
    }
    auto client = ScanManagerClient::GetInstance();
    if (client == nullptr) {
        SCAN_HILOGE("client is a nullptr");
        return SCAN_ERROR_GENERIC_FAILURE;
    }
    int32_t ret = client->StartScan(std::string(scannerId), batchMode);
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("StartScan failed, ErxrorCode: [%{public}d]", ret);
        return ScanContext::StatusConvert(ret);
    } else {
        SCAN_HILOGI("StartScan successfully");
        return SCAN_ERROR_NONE;
    }
}

int32_t OH_Scan_CancelScan(const char* scannerId)
{
    if (scannerId == nullptr) {
        SCAN_HILOGE("Invalid parameter.");
        return SCAN_ERROR_INVALID_PARAMETER;
    }
    auto client = ScanManagerClient::GetInstance();
    if (client == nullptr) {
        SCAN_HILOGE("client is a nullptr");
        return SCAN_ERROR_GENERIC_FAILURE;
    }
    int32_t ret = client->CancelScan(std::string(scannerId));
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("CancelScan failed, ErxrorCode: [%{public}d]", ret);
        return ScanContext::StatusConvert(ret);
    } else {
        SCAN_HILOGI("CancelScan successfully");
        return SCAN_ERROR_NONE;
    }
}

int32_t OH_Scan_GetPictureScanProgress(const char* scannerId, Scan_PictureScanProgress* prog)
{
    if (prog == nullptr) {
        SCAN_HILOGE("Invalid parameter.");
        return SCAN_ERROR_INVALID_PARAMETER;
    }
    ScanProgress scanProg;
    auto client = ScanManagerClient::GetInstance();
    if (client == nullptr) {
        SCAN_HILOGE("client is a nullptr");
        return SCAN_ERROR_GENERIC_FAILURE;
    }
    int32_t ret = client->GetScanProgress(std::string(scannerId), scanProg);
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("GetScanProgress failed, ErrorCode: [%{public}d]", ret);
        return ScanContext::StatusConvert(ret);
    } else {
        prog->progress = scanProg.GetScanProgress();
        prog->fd = scanProg.GetScanPictureFd();
        prog->isFinal = scanProg.GetIsFinal();
        SCAN_HILOGI("GetScanProgress successfully");
        return SCAN_ERROR_NONE;
    }
}

int32_t OH_Scan_Exit()
{
    auto& context = ScanContext::GetInstance();
    auto client = ScanManagerClient::GetInstance();
    if (client == nullptr) {
        SCAN_HILOGE("client is a nullptr");
        return SCAN_ERROR_GENERIC_FAILURE;
    }
    int32_t ret = client->ExitScan();
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("ExitScan failed, ErrorCode: [%{public}d]", ret);
        return ScanContext::StatusConvert(ret);
    }
    client->Off("", context.GetRegisterType());
    context.Clear();
    SCAN_HILOGI("ExitScan successfully");
    return SCAN_ERROR_NONE;
}