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
#include "ohscan.h"

using namespace OHOS::Scan;

struct ValueMap {
    uint32_t valueType;
    int32_t optionIndex;
    std::set<std::string> numList;
    std::set<std::string> strList;
};

struct ScanParaTable {
    std::vector<std::string> titBuff;
    std::vector<std::string> desBuff;
    std::vector<std::string> rangesBuff;
    int32_t lengthBuff;
};

static constexpr int32_t SCAN_INT_TYPE = 1;
static constexpr int32_t SCAN_STRING_TYPE = 3;
static constexpr int32_t SCAN_NUM_LIST = 2;
static constexpr int32_t SCAN_STRING_LIST = 3;
static std::map<std::string, std::map<int, ValueMap>> g_valueMap;
static std::map<std::string, Scan_ScannerOptions* > g_scanParaTables;
static bool g_isListening = false;
static const char* GET_SCANNER_DEVICE_LIST = "GET_SCANNER_DEVICE_LIST";
static Scan_ScannerDiscoveryCallback g_discoverCallback = nullptr;


static inline void FreeDeviceListMemory(Scan_ScannerDevice** devices, int32_t deviceCount)
{
    for (int32_t i = 0; i < deviceCount; i++) {
        DELETE_AND_NULLIFY(devices[i])
    }
    DELETE_ARRAY_AND_NULLIFY(devices)
}

auto callbackFunction = [](std::vector<ScanDeviceInfo> &infos) {
    int32_t deviceCount = infos.size();
    SCAN_HILOGI("deviceCount : [%{public}d]", deviceCount);
    if (deviceCount == 0) {
        SCAN_HILOGE("not found");
        g_discoverCallback(nullptr, 0);
        return;
    }
    Scan_ScannerDevice** devices = new (std::nothrow) Scan_ScannerDevice* [deviceCount];
    if (devices == nullptr) {
        SCAN_HILOGE("devices is a nullptr");
        g_discoverCallback(nullptr, 0);
    }
    int32_t devicesMemSize = deviceCount * sizeof(Scan_ScannerDevice*);
    if (memset_s(devices, devicesMemSize, 0, devicesMemSize) != 0) {
        SCAN_HILOGW("memset_s fail");
        FreeDeviceListMemory(devices, 0);
        g_discoverCallback(nullptr, 0);
        return;
    }
    for (int i = 0; i < deviceCount; i++) {
        Scan_ScannerDevice* device = new (std::nothrow) Scan_ScannerDevice();
        if (device == nullptr) {
            SCAN_HILOGE("devices is a nullptr");
            deviceCount = i;
            break;
        }
        if (memset_s(device, sizeof(Scan_ScannerDevice), 0, sizeof(Scan_ScannerDevice)) != 0) {
            SCAN_HILOGW("memset_s fail");
            deviceCount = i;
            break;
        }
        device->scannerId = infos[i].GetDeviceId().c_str();
        device->manufacturer = infos[i].GetManufacturer().c_str();
        device->model = infos[i].GetModel().c_str();
        device->serialNumber = infos[i].GetSerialNumber().c_str();
        device->discoverMode = infos[i].GetDiscoverMode().c_str();
        devices[i] = device;
    }
    g_discoverCallback(devices, deviceCount);
    FreeDeviceListMemory(devices, deviceCount);
};

namespace {
int32_t GetScanParaDesc(const std::string &deviceId, ScanOptionValue &value)
{
    auto client = ScanManagerClient::GetInstance();
    ScanOptionDescriptor desc;
    int32_t ret = client->GetScanOptionDesc(deviceId, 0, desc);
    uint32_t optionType = desc.GetOptionType();
    int32_t optionSize = desc.GetOptionSize();
    value.SetScanOptionValueType(static_cast<ScanOptionValueType>(optionType));
    value.SetValueSize(optionSize);
    int32_t info = 0;
    ret = client->OpScanOptionValue(deviceId, 0, SCAN_ACTION_GET_VALUE, value, info);
    return ret;
}

int32_t GetScanParaValues(const std::string &deviceId, ScanOptionValue &value, ScanParaTable &paraTable)
{
    std::set<uint32_t> dataType = {SCAN_INT_TYPE, SCAN_STRING_TYPE};
    int32_t lengthBuff = 0;
    for (int i = 1 ; i < value.GetNumValue(); i++) {
        ScanOptionDescriptor desc;
        auto client = ScanManagerClient::GetInstance();
        int32_t ret = client->GetScanOptionDesc(deviceId, i, desc);
        if (ret != SCAN_ERROR_NONE) {
            SCAN_HILOGE("Failed to get scanner parameters.");
            return ret;
        }
        if (!dataType.count(desc.GetOptionType())) {
            continue;
        }
        if (desc.GetOptionConstraintType() == SCAN_NUM_LIST) {
            std::string tmp;
            std::vector<std::int32_t> optionConstraintNumber;
            desc.GetOptionConstraintNumber(optionConstraintNumber);
            for (auto t : optionConstraintNumber) {
                std::string numStr = std::to_string(t);
                tmp.append(numStr).append(",");
                g_valueMap[deviceId][lengthBuff].numList.insert(numStr);
                g_valueMap[deviceId][lengthBuff].valueType = SCAN_INT_TYPE;
            }
            tmp.pop_back();
            paraTable.rangesBuff.emplace_back(tmp);
        } else if (desc.GetOptionConstraintType() == SCAN_STRING_LIST) {
            std::string tmp;
            std::vector<std::string> optionConstraintString;
            desc.GetOptionConstraintString(optionConstraintString);
            for (auto t : optionConstraintString) {
                tmp.append(t).append(",");
                g_valueMap[deviceId][lengthBuff].strList.insert(t);
                g_valueMap[deviceId][lengthBuff].valueType = SCAN_STRING_TYPE;
            }
            tmp.pop_back();
            paraTable.rangesBuff.emplace_back(tmp);
        } else {
            continue;
        }
        paraTable.titBuff.emplace_back(desc.GetOptionTitle());
        paraTable.desBuff.emplace_back(desc.GetOptionDesc());
        g_valueMap[deviceId][lengthBuff].optionIndex = i;
        lengthBuff++;
    }
    paraTable.lengthBuff = lengthBuff;
    return SCAN_ERROR_NONE;
}

void FreeScannerOptionsMemory(Scan_ScannerOptions* scannerOptions)
{
    if (scannerOptions == nullptr) {
        SCAN_HILOGW("scannerOptions is a nullptr.");
        return;
    }

    if (scannerOptions->titles != nullptr) {
        for (int i = 0; i < scannerOptions->optionCount; i++) {
            DELETE_AND_NULLIFY(scannerOptions->titles[i])
        }
        DELETE_ARRAY_AND_NULLIFY(scannerOptions->titles)
    }

    if (scannerOptions->descriptions != nullptr) {
        for (int i = 0; i < scannerOptions->optionCount; i++) {
            DELETE_AND_NULLIFY(scannerOptions->descriptions[i])
        }
        DELETE_ARRAY_AND_NULLIFY(scannerOptions->descriptions)
    }

    if (scannerOptions->ranges != nullptr) {
        for (int i = 0; i < scannerOptions->optionCount; i++) {
            DELETE_AND_NULLIFY(scannerOptions->ranges[i])
        }
        DELETE_ARRAY_AND_NULLIFY(scannerOptions->ranges)
    }

    DELETE_AND_NULLIFY(scannerOptions)
}

Scan_ScannerOptions* CreateScannerOptions(int32_t &optionCount)
{
    Scan_ScannerOptions* scannerOptions = new (std::nothrow) Scan_ScannerOptions();
    if (scannerOptions == nullptr) {
        SCAN_HILOGE("scannerOptions is a nullptr");
        return nullptr;
    }
    int32_t scannerOptionsMemSize = sizeof(Scan_ScannerOptions);
    if (memset_s(scannerOptions, scannerOptionsMemSize, 0, scannerOptionsMemSize) != 0) {
        SCAN_HILOGW("memset_s fail");
        FreeScannerOptionsMemory(scannerOptions);
        return nullptr;
    }
    scannerOptions->titles = new (std::nothrow) char* [optionCount];
    scannerOptions->descriptions = new (std::nothrow) char* [optionCount];
    scannerOptions->ranges = new (std::nothrow) char* [optionCount];
    scannerOptions->optionCount = optionCount;
    if (scannerOptions->titles == nullptr || scannerOptions->descriptions == nullptr ||
        scannerOptions->ranges == nullptr) {
        FreeScannerOptionsMemory(scannerOptions);
        return nullptr;
    }
    int32_t stringMemSize = optionCount * sizeof(char**);
    if (memset_s(scannerOptions->titles, stringMemSize, 0, stringMemSize) != 0 ||
        memset_s(scannerOptions->descriptions, stringMemSize, 0, stringMemSize) != 0 ||
        memset_s(scannerOptions->ranges, stringMemSize, 0, stringMemSize) != 0) {
            SCAN_HILOGW("memset_s fail");
            FreeScannerOptionsMemory(scannerOptions);
            return nullptr;
    }
    return scannerOptions;
}

bool CopySingleBuf(char* destBuf, const char* srcBuf, size_t bufferSize)
{
    if (destBuf == nullptr || srcBuf == nullptr) {
        SCAN_HILOGW("CopySingleBuf new fail");
        return false;
    }
    if (memset_s(destBuf, bufferSize, 0, bufferSize) != 0) {
        SCAN_HILOGE("CopySingleBuf memset_s fail");
        return false;
    }
    if (strncpy_s(destBuf, bufferSize, srcBuf, bufferSize) != 0) {
        SCAN_HILOGE("CopySingleBuf strncpy_s fail");
        return false;
    }

    return true;
}

bool MemSetScannerOptions(Scan_ScannerOptions* scannerOptions, int32_t &optionCount, ScanParaTable &paraTable)
{
    for (int i = 0; i < optionCount; i++) {
        auto bufferSize = paraTable.titBuff[i].length() + 1;
        char* titBuff = new (std::nothrow) char[bufferSize];
        if (!CopySingleBuf(titBuff, paraTable.titBuff[i].c_str(), bufferSize)) {
            if (titBuff != nullptr) {
                delete[] titBuff;
            }
            return false;
        }
        scannerOptions->titles[i] = titBuff;

        bufferSize = paraTable.desBuff[i].length() + 1;
        char* desBuff = new (std::nothrow) char[bufferSize];
        if (!CopySingleBuf(desBuff, paraTable.desBuff[i].c_str(), bufferSize)) {
            if (desBuff != nullptr) {
                delete[] desBuff;
            }
            return false;
        }
        scannerOptions->descriptions[i] = desBuff;

        bufferSize = paraTable.rangesBuff[i].length() + 1;
        char* rangesBuff = new (std::nothrow) char[bufferSize];
        if (!CopySingleBuf(rangesBuff, paraTable.rangesBuff[i].c_str(), bufferSize)) {
            if (rangesBuff != nullptr) {
                delete[] rangesBuff;
            }
            return false;
        }
        scannerOptions->ranges[i] = rangesBuff;
    }
    return true;
}

Scan_ScannerOptions* GetScanParaValue(ScanParaTable &paraTable)
{
    int32_t optionCount = paraTable.lengthBuff;
    if (optionCount <= 0) {
        SCAN_HILOGE("optionCount <= 0");
        return nullptr;
    }
    Scan_ScannerOptions* scannerOptions = CreateScannerOptions(optionCount);
    if (scannerOptions == nullptr) {
        SCAN_HILOGE("scannerOptions is a nullptr");
        return nullptr;
    }
    if (!MemSetScannerOptions(scannerOptions, optionCount, paraTable)) {
        SCAN_HILOGE("MemSetScannerOptions error");
        FreeScannerOptionsMemory(scannerOptions);
        return nullptr;
    }
    return scannerOptions;
}

int32_t GetScanOptionValue(const uint32_t& valueType, const ValueMap& valueMap,
    const char* value, ScanOptionValue& scanOptionValue)
{
    std::string strvalue = std::string(value);
    if (valueType == SCAN_INT_TYPE) {
        if (!valueMap.numList.count(strvalue)) {
            SCAN_HILOGE("not exit this value: %{public}s", strvalue.c_str());
            return SCAN_ERROR_INVALID_PARAMETER;
        }
        int32_t intValue = 0;
        if (!ScanUtil::ConvertToInt(strvalue, intValue)) {
            SCAN_HILOGE("strvalue : %{public}s can not parse to number.", strvalue.c_str());
            return SCAN_ERROR_GENERIC_FAILURE;
        }
        scanOptionValue.SetNumValue(intValue);
        scanOptionValue.SetScanOptionValueType(SCAN_VALUE_NUM);
    } else if (valueType == SCAN_STRING_TYPE) {
        if (!valueMap.strList.count(strvalue)) {
            SCAN_HILOGE("not exit this value: %{public}s", strvalue.c_str());
            return SCAN_ERROR_INVALID_PARAMETER;
        }
        scanOptionValue.SetStrValue(strvalue);
        scanOptionValue.SetScanOptionValueType(SCAN_VALUE_STR);
    } else {
        SCAN_HILOGE("not exist this type: %{public}u", valueType);
        return SCAN_ERROR_GENERIC_FAILURE;
    }
    return SCAN_ERROR_NONE;
}

}

int32_t OH_Scan_Init()
{
    SCAN_HILOGI("Enter OH_Scan_Init");
    auto client = ScanManagerClient::GetInstance();
    int32_t scanVersion = 0;
    int32_t ret = client->InitScan(scanVersion);
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("InitScan failed, ErrorCode: [%{public}d]", ret);
        return ret;
    } else {
        SCAN_HILOGI("InitScan successfully");
        return SCAN_ERROR_NONE;
    }
}

int32_t OH_Scan_StartScannerDiscovery(Scan_ScannerDiscoveryCallback callback)
{
    g_discoverCallback = callback;
    auto client = ScanManagerClient::GetInstance();
    int32_t ret = SCAN_ERROR_NONE;
    if (!g_isListening) {
        OHOS::sptr<IScanCallback> call = new (std::nothrow) ScanCallback(callbackFunction);
        if (call == nullptr) {
            SCAN_HILOGE("call is null");
            return SCAN_ERROR_GENERIC_FAILURE;
        }
        ret = client->On("", std::string(GET_SCANNER_DEVICE_LIST), call);
        if (ret != SCAN_ERROR_NONE) {
            SCAN_HILOGE("Failed to register event");
            return ret;
        }
        g_isListening = true;
    }
    ret = client->GetScannerList();
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("Failed to GetScannerList");
        return ret;
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
    int32_t ret = client->OpenScanner(std::string(scannerId));
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("OpenScanner failed, ErrorCode: [%{public}d]", ret);
        return ret;
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
    int32_t ret = client->CloseScanner(std::string(scannerId));
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("CloseScanner failed, ErrorCode: [%{public}d]", ret);
        return ret;
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
    std::string deviceId = std::string(scannerId);
    if (g_scanParaTables.find(deviceId) != g_scanParaTables.end()) {
        SCAN_HILOGW("Device parameters have been obtained.");
        *errorCode = SCAN_ERROR_NONE;
        return g_scanParaTables[deviceId];
    }
    int32_t status = SCAN_ERROR_NONE;
    ScanOptionValue value;
    status = GetScanParaDesc(deviceId, value);
    if (status != SCAN_ERROR_NONE) {
        SCAN_HILOGE("Failed to get scanner ScanOptionValue value.");
        *errorCode = status;
        return nullptr;
    }
    ScanParaTable paraTable;
    status = GetScanParaValues(deviceId, value, paraTable);
    if (status != SCAN_ERROR_NONE) {
        SCAN_HILOGE("Failed to get scanner ScanParaTable paraTable.");
        *errorCode = status;
        return nullptr;
    }

    Scan_ScannerOptions* scaParaOptions = GetScanParaValue(paraTable);
    if (scaParaOptions == nullptr) {
        *errorCode = SCAN_ERROR_GENERIC_FAILURE;
        return nullptr;
    }
    g_scanParaTables[scannerId] = scaParaOptions;
    *errorCode = SCAN_ERROR_NONE;
    return scaParaOptions;
}

int32_t OH_Scan_SetScannerParameter(const char* scannerId, const int32_t option, const char* value)
{
    if (scannerId == nullptr || value == nullptr) {
        SCAN_HILOGE("Invalid parameter.");
        return SCAN_ERROR_INVALID_PARAMETER;
    }
    auto client = ScanManagerClient::GetInstance();
    if (g_valueMap.find(scannerId) == g_valueMap.end() ||
        g_valueMap[scannerId].find(option) == g_valueMap[scannerId].end()) {
        SCAN_HILOGE("not exit this option: [%{public}d]", option);
        return SCAN_ERROR_INVALID_PARAMETER;
    }
    auto t = g_valueMap[scannerId].find(option);
    ScanOptionValue scanOptionValue;
    uint32_t valueType = g_valueMap[scannerId][option].valueType;
    int32_t ret = GetScanOptionValue(valueType, t->second, value, scanOptionValue);
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("GetScanOptionValue failed, ErxrorCode: [%{public}d]", ret);
        return ret;
    }
    
    int32_t optionIndex = t->second.optionIndex;
    int32_t info = 0;
    ret = client->OpScanOptionValue(std::string(scannerId),
        optionIndex, SCAN_ACTION_SET_VALUE, scanOptionValue, info);
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("SetScannerParameter failed, ErxrorCode: [%{public}d]", ret);
        return ret;
    } else {
        SCAN_HILOGI("SetScannerParameter successfully");
        return SCAN_ERROR_NONE;
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
    int32_t ret = client->StartScan(std::string(scannerId), batchMode);
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("StartScan failed, ErxrorCode: [%{public}d]", ret);
        return ret;
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
    int32_t ret = client->CancelScan(std::string(scannerId));
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("CancelScan failed, ErxrorCode: [%{public}d]", ret);
        return ret;
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
    int32_t ret = client->GetScanProgress(std::string(scannerId), scanProg);
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("GetScanProgress failed, ErrorCode: [%{public}d]", ret);
        return ret;
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
    auto client = ScanManagerClient::GetInstance();
    int32_t ret = client->ExitScan();
    if (ret != SCAN_ERROR_NONE) {
        SCAN_HILOGE("ExitScan failed, ErrorCode: [%{public}d]", ret);
        return ret;
    }
    for (auto table : g_scanParaTables) {
        FreeScannerOptionsMemory(table.second);
    }
    g_scanParaTables.clear();
    if (g_isListening) {
        client->Off("", std::string(GET_SCANNER_DEVICE_LIST));
    }
    SCAN_HILOGI("ExitScan successfully");
    return SCAN_ERROR_NONE;
}