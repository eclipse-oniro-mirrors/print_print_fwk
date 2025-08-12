/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "scan_context.h"
#include "scan_manager_client.h"
#include "scan_callback.h"
#include "scan_log.h"
#include "securec.h"
#include "scan_option_value.h"
#include "scan_util.h"

namespace OHOS::Scan {
constexpr int32_t YES_VALUE = 1;
constexpr int32_t NO_VALUE = 1;

ScanContext::ScanContext() {}

ScanContext::~ScanContext()
{
    Clear();
}

ScanContext& ScanContext::GetInstance()
{
    static ScanContext instance;
    return instance;
}

void ScanContext::ExecuteCallback(const std::vector<ScanDeviceInfo>& infos)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (discoverCallback_ == nullptr) {
        SCAN_HILOGE("discoverCallback_ is a nullptr");
        return;
    }
    int32_t deviceCount = static_cast<int32_t>(infos.size());
    if (deviceCount == 0) {
        SCAN_HILOGD("not found devices");
        discoverCallback_(nullptr, 0);
        return;
    }
    constexpr int32_t maxDeviceCount = 1000;
    if (deviceCount > maxDeviceCount) {
        SCAN_HILOGE("deviceCount [%{public}d] exceeded the maximum value", deviceCount);
    }
    Scan_ScannerDevice** devices = new (std::nothrow) Scan_ScannerDevice* [deviceCount]{};
    if (devices == nullptr) {
        SCAN_HILOGE("devices is a nullptr");
        discoverCallback_(nullptr, 0);
    }
    for (int i = 0; i < deviceCount; i++) {
        Scan_ScannerDevice* device = new (std::nothrow) Scan_ScannerDevice();
        if (device == nullptr) {
            SCAN_HILOGE("devices is a nullptr");
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
    discoverCallback_(devices, deviceCount);
    for (int32_t i = 0; i < deviceCount; i++) {
        DELETE_AND_NULLIFY(devices[i]);
    }
    DELETE_ARRAY_AND_NULLIFY(devices);
}

int32_t ScanContext::GetScannerParaCount(const std::string& deviceId, int32_t& scannerParaCount)
{
    auto client = ScanManagerClient::GetInstance();
    if (client == nullptr) {
        SCAN_HILOGE("client is a nullptr");
        return SCAN_ERROR_GENERIC_FAILURE;
    }
    ScanOptionDescriptor desc;
    int32_t ret = client->GetScanOptionDesc(deviceId, 0, desc);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("GetScanOptionDesc failed, ErrorCode: [%{public}d]", ret);
        return StatusConvert(ret);
    }
    uint32_t optionType = desc.GetOptionType();
    ScanOptionValue value;
    value.SetScanOptionValueType(static_cast<ScanOptionValueType>(optionType));
    ret = client->OpScanOptionValue(deviceId, 0, SCAN_ACTION_GET_VALUE, value);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("OpScanOptionValue failed, ErrorCode: [%{public}d]", ret);
        return StatusConvert(ret);
    }
    scannerParaCount = value.GetNumValue();
    return SCAN_ERROR_NONE;
}

bool ScanContext::ParaIndexConvert(const int32_t option, int32_t& innerOption, const std::string& deviceId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = innerScanParaTables_.find(deviceId);
    if (it == innerScanParaTables_.end()) {
        SCAN_HILOGE("cannot find deviceId [%{public}s] in innerScanParaTables", deviceId.c_str());
        return false;
    }
    auto& tablePtr = it->second;
    if (tablePtr == nullptr) {
        SCAN_HILOGE("tablePtr is a nullptr");
        return false;
    }
    auto& indexMap = tablePtr->indexMap;
    auto indexMapIt = indexMap.find(option);
    if (indexMapIt == indexMap.end()) {
        SCAN_HILOGE("cannot find option [%{public}d] in indexMap", option);
        return false;
    }
    innerOption = indexMapIt->second;
    return true;
}

int32_t ScanContext::GetScannerParameter(const std::string &deviceId,
    int32_t scannerParaCount, ScanParaTable &paraTable)
{
    int32_t buffLength = 0;
    for (int i = 1; i < scannerParaCount; i++) {
        ScanOptionDescriptor desc;
        auto client = ScanManagerClient::GetInstance();
        if (client == nullptr) {
            SCAN_HILOGE("client is a nullptr");
            return SCAN_ERROR_GENERIC_FAILURE;
        }
        int32_t ret = client->GetScanOptionDesc(deviceId, i, desc);
        if (ret != SCAN_ERROR_NONE) {
            SCAN_HILOGE("GetScanOptionDesc failed, ErrorCode: [%{public}d]", ret);
            return StatusConvert(ret);
        }
        if (SetParaTable(desc, paraTable, buffLength)) {
            paraTable.indexMap.insert({buffLength, i});
            buffLength++;
        }
    }
    paraTable.buffLength = buffLength;
    return SCAN_ERROR_NONE;
}

std::string ScanContext::SetRangeStrInParaTable(const ScanOptionDescriptor& desc,
    ScanParaTable& paraTable, const int32_t& buffLength)
{
    std::string rangeStr;
    uint32_t constraintType = desc.GetOptionConstraintType();
    uint32_t optionType = desc.GetOptionType();
    if (constraintType == SCAN_CONSTRAINT_WORD_LIST) {
        std::vector<std::int32_t> optionConstraintNumber;
        desc.GetOptionConstraintNumber(optionConstraintNumber);
        for (auto t : optionConstraintNumber) {
            std::string numStr = std::to_string(t);
            rangeStr.append(numStr).append(",");
        }
        rangeStr.pop_back();
    } else if (constraintType == SCAN_CONSTRAINT_STRING_LIST) {
        std::vector<std::string> optionConstraintString;
        desc.GetOptionConstraintString(optionConstraintString);
        for (auto t : optionConstraintString) {
            rangeStr.append(t).append(",");
        }
        rangeStr.pop_back();
    } else if (constraintType == SCAN_CONSTRAINT_RANGE) {
        ScanRange range;
        desc.GetOptionConstraintRange(range);
        int32_t minValue = range.GetMinValue();
        int32_t maxValue = range.GetMaxValue();
        int32_t quantValue = range.GetQuantValue();
        if (quantValue != 0) {
            minValue /= quantValue;
            maxValue /= quantValue;
            paraTable.quantMap[buffLength] = quantValue;
        }
        const std::string symbol = "..";
        rangeStr.append(std::to_string(minValue).append(symbol).append(std::to_string(maxValue)));
    } else if (constraintType == SCAN_CONSTRAINT_NONE && optionType == SCAN_VALUE_BOOL) {
        rangeStr = "yes,no";
    } else {
        SCAN_HILOGD("not support ConstraintType[%{public}u], optionType[%{public}u]", constraintType, optionType);
        return "";
    }
    return rangeStr;
}

std::string ScanContext::GetPhysicalUnitDesc(uint32_t physicalUnit)
{
    static const std::map<uint32_t, std::string> physicalUnitDescMap = {
        {SCANNER_UNIT_PIXEL, "(Physical unit is number of pixels)"},
        {SCANNER_UNIT_BIT, "(Physical unit is number of bits)"},
        {SCANNER_UNIT_MM, "(Physical unit is millimeters)"},
        {SCANNER_UNIT_DPI, "(Physical unit is resolution in dots/inch)"},
        {SCANNER_UNIT_PERCENT, "(Physical unit is a percentage)"},
        {SCANNER_UNIT_MICROSECOND, "(Physical unit is micro seconds)"},
    };
    auto it = physicalUnitDescMap.find(physicalUnit);
    if (it == physicalUnitDescMap.end()) {
        SCAN_HILOGW("physicalUnit [%{public}u] is not exist", physicalUnit);
        return "";
    }
    return it->second;
}

bool ScanContext::SetParaTable(ScanOptionDescriptor& desc, ScanParaTable& paraTable, int32_t& buffLength)
{
    std::string rangeStr = SetRangeStrInParaTable(desc, paraTable, buffLength);
    if (rangeStr == "") {
        SCAN_HILOGE("SetRangeStrInParaTable fail");
        return false;
    }
    uint32_t optionType = desc.GetOptionType();
    paraTable.optionTypeBuff.emplace_back(optionType);
    paraTable.rangesBuff.emplace_back(rangeStr);
    paraTable.titBuff.emplace_back(desc.GetOptionTitle());
    std::string optionDesc = desc.GetOptionDesc();
    uint32_t physicalUnit = desc.GetOptionUnit();
    if (physicalUnit != SCANNER_UNIT_NONE) {
        optionDesc.append(GetPhysicalUnitDesc(physicalUnit));
    }
    paraTable.desBuff.emplace_back(optionDesc);
    return true;
}

int32_t ScanContext::GetOptionValueFromTable(const std::string& deviceId, int32_t option,
    const char* value, ScanOptionValue& optionValue)
{
    auto* paraTable = GetScanParaTable(deviceId);
    std::lock_guard<std::mutex> lock(mutex_);
    if (paraTable == nullptr) {
        SCAN_HILOGE("cannot find scannerId [%{private}s] in parameter tables.", deviceId.c_str());
        return SCAN_ERROR_INVALID_PARAMETER;
    }
    if (value == nullptr) {
        SCAN_HILOGE("value is a nullptr");
        return SCAN_ERROR_INVALID_PARAMETER;
    }
    if (option < 0 || option >= paraTable->buffLength) {
        SCAN_HILOGE("cannot find option [%{private}d] in parameter tables.", option);
        return SCAN_ERROR_INVALID_PARAMETER;
    }
    uint32_t optionType = paraTable->optionTypeBuff[option];
    optionValue.SetScanOptionValueType(static_cast<ScanOptionValueType>(optionType));
    if (optionType == SCAN_VALUE_STR) {
        optionValue.SetStrValue(std::string(value));
    } else if (optionType == SCAN_VALUE_BOOL) {
        if (strcmp(value, "yes") == 0) {
            optionValue.SetNumValue(YES_VALUE);
        } else if (strcmp(value, "no") == 0) {
            optionValue.SetNumValue(NO_VALUE);
        } else {
            SCAN_HILOGE("option [%{private}d] is invalid.", option);
            return SCAN_ERROR_INVALID_PARAMETER;
        }
    } else {
        int32_t numValue = 0;
        if (!ScanUtil::ConvertToInt(std::string(value), numValue)) {
            SCAN_HILOGE("option [%{private}d] is invalid.", option);
            return SCAN_ERROR_INVALID_PARAMETER;
        }
        auto quantIt = paraTable->quantMap.find(option);
        if (quantIt != paraTable->quantMap.end()) {
            numValue *= quantIt->second;
        }
        optionValue.SetNumValue(numValue);
    }
    return SCAN_ERROR_NONE;
}

void ScanContext::FreeScannerOptionsMemory(Scan_ScannerOptions* scannerOptions)
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

Scan_ScannerOptions* ScanContext::CreateScannerOptions(int32_t &optionCount)
{
    constexpr int32_t maxOptionCount = 1000;
    if (optionCount > maxOptionCount) {
        SCAN_HILOGE("optionCount [%{public}d] exceeded the maximum value", optionCount);
        return nullptr;
    }
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
    int32_t stringMemSize = optionCount * sizeof(char*);
    if (memset_s(scannerOptions->titles, stringMemSize, 0, stringMemSize) != 0 ||
        memset_s(scannerOptions->descriptions, stringMemSize, 0, stringMemSize) != 0 ||
        memset_s(scannerOptions->ranges, stringMemSize, 0, stringMemSize) != 0) {
            SCAN_HILOGW("memset_s fail");
            FreeScannerOptionsMemory(scannerOptions);
            return nullptr;
    }
    return scannerOptions;
}

bool ScanContext::CopySingleBuf(char* destBuf, const char* srcBuf, size_t bufferSize)
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

bool ScanContext::MemSetScannerOptions(Scan_ScannerOptions* scannerOptions,
    int32_t &optionCount, ScanParaTable &paraTable)
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

Scan_ScannerOptions* ScanContext::ConvertToScannerOptions(ScanParaTable &paraTable)
{
    int32_t optionCount = paraTable.buffLength;
    if (optionCount <= 0) {
        SCAN_HILOGE("optionCount is less than 0");
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

int32_t ScanContext::StatusConvert(int32_t status)
{
    static const std::map<uint32_t, uint32_t> errorCodeMap = {
        {E_SCAN_GENERIC_FAILURE, SCAN_ERROR_GENERIC_FAILURE},
        {E_SCAN_RPC_FAILURE, SCAN_ERROR_RPC_FAILURE},
        {E_SCAN_SERVER_FAILURE, SCAN_ERROR_SERVER_FAILURE},
        {E_SCAN_UNSUPPORTED, SCAN_ERROR_UNSUPPORTED},
        {E_SCAN_CANCELLED, SCAN_ERROR_CANCELED},
        {E_SCAN_DEVICE_BUSY, SCAN_ERROR_DEVICE_BUSY},
        {E_SCAN_INVAL, SCAN_ERROR_INVALID},
        {E_SCAN_JAMMED, SCAN_ERROR_JAMMED},
        {E_SCAN_NO_DOCS, SCAN_ERROR_NO_DOCS},
        {E_SCAN_COVER_OPEN, SCAN_ERROR_COVER_OPEN},
        {E_SCAN_IO_ERROR, SCAN_ERROR_IO_ERROR},
        {E_SCAN_NO_MEM, SCAN_ERROR_NO_MEMORY},
        {E_SCAN_ACCESS_DENIED, SCAN_ERROR_INVALID}
    };
    auto it = errorCodeMap.find(status);
    if (it != errorCodeMap.end()) {
        return it->second;
    } else {
        SCAN_HILOGE("StatusConvert failed, status: [%{public}d]", status);
        return E_SCAN_GENERIC_FAILURE;
    }
}

void ScanContext::Clear()
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& pair : exScanParaTables_) {
        FreeScannerOptionsMemory(pair.second);
    }
    exScanParaTables_.clear();
    innerScanParaTables_.clear();
    discoverCallback_ = nullptr;
}

ScanParaTable* ScanContext::GetScanParaTable(const std::string& scannerId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = innerScanParaTables_.find(scannerId);
    return it != innerScanParaTables_.end() ? it->second.get() : nullptr;
}

void ScanContext::SetScanParaTable(const std::string& scannerId, std::unique_ptr<ScanParaTable> table)
{
    std::lock_guard<std::mutex> lock(mutex_);
    innerScanParaTables_[scannerId] = std::move(table);
}

Scan_ScannerOptions* ScanContext::GetScannerOptions(const std::string& scannerId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = exScanParaTables_.find(scannerId);
    return it != exScanParaTables_.end() ? it->second : nullptr;
}

void ScanContext::SetScannerOptions(const std::string& scannerId, Scan_ScannerOptions* options)
{
    std::lock_guard<std::mutex> lock(mutex_);
    exScanParaTables_[scannerId] = options;
}

void ScanContext::SetDiscoverCallback(Scan_ScannerDiscoveryCallback callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    discoverCallback_ = callback;
}

const std::string& ScanContext::GetRegisterType()
{
    static const std::string discoveryRegistryType = "GET_SCANNER_DEVICE_LIST";
    return discoveryRegistryType;
}
}  // namespace OHOS::Scan