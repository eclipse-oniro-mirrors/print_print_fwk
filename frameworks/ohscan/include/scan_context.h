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

#ifndef SCAN_CONTEXT_H
#define SCAN_CONTEXT_H

#include <map>
#include <vector>
#include <string>
#include <mutex>
#include "ohscan.h"
#include "scanner_info.h"
#include "scan_option_descriptor.h"
#include "scan_option_value.h"

namespace OHOS::Scan {
struct ScanParaTable {
    std::vector<std::string> titBuff;
    std::vector<std::string> desBuff;
    std::vector<std::string> rangesBuff;
    std::vector<uint32_t> optionTypeBuff;
    std::map<int32_t, int32_t> quantMap; // key is index, value is quant
    std::map<int32_t, int32_t> indexMap; // key is outerIndex, value is index in sane-backends
    int32_t buffLength = 0;
};

class ScanContext {
public:
    static ScanContext& GetInstance();
    ScanContext(const ScanContext&) = delete;
    ScanContext& operator=(const ScanContext&) = delete;
    ScanContext(ScanContext&&) = delete;
    ScanContext& operator=(ScanContext&&) = delete;

    void SetDiscoverCallback(Scan_ScannerDiscoveryCallback callback);
    void ExecuteCallback(const std::vector<ScanDeviceInfo>& infos);
    Scan_ScannerOptions* ConvertToScannerOptions(ScanParaTable& paraTable);
    int32_t GetScannerParaCount(const std::string& deviceId, int32_t& scannerParaCount);
    int32_t GetScannerParameter(const std::string& deviceId, int32_t scannerParaCount, ScanParaTable& paraTable);
    void SetScannerOptions(const std::string& scannerId, Scan_ScannerOptions* options);
    Scan_ScannerOptions* GetScannerOptions(const std::string& scannerId);
    void SetScanParaTable(const std::string& scannerId, std::unique_ptr<ScanParaTable> table);
    bool IsListening() const;
    void SetListening(bool listening);
    const std::string& GetRegisterType();
    void Clear();
    bool ParaIndexConvert(const int32_t option, int32_t& innerOption, const std::string& deviceId);
    int32_t GetOptionValueFromTable(const std::string& deviceId, int32_t option,
        const char* value, ScanOptionValue& optionValue);
    static int32_t StatusConvert(int32_t status);

private:
    ScanContext();
    ~ScanContext();

    bool SetParaTable(ScanOptionDescriptor& desc, ScanParaTable& paraTable, int32_t& buffLength);
    Scan_ScannerOptions* CreateScannerOptions(int32_t& optionCount);
    bool CopySingleBuf(char* destBuf, const char* srcBuf, size_t bufferSize);
    bool MemSetScannerOptions(Scan_ScannerOptions* scannerOptions, int32_t& optionCount, ScanParaTable& paraTable);
    void FreeScannerOptionsMemory(Scan_ScannerOptions* scannerOptions);
    ScanParaTable* GetScanParaTable(const std::string& scannerId);
    std::string GetPhysicalUnitDesc(uint32_t physicalUnit);
    std::string SetRangeStrInParaTable(const ScanOptionDescriptor& desc,
        ScanParaTable& paraTable, const int32_t& buffLength);

    mutable std::mutex mutex_;
    std::map<std::string, Scan_ScannerOptions*> exScanParaTables_;
    std::map<std::string, std::unique_ptr<ScanParaTable>> innerScanParaTables_;
    bool isListening_ = false;
    Scan_ScannerDiscoveryCallback discoverCallback_ = nullptr;
};
} // namespace OHOS::Scan
#endif // SCAN_CONTEXT_H
