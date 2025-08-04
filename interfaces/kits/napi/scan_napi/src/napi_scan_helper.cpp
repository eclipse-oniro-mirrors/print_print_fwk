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
#include <vector>
#include "scan_manager_client.h"
#include "napi_scan_helper.h"
#include "scan_constant.h"
#include "scan_log.h"

namespace OHOS::Scan {
int32_t NapiScanHelper::GetScannerAllPara(const std::string &deviceId, std::vector<ScanOptionDescriptor> &allDesc)
{
    int32_t scannerParaCount = 0;
    int32_t ret = GetScannerParaCount(deviceId, scannerParaCount);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("Failed to get the scan para count");
        return ret;
    }
    ret = GetScannerParameter(deviceId, scannerParaCount, allDesc);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("Failed to get the scan para count");
        return ret;
    }
    return E_SCAN_NONE;
}

int32_t NapiScanHelper::GetScannerParaCount(const std::string& deviceId, int32_t& scannerParaCount)
{
    auto client = ScanManagerClient::GetInstance();
    if (client == nullptr) {
        SCAN_HILOGE("client is a nullptr");
        return E_SCAN_GENERIC_FAILURE;
    }
    ScanOptionDescriptor desc;
    int32_t ret = client->GetScanOptionDesc(deviceId, 0, desc);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("GetScanOptionDesc failed, ErrorCode: [%{public}d]", ret);
        return ret;
    }
    uint32_t optionType = desc.GetOptionType();
    ScanOptionValue value;
    value.SetScanOptionValueType(static_cast<ScanOptionValueType>(optionType));
    ret = client->OpScanOptionValue(deviceId, 0, SCAN_ACTION_GET_VALUE, value);
    if (ret != E_SCAN_NONE) {
        SCAN_HILOGE("OpScanOptionValue failed, ErrorCode: [%{public}d]", ret);
        return ret;
    }
    scannerParaCount = value.GetNumValue();
    return E_SCAN_NONE;
}

int32_t NapiScanHelper::GetScannerParameter(const std::string &deviceId,
    int32_t scannerParaCount, std::vector<ScanOptionDescriptor> &allDesc)
{
    for (int i = 1; i < scannerParaCount; i++) {
        ScanOptionDescriptor desc;
        auto client = ScanManagerClient::GetInstance();
        if (client == nullptr) {
            SCAN_HILOGE("client is a nullptr");
            return E_SCAN_GENERIC_FAILURE;
        }
        int32_t ret = client->GetScanOptionDesc(deviceId, i, desc);
        if (ret != E_SCAN_NONE) {
            SCAN_HILOGE("GetScanOptionDesc failed, ErrorCode: [%{public}d]", ret);
            return ret;
        }
        desc.SetOptionIndex(i);
        allDesc.push_back(desc);
    }
    return E_SCAN_NONE;
}

} // namespace OHOS::Scan