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

#ifndef NAPI_SCAN_HELPER
#define NAPI_SCAN_HELPER

#include <stdint.h>
#include <string>
#include "scan_option_descriptor.h"

namespace OHOS::Scan {
class NapiScanHelper {
public:
    static int32_t GetScannerAllPara(const std::string &deviceId, std::vector<ScanOptionDescriptor> &allDesc);
private:
    static int32_t GetScannerParaCount(const std::string& deviceId, int32_t& scannerParaCount);
    static int32_t GetScannerParameter(const std::string &deviceId,
        int32_t scannerParaCount, std::vector<ScanOptionDescriptor> &allDesc);
};
} // namespace OHOS::Scan
#endif // NAPI_SCAN_HELPER