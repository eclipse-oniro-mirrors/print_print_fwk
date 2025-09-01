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
#ifndef SCAN_SERVICE_UTILS_H
#define SCAN_SERVICE_UTILS_H

#include <string>
#include <stdint.h>
#include <stdbool.h>
#include "scan_constant.h"
#include "sane_info.h"

namespace OHOS::Scan {
class ScanServiceUtils {
public:
    static std::string ReplaceDeviceIdUsbPort(const std::string& deviceId, const std::string& usbPort);
    static bool EncodeTaskEventId(const std::string &eventType, std::string &type);
    static std::string GetTaskEventId(const std::string &taskId, const std::string &type,
        int32_t userId, int32_t callerPid);
    static ScanErrorCode ConvertErro(const SaneStatus status);
    static std::vector<std::string> ExtractIpOrPortFromUrl(const std::string& url,
        const char delimiter, const int32_t minTokenLength);
private:
    static std::unordered_map<SaneStatus, ScanErrorCode> saneStatusToScanErrorCodeMap_;
};
}  // namespace OHOS::Scan
#endif  // SCAN_SERVICE_UTILS_H