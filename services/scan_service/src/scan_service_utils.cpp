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
#include <sstream>
#include <iomanip>
#include "scan_log.h"
#include "scan_service_utils.h"

namespace OHOS::Scan {
std::string ScanServiceUtils::ReplaceDeviceIdUsbPort(const std::string& deviceId, const std::string& usbPort)
{
    constexpr int32_t invalidPort = -1;
    int32_t start = invalidPort;
    int32_t end = invalidPort;
    char dash;
    std::istringstream(usbPort) >> start >> dash >> end;
    if (start < 0 || end < 0 || dash != '-') {
        SCAN_HILOGE("usbPort format is error");
        return "";
    }
    std::ostringstream oss;
    char zero = '0';
    constexpr int32_t portWidth = 3;
    oss << std::setw(portWidth) << std::setfill(zero) << start;
    std::string formattedStart = oss.str();
    oss.str("");
    oss << std::setw(portWidth) << std::setfill(zero) << end;
    std::string formattedEnd = oss.str();
    size_t pos1 = deviceId.rfind(':');
    if (pos1 == std::string::npos) {
        SCAN_HILOGE("deviceId format is error");
        return "";
    }
    size_t pos2 = deviceId.rfind(':', pos1 - 1);
    if (pos2 == std::string::npos) {
        SCAN_HILOGE("deviceId format is error");
        return "";
    }
    std::string newDeviceId = deviceId.substr(0, pos2 + 1).append(formattedStart).append(":").append(formattedEnd);
    SCAN_HILOGD("new deviceId = %{private}s", newDeviceId.c_str());
    return newDeviceId;
}
}  // namespace OHOS::Scan