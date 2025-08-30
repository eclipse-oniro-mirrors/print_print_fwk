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
const std::string TASK_EVENT_DELIMITER = "-";
std::unordered_map<SaneStatus, ScanErrorCode> ScanServiceUtils::saneStatusToScanErrorCodeMap_ = {
    {SANE_STATUS_GOOD, E_SCAN_NONE},
    {SANE_STATUS_UNSUPPORTED, E_SCAN_UNSUPPORTED},
    {SANE_STATUS_CANCELLED, E_SCAN_CANCELLED},
    {SANE_STATUS_DEVICE_BUSY, E_SCAN_DEVICE_BUSY},
    {SANE_STATUS_INVAL, E_SCAN_INVAL},
    {SANE_STATUS_EOF, E_SCAN_EOF},
    {SANE_STATUS_JAMMED, E_SCAN_JAMMED},
    {SANE_STATUS_NO_DOCS, E_SCAN_NO_DOCS},
    {SANE_STATUS_COVER_OPEN, E_SCAN_COVER_OPEN},
    {SANE_STATUS_IO_ERROR, E_SCAN_IO_ERROR},
    {SANE_STATUS_NO_MEM, E_SCAN_NO_MEM},
    {SANE_STATUS_ACCESS_DENIED, E_SCAN_ACCESS_DENIED},
    {SANE_STATUS_NO_PERMISSION, E_SCAN_NO_PERMISSION},
    {SANE_STATUS_INVALID_PARAMETER, E_SCAN_INVALID_PARAMETER},
    {SANE_STATUS_GENERIC_FAILURE, E_SCAN_GENERIC_FAILURE},
    {SANE_STATUS_RPC_FAILURE, E_SCAN_RPC_FAILURE},
    {SANE_STATUS_SERVER_FAILURE, E_SCAN_SERVER_FAILURE}
};
std::string ScanServiceUtils::ReplaceDeviceIdUsbPort(const std::string& deviceId, const std::string& usbPort)
{
    constexpr int32_t invalidPort = -1;
    int32_t start = invalidPort;
    int32_t end = invalidPort;
    char dash = '\0';
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

bool ScanServiceUtils::EncodeTaskEventId(const std::string &eventType, std::string &type)
{
    size_t pos = eventType.find_last_of(TASK_EVENT_DELIMITER);
    if (pos != std::string::npos) {
        type = eventType.substr(pos + 1);
        return true;
    }
    return false;
}

std::string ScanServiceUtils::GetTaskEventId(const std::string &taskId, const std::string &type,
    int32_t userId, int32_t callerPid)
{
    std::ostringstream eventTypeStream;
    eventTypeStream << userId << TASK_EVENT_DELIMITER << callerPid << TASK_EVENT_DELIMITER;
    if (!taskId.empty()) {
        eventTypeStream << taskId << TASK_EVENT_DELIMITER;
    }
    eventTypeStream << type;
    return eventTypeStream.str();
}

ScanErrorCode ScanServiceUtils::ConvertErro(const SaneStatus status)
{
    auto it = saneStatusToScanErrorCodeMap_.find(status);
    if (it != saneStatusToScanErrorCodeMap_.end()) {
        return it->second;
    }
    return E_SCAN_GENERIC_FAILURE;
}

std::vector<std::string> ScanServiceUtils::ExtractIpOrPortFromUrl(const std::string& url,
    const char delimiter, const int32_t minTokenLength)
{
    std::vector<std::string> tokens;
    size_t start = 0;
    size_t end = url.find(delimiter);
    while (end != std::string::npos) {
        tokens.push_back(url.substr(start, end - start));
        start = end + 1;
        end = url.find(delimiter, start);
    }
    tokens.push_back(url.substr(start));
    if (tokens.size() < minTokenLength) {
        SCAN_HILOGE("Url size < %{public}d ", minTokenLength);
        tokens.clear();
    }
    return tokens;
}
}  // namespace OHOS::Scan