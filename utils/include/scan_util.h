/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef SCAN_UTIL_H
#define SCAN_UTIL_H

#include <algorithm>
#include <charconv>
#include <iostream>
#include <sstream>
#include <list>
#include <vector>
#include <iomanip>
#include <regex>
#include <string>
#include "scan_constant.h"
#include "scan_log.h"
#ifdef SANE_ENABLE
#include "sane/sane.h"
#include "sane/saneopts.h"
#endif

namespace OHOS::Scan {
class ScanUtil {
public:
    #ifdef SANE_ENABLE
    static ScanErrorCode ConvertErro(const SANE_Status status);
    #endif
    static bool ConvertToInt(const std::string& str, int32_t& value);
    static bool ExtractIpAddresses(const std::string& str, std::string& ip);
    static std::string ReplaceIpAddress(const std::string& deviceId, const std::string& newIp);
};
#ifdef SANE_ENABLE
inline ScanErrorCode ScanUtil::ConvertErro(const SANE_Status status)
{
    return static_cast<ScanErrorCode> (status + E_SCAN_GOOD);
}
#endif
inline bool ScanUtil::ConvertToInt(const std::string& str, int32_t& value)
{
    auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), value);
    return ec == std::errc{} && ptr == str.data() + str.size();
}
inline bool ScanUtil::ExtractIpAddresses(const std::string& str, std::string& ip)
{
    std::regex ipRegex(R"((\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b))");
    std::smatch match;
    if (std::regex_search(str, match, ipRegex)) {
        ip = match[0];
        return true;
    } else {
        return false;
    }
}
inline std::string ScanUtil::ReplaceIpAddress(const std::string& deviceId, const std::string& newIp)
{
    std::regex ipRegex(R"((\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b))");
    return std::regex_replace(deviceId, ipRegex, newIp);
}
} // namespace OHOS::Scan

#endif // SCAN_UTIL_H
