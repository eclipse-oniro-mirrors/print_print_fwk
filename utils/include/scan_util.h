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
#include "sane_info.h"
#include "scan_constant.h"
#include "scan_log.h"

namespace OHOS::Scan {
class ScanUtil {
public:
    static ScanErrorCode ConvertErro(const SaneStatus status);
    static bool ConvertToInt(const std::string& str, int32_t& value);
    static bool ExtractIpAddresses(const std::string& str, std::string& ip);
    static std::string ReplaceIpAddress(const std::string& deviceId, const std::string& newIp);
    static std::vector<std::string> ExtractIpOrPortFromUrl(const std::string& url,
                                                           const char delimiter, const int32_t minTokenLength);
};
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
inline std::vector<std::string> ScanUtil::ExtractIpOrPortFromUrl(const std::string& url,
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
} // namespace OHOS::Scan

#endif // SCAN_UTIL_H
