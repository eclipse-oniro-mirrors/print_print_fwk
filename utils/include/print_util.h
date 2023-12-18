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

#ifndef PRINT_UTIL_H
#define PRINT_UTIL_H

#include <algorithm>
#include <iostream>
#include <sstream>
#include <list>
#include <vector>
#include <string>
#include <regex>

#include "print_log.h"

namespace OHOS::Print {
const uint32_t MAX_PRINTER_NAME_LENGTH = 127;
class PrintUtil {
public:
    static std::string ParseListToString(const std::vector<std::string> &list);

    static std::string SplitStr(const std::string& str, char delimiter, int index);

    static std::string ToUpper(const std::string& str);

    static bool CheckContains(const std::string& str, const std::string& content);

    static std::string StandardizePrinterName(std::string printerName);
};

inline std::string PrintUtil::ParseListToString(const std::vector<std::string> &list)
{
    std::string str;
    if (!list.empty()) {
        uint32_t count = 1;
        uint32_t size = list.size();
        for (auto val: list) {
            str += val;
            if (count < size) {
                str += ",";
            }
            count ++;
        }
    }
    return str;
}

inline std::string PrintUtil::SplitStr(const std::string& str, char delimiter, int index)
{
    if (!str.empty()) {
        std::string token;
        std::istringstream tokenStream(str);
        int count = 0;
        while (std::getline(tokenStream, token, delimiter)) {
            if (count == index) {
                return token;
            }
            count ++;
        }
    }
    return str;
}

inline std::string PrintUtil::ToUpper(const std::string& val)
{
    std::string str = val;
    if (!str.empty()) {
        std::transform(str.begin(), str.end(), str.begin(), toupper);
    }
    return str;
}

inline bool PrintUtil::CheckContains(const std::string& str, const std::string& content)
{
    if (str.empty() || content.empty()) {
        return false;
    }

    return str.find(content) != std::string::npos;
}

inline std::string PrintUtil::StandardizePrinterName(std::string printerName)
{
    std::regex pattern("[ /#]");
    std::string name = std::regex_replace(printerName, pattern, "_");
    if (name.length() < MAX_PRINTER_NAME_LENGTH) {
        return name;
    }
    return name.substr(0, MAX_PRINTER_NAME_LENGTH - 1);
}
} // namespace OHOS::Print

#endif // PRINT_UTIL_H