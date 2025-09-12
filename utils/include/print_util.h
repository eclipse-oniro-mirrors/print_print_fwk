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
#include <charconv>
#include <iostream>
#include <sstream>
#include <list>
#include <vector>
#include <string>
#include <regex>

#include "print_log.h"

namespace OHOS::Print {
const uint32_t MAX_PRINTER_NAME_LENGTH = 127;
const uint32_t MIN_INT_LIST_STRLENGTH = 2;
const uint32_t MAX_BUFFER_SIZE = 1024;
class PrintUtil {
public:
    static std::string ParseListToString(const std::vector<std::string> &list);

    static std::string SplitStr(const std::string& str, char delimiter, int index);

    static std::string ToUpper(const std::string& str);

    static bool CheckContains(const std::string& str, const std::string& content);

    static std::string StandardizePrinterName(std::string printerName);

    static std::string RemoveUnderlineFromPrinterName(std::string printerName);

    static std::vector<uint32_t> Str2Vec(std::string str);

    static void Str2VecStr(std::string& str, std::vector<std::string>& vec);

    static bool startsWith(const std::string& str, const std::string& prefix);

    static bool ConvertToInt(const std::string& str, int32_t& value);
    
    static void SafeDeleteAuthInfo(char *userPasswd);
};

inline std::vector<uint32_t> PrintUtil::Str2Vec(std::string str)
{
    if (str.size() < MIN_INT_LIST_STRLENGTH) {
        return {};
    }
    str.pop_back();
    str.erase(str.begin());
    std::vector<uint32_t> vec;
    std::istringstream is(str);
    std::string temp;
    while (getline(is, temp, ',')) {
        int32_t tempNum = 0;
        if (!ConvertToInt(temp, tempNum)) {
            return {};
        }
        vec.push_back(tempNum);
    }
    return vec;
}

inline void PrintUtil::Str2VecStr(std::string& str, std::vector<std::string>& vec)
{
    if (!str.empty()) {
        str.pop_back();
        str.erase(str.begin());
        std::istringstream is(str);
        std::string temp;
        while (getline(is, temp, ',')) {
            vec.push_back(temp);
        }
    }
}

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

inline std::string PrintUtil::RemoveUnderlineFromPrinterName(std::string printerName)
{
    std::regex pattern("[_]");
    std::string name = std::regex_replace(printerName, pattern, " ");
    if (name.length() < MAX_PRINTER_NAME_LENGTH) {
        return name;
    }
    return name.substr(0, MAX_PRINTER_NAME_LENGTH - 1);
}

inline bool PrintUtil::startsWith(const std::string& str, const std::string& prefix)
{
    if (str.length() < prefix.length()) {
        return false;
    }
    return str.compare(0, prefix.length(), prefix) == 0;
}

inline bool PrintUtil::ConvertToInt(const std::string& str, int32_t& value)
{
    auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), value);
    return ec == std::errc{} && ptr == str.data() + str.size();
}

inline void PrintUtil::SafeDeleteAuthInfo(char *userPasswd)
{
    if (userPasswd == nullptr) {
        PRINT_HILOGE("The ptr is nullptr!");
        return;
    }
    uint32_t userPasswdLength = strnlen(userPasswd, MAX_BUFFER_SIZE);
    for (size_t i = 0; i < userPasswdLength; i++) {
        userPasswd[i] = '\0';
    }
    delete []userPasswd;
    userPasswd = nullptr;
}

} // namespace OHOS::Print

#endif // PRINT_UTIL_H