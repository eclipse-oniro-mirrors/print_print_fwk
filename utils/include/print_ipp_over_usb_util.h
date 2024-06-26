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
 
#ifndef PRINT_IPP_OVER_USB__UTIL_H
#define PRINT_IPP_OVER_USB__UTIL_H
#include <sstream>
#include <iostream>
#include <iomanip>
#include "httplib.h"
#include "print_log.h"
#include "print_ipp_over_usb_constant.h"

#define TAG "HttpUSB"

namespace OHOS::Print {
using namespace httplib;

class PrintIppOverUsbUtil {
public:
    static std::string Uint8ToHexString(const uint8_t *v, const size_t s);

    static std::string IntToHexString(unsigned int v);

    static void TrimString(std::string &s);

    static bool IsStartWithHttpHeader(uint8_t *data, size_t length);

    static bool IsEndWithHttpResponse(uint8_t *data, size_t length);

    static void MakeHeader(size_t startLine, size_t endline, const uint8_t *data, httplib::Response &httpResponse);

    static void DumpRespCode(const uint8_t *data, size_t dataLength, size_t start, size_t dumpLength);

    static int ConstructHttpResponse(const uint8_t *v, const size_t length, httplib::Response &httpResponse);
};

inline std::string PrintIppOverUsbUtil::Uint8ToHexString(const uint8_t *v, const size_t s)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < s; i++) {
        ss << std::hex << std::setw(HTTP_COMMON_CONST_VALUE_2) << static_cast<int>(v[i]) << " ";
    }
    return ss.str();
}

inline std::string PrintIppOverUsbUtil::IntToHexString(unsigned int v)
{
    std::stringstream ss;
    ss << std::hex << v;
    std::string temp;
    ss >> temp;
    return temp;
}

inline void PrintIppOverUsbUtil::TrimString(std::string &s)
{
    if (!s.empty()) {
        s.erase(0, s.find_first_not_of(" "));
        s.erase(s.find_last_not_of(" ") + 1);
    }
}

inline bool PrintIppOverUsbUtil::IsStartWithHttpHeader(uint8_t *data, size_t length)
{ // 是一段http报文的开头
    if (length > HTTP_COMMON_CONST_VALUE_5 && data[INDEX_0] == HTTP_RESPONSE_H &&
        data[INDEX_1] == HTTP_RESPONSE_T && data[INDEX_2] == HTTP_RESPONSE_T &&
        data[INDEX_3] == HTTP_RESPONSE_P &&
        data[INDEX_4] == HTTP_RESPONSE_VERSION_SPLIT_GANG) {
        return true;
    }
    return false;
}

inline bool PrintIppOverUsbUtil::IsEndWithHttpResponse(uint8_t *data, size_t length)
{ // 是一段http报文的结尾
    if (data[INDEX_0] == IPP_END_SPLIT_VALUE && length == HTTP_COMMON_CONST_VALUE_1) {
        return true;
    } else if (length > HTTP_COMMON_CONST_VALUE_6 && data[INDEX_1] == HTTP_RESPONSE_H &&
        data[INDEX_2] == HTTP_RESPONSE_T && data[INDEX_3] == HTTP_RESPONSE_T &&
        data[INDEX_4] == HTTP_RESPONSE_P &&
        data[INDEX_5] == HTTP_RESPONSE_VERSION_SPLIT_GANG) {
        return true;
    } else {
        return false;
    }
}

void PrintIppOverUsbUtil::MakeHeader(size_t startLine, size_t endline, const uint8_t *data,
    httplib::Response &httpResponse)
{
    // 提取key和value
    size_t theSplitIndex = startLine; // ":" 所在的位置
    while (data[theSplitIndex] != CODE_SPLIT_VALUE_COLON && theSplitIndex < endline) {
        theSplitIndex++;
    }
    std::string keyString;
    std::string valueString;
    for (size_t i = startLine; i < theSplitIndex; i++) {
        keyString += data[i];
    }
    for (size_t i = theSplitIndex + 1; i <= endline; i++) {
        valueString += data[i];
    }
    TrimString(keyString);
    TrimString(valueString);
    PRINT_HILOGD("keyString :%{public}s, valueString :%{public}s", keyString.c_str(), valueString.c_str());
    if (HTTP_CONTENT_LENGTH != keyString) {
        httpResponse.set_header(keyString, valueString);
    }
}

inline void PrintIppOverUsbUtil::DumpRespCode(const uint8_t *data, size_t dataLength, size_t start, size_t dumpLength)
{
    for (size_t i = start; i < dataLength && i < (start + dumpLength); i++) {
        PRINT_HILOGE("Resp :%{public}x", data[i]);
    }
}

int PrintIppOverUsbUtil::ConstructHttpResponse(const uint8_t *readBuf, const size_t length,
    httplib::Response &httpResponse)
{
    PRINT_HILOGD("start construct_http_response length :%{public}lu", length);
    if (length <= HTTP_COMMON_CONST_VALUE_6) {
        return INVAILD_VALUE;
    }
    const uint8_t *bufTmp = readBuf;
    size_t index = 0;
    size_t startline = index;
    size_t endline = index;
    while (index < length - INDEX_3) {
        bool isHeaerEnd = (bufTmp[index] == HTTP_SPLIT_R_CODE && bufTmp[index + INDEX_1] == HTTP_SPLIT_N_CODE &&
            bufTmp[index + INDEX_2] == HTTP_SPLIT_R_CODE &&
            bufTmp[index + INDEX_3] == HTTP_SPLIT_N_CODE);
        if (isHeaerEnd) {
            break;
        }
        bool isLineBegin = (index > INDEX_2 && bufTmp[index - INDEX_2] == HTTP_SPLIT_R_CODE &&
            bufTmp[index - INDEX_1] == HTTP_SPLIT_N_CODE);
        if (isLineBegin) { // 识别出一行的第一个字符
            startline = index;
            endline = startline;
            // 识别出一行的行尾
            while (!(bufTmp[endline + INDEX_1] == HTTP_SPLIT_R_CODE &&
                bufTmp[endline + INDEX_2] == HTTP_SPLIT_N_CODE)) {
                endline++;
            }
            MakeHeader(startline, endline, readBuf, httpResponse);
            index++;
        } else {
            index++;
        }
    }
    DumpRespCode(bufTmp, length, index + HTTP_COMMON_CONST_VALUE_4, HTTP_COMMON_CONST_VALUE_8);
    if (index < length - HTTP_COMMON_CONST_VALUE_4) {
        httpResponse.version = "1.1";
        httpResponse.status = HTTP_RESPONSE_STATUS_200;
        httpResponse.reason = "OK";
        std::string body;
        index = index + HTTP_COMMON_CONST_VALUE_4;
        while (index < length) {
            body += bufTmp[index];
            index++;
        }
        httpResponse.body = body;
        return 0;
    } else {
        return INVAILD_VALUE;
    }
}
}
#endif // PRINT_IPP_OVER_USB__UTIL_H