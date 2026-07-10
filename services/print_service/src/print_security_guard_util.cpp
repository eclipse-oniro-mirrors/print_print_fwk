/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "print_security_guard_util.h"
#include "print_constant.h"
#include "print_json_util.h"
#include "print_log.h"

#include <algorithm>
#include <charconv>
#include <unordered_set>

namespace OHOS::Print {

namespace {

static const std::map<uint32_t, std::string> SUBSTATE_ERROR_MAP = {
    {PRINT_JOB_COMPLETED_SUCCESS, "success"},
    {PRINT_JOB_COMPLETED_FAILED, "failed"},
    {PRINT_JOB_COMPLETED_CANCELLED, "cancelled"},
    {PRINT_JOB_COMPLETED_FILE_CORRUPT, "file_corrupt"},
    {PRINT_JOB_BLOCKED_OFFLINE, "offline"},
    {PRINT_JOB_BLOCKED_BUSY, "busy"},
    {PRINT_JOB_BLOCKED_CANCELLED, "cancelled"},
    {PRINT_JOB_BLOCKED_OUT_OF_PAPER, "out_of_paper"},
    {PRINT_JOB_BLOCKED_OUT_OF_INK, "out_of_ink"},
    {PRINT_JOB_BLOCKED_OUT_OF_TONER, "out_of_toner"},
    {PRINT_JOB_BLOCKED_JAMMED, "jammed"},
    {PRINT_JOB_BLOCKED_DOOR_OPEN, "door_open"},
    {PRINT_JOB_BLOCKED_SERVICE_REQUEST, "service_request"},
    {PRINT_JOB_BLOCKED_LOW_ON_INK, "low_on_ink"},
    {PRINT_JOB_BLOCKED_LOW_ON_TONER, "low_on_toner"},
    {PRINT_JOB_BLOCKED_REALLY_LOW_ON_INK, "really_low_on_ink"},
    {PRINT_JOB_BLOCKED_BAD_CERTIFICATE, "bad_certificate"},
    {PRINT_JOB_BLOCKED_ACCOUNT_ERROR, "account_error"},
    {PRINT_JOB_BLOCKED_PRINT_PERMISSION_ERROR, "print_permission_error"},
    {PRINT_JOB_BLOCKED_PRINT_COLOR_PERMISSION_ERROR, "color_permission_error"},
    {PRINT_JOB_BLOCKED_DRIVER_EXCEPTION, "driver_exception"},
    {PRINT_JOB_BLOCKED_NETWORK_ERROR, "network_error"},
    {PRINT_JOB_BLOCKED_SERVER_CONNECTION_ERROR, "server_connection_error"},
    {PRINT_JOB_BLOCKED_LARGE_FILE_ERROR, "large_file_error"},
    {PRINT_JOB_BLOCKED_FILE_PARSING_ERROR, "file_parsing_error"},
    {PRINT_JOB_BLOCKED_SLOW_FILE_CONVERSION, "slow_file_conversion"},
    {PRINT_JOB_BLOCK_FILE_UPLOADING_ERROR, "file_uploading_error"},
    {PRINT_JOB_BLOCKED_DRIVER_MISSING, "driver_missing"},
    {PRINT_JOB_BLOCKED_INTERRUPT, "interrupt"},
    {PRINT_JOB_BLOCKED_AUTHENTICATION, "authentication_required"},
    {PRINT_JOB_BLOCKED_BANNED, "banned"},
    {PRINT_JOB_BLOCKED_SMB_PRINTER, "smb_printer_error"},
    {PRINT_JOB_BLOCKED_INPUT_TRAY_MISSING, "input_tray_missing"},
    {PRINT_JOB_BLOCKED_SECURITY_POLICY_RESTRICTED, "security_policy_restricted"},
    {PRINT_JOB_BLOCKED_PRINTER_UNAVAILABLE, "printer_unavailable"},
    {PRINT_JOB_BLOCKED_UNKNOWN, ERROR_CODE_UNKNOWN}
};

std::string SubStateToErrorCodeStr(uint32_t subState)
{
    auto it = SUBSTATE_ERROR_MAP.find(subState);
    if (it != SUBSTATE_ERROR_MAP.end()) {
        return it->second;
    }
    return ERROR_CODE_OTHER_ERROR;
}

} // namespace

std::vector<std::string> GenerateErrorCodes(const std::set<uint32_t> &blockedSubStates)
{
    std::set<std::string> errorSet;
    
    auto addErrorCode = [&errorSet](uint32_t subState) {
        if (subState == PRINT_JOB_COMPLETED_SUCCESS) {
            return;
        }
        std::string code = SubStateToErrorCodeStr(subState);
        if (code == ERROR_CODE_UNKNOWN || code == ERROR_CODE_OTHER_ERROR) {
            errorSet.insert(ERROR_CODE_UNKNOWN);
        } else {
            errorSet.insert(code);
        }
    };
    
    for (uint32_t subState : blockedSubStates) {
        if (subState > maxSingleSubStateCode) {
            std::string codeStr = std::to_string(subState);
            while (codeStr.length() % subStateCodeDigits != 0) {
                codeStr = "0" + codeStr;
            }
            for (size_t i = 0; i < codeStr.length(); i += subStateCodeDigits) {
                std::string chunk = codeStr.substr(i, subStateCodeDigits);
                uint32_t singleState = 0;
                auto [ptr, ec] = std::from_chars(chunk.data(), chunk.data() + chunk.size(), singleState);
                if (ec != std::errc{}) {
                    continue;
                }
                addErrorCode(singleState);
            }
        } else {
            addErrorCode(subState);
        }
    }
    return std::vector<std::string>(errorSet.begin(), errorSet.end());
}

static void ExtractFileListFromJsonArray(const Json::Value &array, std::vector<std::string> &fileList)
{
    for (const auto &file : array) {
        if (file.isString()) {
            fileList.push_back(file.asString());
        }
    }
}

std::vector<std::string> PrintSecurityGuardUtil::ExtractFileListFromOption(const std::string &option)
{
    std::vector<std::string> fileList;
    Json::Value optionJson;
    if (!PrintJsonUtil::Parse(option, optionJson)) {
        return fileList;
    }
    if (PrintJsonUtil::IsMember(optionJson, "fileList") && optionJson["fileList"].isArray()) {
        ExtractFileListFromJsonArray(optionJson["fileList"], fileList);
    } else if (PrintJsonUtil::IsMember(optionJson, "jobName") && optionJson["jobName"].isString()) {
        fileList.push_back(optionJson["jobName"].asString());
    }
    return fileList;
}

namespace {
constexpr size_t URL_HEX_DIGITS = 2;
constexpr int HEX_RADIX = 16;
constexpr int HEX_ALPHA_OFFSET = 10;

bool HexCharToInt(char c, int &value)
{
    if (c >= '0' && c <= '9') {
        value = c - '0';
    } else if (c >= 'a' && c <= 'f') {
        value = c - 'a' + HEX_ALPHA_OFFSET;
    } else if (c >= 'A' && c <= 'F') {
        value = c - 'A' + HEX_ALPHA_OFFSET;
    } else {
        return false;
    }
    return true;
}
} // namespace

std::string PrintSecurityGuardUtil::UrlDecode(const std::string &str)
{
    std::string result;
    result.reserve(str.size());
    for (size_t i = 0; i < str.size(); i++) {
        if (str[i] == '%' && i + URL_HEX_DIGITS < str.size()) {
            int high = 0;
            int low = 0;
            if (HexCharToInt(str[i + 1], high) && HexCharToInt(str[i + URL_HEX_DIGITS], low)) {
                result += static_cast<char>(high * HEX_RADIX + low);
                i += URL_HEX_DIGITS;
            } else {
                result += str[i];
            }
        } else if (str[i] == '+') {
            result += ' ';
        } else {
            result += str[i];
        }
    }
    return result;
}

static const std::unordered_set<std::string> PRINTABLE_EXTENSIONS = {
    ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".ico", ".dng",
    ".jpg", ".jpe", ".jfif", ".jif",
    ".docx", ".doc", ".txt", ".docm", ".dot", ".dotx", ".dotm",
    ".wps", ".wpt", ".rtf", ".xml",
    ".htm", ".html", ".mht", ".mhtml",
    ".xlsx", ".xls", ".et", ".ett", ".xlt", ".xlsm", ".xltx", ".csv", ".xlsb",
    ".ppt", ".pptx", ".dps", ".dpt", ".potm", ".potx", ".pot",
    ".ppsm", ".ppsx", ".pps", ".pptm",
    ".pdf",
};

bool PrintSecurityGuardUtil::IsPrintableFile(const std::string &fileName)
{
    auto dotPos = fileName.rfind('.');
    if (dotPos == std::string::npos) {
        return false;
    }
    std::string ext = fileName.substr(dotPos);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return PRINTABLE_EXTENSIONS.find(ext) != PRINTABLE_EXTENSIONS.end();
}

} // namespace OHOS::Print
