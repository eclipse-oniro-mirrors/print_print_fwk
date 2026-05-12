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

#include "print_security_guard_util.h"
#include "print_constant.h"
#include <map>

namespace OHOS::Print {

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
    {PRINT_JOB_BLOCKED_INVALID_NUMBER_UP, "invalid_number_up"},
    {PRINT_JOB_BLOCKED_PRINTER_UNAVAILABLE, "printer_unavailable"},
    {PRINT_JOB_BLOCKED_UNKNOWN, "unknown"}
};

std::string SubStateToErrorCodeStr(uint32_t subState)
{
    auto it = SUBSTATE_ERROR_MAP.find(subState);
    if (it != SUBSTATE_ERROR_MAP.end()) {
        return it->second;
    }
    return "other_error";
}

std::vector<std::string> GenerateErrorCodes(const std::set<uint32_t> &blockedSubStates)
{
    std::set<std::string> errorSet;
    
    auto addErrorCode = [&errorSet](uint32_t subState) {
        std::string code = SubStateToErrorCodeStr(subState);
        if (code == "unknown" || code == "other_error") {
            errorSet.insert("unknown");
        } else {
            errorSet.insert(code);
        }
    };
    
    constexpr int SUB_STATE_CODE_DIGITS = 2;
    constexpr int MAX_SINGLE_SUB_STATE_CODE = 99;

    for (uint32_t subState : blockedSubStates) {
        if (subState > MAX_SINGLE_SUB_STATE_CODE) {
            std::string codeStr = std::to_string(subState);
            if (codeStr.length() % SUB_STATE_CODE_DIGITS != 0) {
                codeStr = "0" + codeStr;
            }
            for (size_t i = 0; i < codeStr.length(); i += SUB_STATE_CODE_DIGITS) {
                uint32_t singleState = std::stoul(codeStr.substr(i, SUB_STATE_CODE_DIGITS));
                addErrorCode(singleState);
            }
        } else {
            addErrorCode(subState);
        }
    }
    return std::vector<std::string>(errorSet.begin(), errorSet.end());
}

} // namespace OHOS::Print
