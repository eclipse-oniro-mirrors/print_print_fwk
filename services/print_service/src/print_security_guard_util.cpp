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
#include "print_log.h"
#include <cups/cups.h>
#include <fcntl.h>
#include <map>
#include <sstream>
#include <iomanip>
#include <unistd.h>

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

std::vector<std::string> GenerateErrorCodes(const std::set<uint32_t> &blockedSubStates)
{
    std::set<std::string> errorSet;
    
    auto addErrorCode = [&errorSet](uint32_t subState) {
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
            if (codeStr.length() % subStateCodeDigits != 0) {
                codeStr = "0" + codeStr;
            }
            for (size_t i = 0; i < codeStr.length(); i += subStateCodeDigits) {
                uint32_t singleState = std::stoul(codeStr.substr(i, subStateCodeDigits));
                addErrorCode(singleState);
            }
        } else {
            addErrorCode(subState);
        }
    }
    return std::vector<std::string>(errorSet.begin(), errorSet.end());
}

static constexpr int32_t HEX_STRING_WIDTH = 2;

std::string PrintSecurityGuardUtil::Md5HashBuffer(const char* data, size_t size)
{
    if (data == nullptr || size == 0) {
        PRINT_HILOGE("Md5HashBuffer invalid input");
        return "";
    }
    unsigned char hash[16];
    ssize_t result = cupsHashData("md5", data, size, hash, sizeof(hash));
    if (result != sizeof(hash)) {
        PRINT_HILOGE("Md5HashBuffer cupsHashData failed, result: %{public}zd, expected: %{public}zu",
            result, sizeof(hash));
        return "";
    }
    std::stringstream ss;
    for (ssize_t i = 0; i < result; i++) {
        ss << std::hex << std::setw(HEX_STRING_WIDTH) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string PrintSecurityGuardUtil::CalculateFileMd5(uint32_t fd)
{
    int32_t fdInt = static_cast<int32_t>(fd);
    if (fdInt < 0) {
        PRINT_HILOGE("CalculateFileMd5 invalid fd");
        return "";
    }
    int32_t dupFd = dup(fdInt);
    if (dupFd < 0) {
        PRINT_HILOGE("CalculateFileMd5 dup failed, fd: %{public}d, errno: %{public}d", fdInt, errno);
        return "";
    }
    off_t fileSize = lseek(dupFd, 0, SEEK_END);
    if (fileSize == static_cast<off_t>(-1)) {
        PRINT_HILOGE("CalculateFileMd5 lseek to end failed, fd: %{public}d, errno: %{public}d", fdInt, errno);
        close(dupFd);
        return "";
    }
    if (fileSize == 0) {
        PRINT_HILOGE("CalculateFileMd5 file size is 0, fd: %{public}d", fdInt);
        close(dupFd);
        return "";
    }
    lseek(dupFd, 0, SEEK_SET);
    std::vector<char> buffer(fileSize);
    size_t totalRead = 0;
    while (totalRead < static_cast<size_t>(fileSize)) {
        ssize_t bytesRead = read(dupFd, buffer.data() + totalRead, fileSize - totalRead);
        if (bytesRead < 0) {
            PRINT_HILOGE("CalculateFileMd5 read failed, fd: %{public}d, errno: %{public}d", fdInt, errno);
            close(dupFd);
            return "";
        }
        if (bytesRead == 0) {
            break;
        }
        totalRead += static_cast<size_t>(bytesRead);
    }
    if (lseek(dupFd, 0, SEEK_SET) != 0) {
        PRINT_HILOGW("CalculateFileMd5 lseek back to begin failed, fd: %{public}d, errno: %{public}d", fdInt, errno);
    }
    close(dupFd);
    if (totalRead != static_cast<size_t>(fileSize)) {
        PRINT_HILOGE("CalculateFileMd5 read failed, fd: %{public}d, read: %{public}zu, expect: %{public}ld",
            fdInt, totalRead, fileSize);
        return "";
    }
    return Md5HashBuffer(buffer.data(), static_cast<size_t>(fileSize));
}

uint64_t PrintSecurityGuardUtil::GetFileSize(uint32_t fd)
{
    int32_t fdInt = static_cast<int32_t>(fd);
    if (fdInt < 0) {
        PRINT_HILOGE("GetFileSize invalid fd");
        return 0;
    }
    int32_t dupFd = dup(fdInt);
    if (dupFd < 0) {
        PRINT_HILOGE("GetFileSize dup failed, fd: %{public}d, errno: %{public}d", fdInt, errno);
        return 0;
    }
    off_t fileSize = lseek(dupFd, 0, SEEK_END);
    if (lseek(dupFd, 0, SEEK_SET) != 0) {
        PRINT_HILOGW("GetFileSize lseek back to begin failed, fd: %{public}d, errno: %{public}d", fdInt, errno);
    }
    close(dupFd);
    if (fileSize == static_cast<off_t>(-1)) {
        PRINT_HILOGE("GetFileSize lseek to end failed, fd: %{public}d, errno: %{public}d", fdInt, errno);
        return 0;
    }
    return static_cast<uint64_t>(fileSize);
}

std::vector<FileAuditInfo> PrintSecurityGuardUtil::CalculateFileAuditInfo(
    const std::vector<std::string> &fileList, const std::vector<uint32_t> &fdList)
{
    std::vector<FileAuditInfo> fileInfos;
    size_t fileCount = std::min(fileList.size(), fdList.size());
    PRINT_HILOGI("CalculateFileAuditInfo fileList: %{public}zu, fdList: %{public}zu",
        fileList.size(), fdList.size());
    for (size_t i = 0; i < fileCount; i++) {
        FileAuditInfo info;
        info.fileName = fileList[i];
        info.md5 = CalculateFileMd5(fdList[i]);
        info.size = GetFileSize(fdList[i]);
        PRINT_HILOGI("CalculateFileAuditInfo file[%{public}zu] name: %{public}s, md5: %{public}s, size: %{public}llu",
            i, fileList[i].c_str(), info.md5.c_str(), (unsigned long long)info.size);
        fileInfos.push_back(info);
    }
    return fileInfos;
}

} // namespace OHOS::Print
