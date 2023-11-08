/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "print_utils.h"

#include <fcntl.h>
#include "ability.h"
#include "print_constant.h"
#include "print_log.h"
#include "securec.h"

namespace OHOS::Print {
static std::map<uint32_t, std::string> jobStateMap_;
const std::string GLOBAL_ID_DELIMITER = ":";
const std::string EXTENSION_CID_DELIMITER = ":";
const std::string TASK_EVENT_DELIMITER = "-";

std::string PrintUtils::ToLower(const std::string &s)
{
    std::string res = s;
    std::transform(res.begin(), res.end(), res.begin(), tolower);
    return res;
}

std::string PrintUtils::GetExtensionId(const std::string &globalId)
{
    auto pos = globalId.find(GLOBAL_ID_DELIMITER);
    if (pos == std::string::npos) {
        return "";
    }
    return globalId.substr(0, pos);
}

std::string PrintUtils::GetGlobalId(const std::string& extensionId, const std::string& localId)
{
    return extensionId + GLOBAL_ID_DELIMITER + localId;
}

std::string PrintUtils::GetLocalId(const std::string& globalId, const std::string& extensionId)
{
    auto pos = globalId.find(GLOBAL_ID_DELIMITER);
    if (pos == std::string::npos) {
        return "";
    }

    if (globalId.substr(0, pos) != extensionId) {
        return "";
    }
    return globalId.substr(pos + 1);
}

std::string PrintUtils::EncodeExtensionCid(const std::string &extensionId, uint32_t callbackId)
{
    return extensionId + EXTENSION_CID_DELIMITER + std::to_string(callbackId);
}

bool PrintUtils::DecodeExtensionCid(const std::string &cid, std::string &extensionId, uint32_t &callbackId)
{
    auto pos = cid.find(EXTENSION_CID_DELIMITER);
    if (pos == std::string::npos) {
        return false;
    }
    extensionId = cid.substr(0, pos);
    callbackId = static_cast<uint32_t>(atoi(cid.substr(pos + 1).c_str()));
    return true;
}

std::string PrintUtils::GetTaskEventId(const std::string &taskId, const std::string &type)
{
    return type + TASK_EVENT_DELIMITER + taskId;
}

int32_t PrintUtils::OpenFile(const std::string &filePath)
{
    if (!IsPathValid(filePath)) {
        return PRINT_INVALID_ID;
    }
    int32_t fd = open(filePath.c_str(), O_RDONLY);
    PRINT_HILOGD("fd: %{public}d", fd);
    if (fd < 0) {
        PRINT_HILOGE("Failed to open file errno: %{public}s", std::to_string(errno).c_str());
        close(fd);
        return PRINT_INVALID_ID;
    }
    return fd;
}

bool PrintUtils::IsPathValid(const std::string &filePath)
{
    auto path = filePath.substr(0, filePath.rfind('/'));
    char resolvedPath[PATH_MAX] = { 0 };
    if (path.length() >= PATH_MAX || realpath(path.c_str(), resolvedPath) == nullptr ||
        strncmp(resolvedPath, path.c_str(), path.length()) != 0) {
        PRINT_HILOGE("invalid file path!");
        return false;
    }
    return true;
}

uint32_t PrintUtils::GetIdFromFdPath(const std::string &fdPath)
{
    std::string fd_str = fdPath.substr(fdPath.rfind('/') + 1, fdPath.length());
    std::stringstream getStrStream(fd_str);
    uint32_t fd;
    if (!(getStrStream >> fd)) {
        PRINT_HILOGD("failed to convert to uint32");
    }
    return fd;
}

std::string PrintUtils::GetJobStateChar(const uint32_t state)
{
    if (jobStateMap_.size() == 0) {
        jobStateMap_[PRINT_JOB_PREPARED] = "PRINT_JOB_PREPARED";
        jobStateMap_[PRINT_JOB_QUEUED] = "PRINT_JOB_QUEUED";
        jobStateMap_[PRINT_JOB_RUNNING] = "PRINT_JOB_RUNNING";
        jobStateMap_[PRINT_JOB_BLOCKED] = "PRINT_JOB_BLOCKED";
        jobStateMap_[PRINT_JOB_COMPLETED] = "PRINT_JOB_COMPLETED";
        jobStateMap_[PRINT_JOB_CREATE_FILE_COMPLETED] = "PRINT_JOB_CREATE_FILE_COMPLETED";
        jobStateMap_[PRINT_JOB_UNKNOWN] = "PRINT_JOB_UNKNOWN";
    }
    auto it = jobStateMap_.find(state);
    if (it != jobStateMap_.end()) {
        return it -> second;
    }
    return "PRINT_JOB_UNKNOWN";
}
}  // namespace OHOS::Print
