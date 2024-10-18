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
#include "securec.h"
#include <chrono>
#include <sstream>
#include <cstdlib>
#include <ctime>
#include <random>

namespace OHOS::Print {

using json = nlohmann::json;

std::mutex PrintUtils::instanceLock_;

static const std::string LAUNCH_PARAMETER_DOCUMENT_NAME = "documentName";
static const std::string LAUNCH_PARAMETER_PRINT_ATTRIBUTE = "printAttributes";

static std::map<uint32_t, std::string> jobStateMap_;
const std::string GLOBAL_ID_DELIMITER = ":";
const std::string EXTENSION_CID_DELIMITER = ":";
const std::string TASK_EVENT_DELIMITER = "-";
const std::string USER_ID_DELIMITER = ":";
const int32_t DEFAULT_FD = 99;
const int32_t MINIMUN_RANDOM_NUMBER_100 = 100;
const int32_t MAXIMUN_RANDOM_NUMBER_999 = 999;

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

std::string PrintUtils::GetEventTypeWithToken(int32_t userId, int64_t pid, const std::string &type)
{
    std::string eventType =
        std::to_string(userId) + USER_ID_DELIMITER + std::to_string(pid) + TASK_EVENT_DELIMITER + type;
    PRINT_HILOGD("eventType: %{public}s", eventType.c_str());
    return eventType;
}

std::string PrintUtils::GetEventType(const std::string &type)
{
    auto pos = type.find(TASK_EVENT_DELIMITER);
    if (pos == std::string::npos || pos + 1 >= type.length()) {
        return type;
    }
    std::string eventType = type.substr(pos + 1);
    PRINT_HILOGD("eventType: %{public}s", eventType.c_str());
    return eventType;
}

bool CheckUserIdInEventType(const std::string &type, int32_t callerUserId)
{
    auto userIdPos = type.find(USER_ID_DELIMITER);
    auto eventPos = type.find(TASK_EVENT_DELIMITER);
    if (userIdPos == std::string::npos || eventPos == std::string::npos || userIdPos >= type.length()) {
        return E_PRINT_INVALID_USERID;
    }
    std::string userIdStr = type.substr(0, userIdPos);
    PRINT_HILOGD("userId: %{public}s", userIdStr.c_str());
    if (userIdStr == std::to_string(callerUserId)) {
        return true;
    }
    return false;
}

int32_t PrintUtils::OpenFile(const std::string &filePath)
{
    if (filePath.find("content://") == 0) {
        return DEFAULT_FD;
    }
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

void PrintUtils::BuildAdapterParam(const std::shared_ptr<AdapterParam> &adapterParam, AAFwk::Want &want)
{
    want.SetParam(LAUNCH_PARAMETER_DOCUMENT_NAME, adapterParam->documentName);
    if (adapterParam->isCheckFdList) {
        std::string defaultAttribute = "";
        want.SetParam(LAUNCH_PARAMETER_PRINT_ATTRIBUTE, defaultAttribute);
        return;
    }
    BuildPrintAttributesParam(adapterParam, want);
}

void PrintUtils::BuildPrintAttributesParam(const std::shared_ptr<AdapterParam> &adapterParam, AAFwk::Want &want)
{
    json attrJson;
    PrintAttributes attrParam = adapterParam->printAttributes;
    if (attrParam.HasCopyNumber()) {
        attrJson["copyNumber"] = attrParam.GetCopyNumber();
    }
    if (attrParam.HasSequential()) {
        attrJson["isSequential"] = attrParam.GetIsSequential();
    }
    if (attrParam.HasLandscape()) {
        attrJson["isLandscape"] = attrParam.GetIsLandscape();
    }
    if (attrParam.HasDirectionMode()) {
        attrJson["directionMode"] = attrParam.GetDirectionMode();
    }
    if (attrParam.HasColorMode()) {
        attrJson["colorMode"] = attrParam.GetColorMode();
    }
    if (attrParam.HasDuplexMode()) {
        attrJson["duplexMode"] = attrParam.GetDuplexMode();
    }
    ParseAttributesObjectParamForJson(attrParam, attrJson);
    if (attrParam.HasOption()) {
        attrJson["options"] = attrParam.GetOption();
    }
    want.SetParam(LAUNCH_PARAMETER_PRINT_ATTRIBUTE, attrJson.dump());
    PRINT_HILOGD("CallSpooler set printAttributes: %{public}s", attrJson.dump().c_str());
}

void PrintUtils::ParseAttributesObjectParamForJson(const PrintAttributes &attrParam, nlohmann::json &attrJson)
{
    if (attrParam.HasPageRange()) {
        json pageRangeJson;
        PrintRange printRangeAttr;
        attrParam.GetPageRange(printRangeAttr);
        if (printRangeAttr.HasStartPage()) {
            pageRangeJson["startPage"] = printRangeAttr.GetStartPage();
        }
        if (printRangeAttr.HasEndPage()) {
            pageRangeJson["endPage"] = printRangeAttr.GetEndPage();
        }
        if (printRangeAttr.HasPages()) {
            std::vector<uint32_t> pages;
            printRangeAttr.GetPages(pages);
            pageRangeJson["pages"] = pages;
        }
        attrJson["pageRange"] = pageRangeJson;
    }
    if (attrParam.HasPageSize()) {
        json pageSizeJson;
        PrintPageSize pageSizeAttr;
        attrParam.GetPageSize(pageSizeAttr);
        pageSizeJson["id"] = pageSizeAttr.GetId();
        pageSizeJson["name"] = pageSizeAttr.GetName();
        pageSizeJson["width"] = pageSizeAttr.GetWidth();
        pageSizeJson["height"] = pageSizeAttr.GetHeight();
        attrJson["pageSize"] = pageSizeJson;
    }
    if (attrParam.HasMargin()) {
        json marginJson;
        PrintMargin marginAttr;
        attrParam.GetMargin(marginAttr);
        if (marginAttr.HasTop()) {
            marginJson["top"] = marginAttr.GetTop();
        }
        if (marginAttr.HasBottom()) {
            marginJson["bottom"] = marginAttr.GetBottom();
        }
        if (marginAttr.HasLeft()) {
            marginJson["left"] = marginAttr.GetLeft();
        }
        if (marginAttr.HasRight()) {
            marginJson["right"] = marginAttr.GetRight();
        }
        attrJson["margin"] = marginJson;
    }
}

std::string PrintUtils::GetBundleNameForUid(const int uid)
{
    OHOS::AppExecFwk::BundleMgrClient bmsClient;
    std::string bundleName = "";
    auto ret = bmsClient.GetNameForUid(uid, bundleName);
    if (ret != OHOS::ERR_OK || bundleName.empty()) {
        PRINT_HILOGE("get bundleName failed.");
    }
    PRINT_HILOGI("bundleName: %{public}s", bundleName.c_str());
    return bundleName;
}

std::string PrintUtils::GetPrintJobId()
{
    std::lock_guard<std::mutex> autoLock(instanceLock_);
    auto nowTime = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(nowTime.time_since_epoch()).count();
    std::stringstream ss;
    ss << timestamp;

    std::random_device rd;
    std::mt19937 gen((unsigned int)time(NULL));
    std::uniform_int_distribution<> dis(MINIMUN_RANDOM_NUMBER_100, MAXIMUN_RANDOM_NUMBER_999);
    int32_t randomNumber = dis(gen);
    std::string jobId = ss.str() + "_" + std::to_string(randomNumber);
    PRINT_HILOGI("jobId: %{public}s", jobId.c_str());
    return jobId;
}
}  // namespace OHOS::Print
