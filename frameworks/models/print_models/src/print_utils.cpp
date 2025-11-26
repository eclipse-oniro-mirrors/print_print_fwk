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

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fcntl.h>
#include <random>
#include <sstream>
#include "ability.h"
#include "print_util.h"
#include "securec.h"

namespace OHOS::Print {

std::mutex PrintUtils::instanceLock_;

static const std::string LAUNCH_PARAMETER_DOCUMENT_NAME = "documentName";
static const std::string LAUNCH_PARAMETER_PRINT_ATTRIBUTE = "printAttributes";
static const std::string PRINTER_ID_USB_PREFIX = "USB";

static std::map<uint32_t, std::string> jobStateMap_;
const std::string GLOBAL_ID_DELIMITER = ":";
const std::string EXTENSION_CID_DELIMITER = ":";
const std::string TASK_EVENT_DELIMITER = "-";
const std::string USER_ID_DELIMITER = ":";
const int32_t DEFAULT_FD = 99;
const int32_t MINIMUN_RANDOM_NUMBER_100 = 100;
const int32_t MAXIMUN_RANDOM_NUMBER_999 = 999;
const uint32_t URI_HOST_START_STR_LEN = 3;
const uint32_t ANONYMIZE_IPV4_LEN = 3;
const uint32_t ANONYMIZE_IPV6_LEN = 2;

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

std::string PrintUtils::GetGlobalId(const std::string &extensionId, const std::string &localId)
{
    if (localId.find(extensionId) != std::string::npos) {
        return localId;
    }
    return extensionId + GLOBAL_ID_DELIMITER + localId;
}

std::string PrintUtils::GetLocalId(const std::string &globalId, const std::string &extensionId)
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
    int32_t callbackIdTmp = 0;
    if (!PrintUtil::ConvertToInt(cid.substr(pos + 1), callbackIdTmp)) {
        return false;
    }
    callbackId = static_cast<uint32_t>(callbackIdTmp);
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

std::string PrintUtils::GetBundleName(const std::string &printerId)
{
    auto userIdPos = printerId.find(USER_ID_DELIMITER);
    if (userIdPos == std::string::npos || userIdPos >= printerId.length()) {
        return "";
    }
    std::string bundleName = printerId.substr(0, userIdPos);
    PRINT_HILOGD("bundleName: %{private}s", bundleName.c_str());
    return bundleName;
}

bool PrintUtils::CheckUserIdInEventType(const std::string &type, int32_t callerUserId)
{
    auto userIdPos = type.find(USER_ID_DELIMITER);
    if (userIdPos == std::string::npos || userIdPos >= type.length()) {
        return false;
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
        fdsan_close_with_tag(fd, PRINT_LOG_DOMAIN);
        return PRINT_INVALID_ID;
    }
    return fd;
}

bool PrintUtils::IsPathValid(const std::string &filePath)
{
    auto path = filePath.substr(0, filePath.rfind('/'));
    char resolvedPath[PATH_MAX] = {0};
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
    uint32_t fd = 0;
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
        return it->second;
    }
    return "PRINT_JOB_UNKNOWN";
}

bool PrintUtils::ExtractIpv4(const std::string &str, std::string &ip, size_t &startPos)
{
    std::regex ipRegex(R"((\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b))");
    std::smatch match;
    if (std::regex_search(str, match, ipRegex)) {
        ip = match[0];
        startPos = static_cast<size_t>(match.position());
        return true;
    }
    return false;
}

bool PrintUtils::ExtractIpv6(const std::string &str, std::string &ip, size_t &startPos)
{
    std::regex ipRegex(R"((\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b))");
    std::smatch match;
    if (std::regex_search(str, match, ipRegex)) {
        ip = match[0];
        startPos = static_cast<size_t>(match.position());
        return true;
    }
    return false;
}

std::string PrintUtils::AnonymizeIpv4(const std::string &ip)
{
    size_t lastDot = ip.find_last_of('.');
    if (lastDot != std::string::npos) {
        std::string lastOctet = ip.substr(lastDot + 1);
        if (lastOctet.find_first_of('.') == std::string::npos && lastOctet.length() <= ANONYMIZE_IPV4_LEN) {
            return ip.substr(0, lastDot + 1) + "xxx";
        }
    }
    return ip;
}

std::string PrintUtils::AnonymizeIpv6(const std::string &ip)
{
    size_t firstColon = ip.find(':');
    if (firstColon == std::string::npos) {
        return ip;
    }
    size_t secondColon = ip.find(':', firstColon + 1);
    if (secondColon == std::string::npos) {
        return ip;
    }
    size_t thirdColon = ip.find(':', secondColon + 1);
    if (thirdColon == std::string::npos) {
        return ip;
    }

    std::string middlePart = ip.substr(secondColon + 1, thirdColon - secondColon - 1);
    std::string anonymizeMiddle;
    if (middlePart.length() < ANONYMIZE_IPV6_LEN) {
        anonymizeMiddle = "xx";
    } else {
        anonymizeMiddle = middlePart.substr(0, middlePart.length() - ANONYMIZE_IPV6_LEN) + "xx";
    }
    return ip.substr(0, secondColon + 1) + anonymizeMiddle + ":xxxx:xxxx:xxxx:xxxx:xxxx";
}

std::string PrintUtils::AnonymizeUUid(const std::string &uuid)
{
    size_t pos = uuid.find_last_of('-');
    if (pos == std::string::npos) {
        return uuid;
    }
    std::string result = uuid.substr(0, pos + 1) + "x";
    return result;
}

std::string PrintUtils::AnonymizePrinterId(const std::string &printerId)
{
    if (printerId.find_last_of('-') != std::string::npos) {
        return AnonymizeUUid(printerId);
    }
    return printerId;
}

std::string PrintUtils::AnonymizePrinterUri(const std::string &printerUri)
{
    std::string ipv4;
    size_t startPos;
    std::string result = printerUri;
    if (ExtractIpv4(printerUri, ipv4, startPos)) {
        std::string anonymizeIpv4 = AnonymizeIpv4(ipv4);
        return result.replace(startPos, ipv4.length(), anonymizeIpv4);
    }

    std::string ipv6;
    if (ExtractIpv6(printerUri, ipv6, startPos)) {
        std::string anonymizeIpv6 = AnonymizeIpv6(ipv6);
        return result.replace(startPos, ipv6.length(), anonymizeIpv6);
    }
    return result;
}

std::string PrintUtils::AnonymizeIp(const std::string &ip)
{
    if (ip.find('.') != std::string::npos) {
        return AnonymizeIpv4(ip);
    } else if (ip.find(':') != std::string::npos) {
        return AnonymizeIpv6(ip);
    }
    return ip;
}

std::string PrintUtils::AnonymizeJobOption(const std::string &option)
{
    std::string anonymizeoption = option;
    std::string ip;
    size_t startPos;
    if (ExtractIpv4(option, ip, startPos)) {
        std::string anonymizeIpv4 = AnonymizeIpv4(ip);
        anonymizeoption.replace(startPos, ip.length(), anonymizeIpv4);
    } else if (ExtractIpv6(option, ip, startPos)) {
        std::string anonymizeIpv6 = AnonymizeIpv6(ip);
        anonymizeoption.replace(startPos, ip.length(), anonymizeIpv6);
    }

    if (option.find_last_of('-') != std::string::npos) {
        anonymizeoption = AnonymizeUUid(anonymizeoption);
    }
    return anonymizeoption;
}

std::string PrintUtils::AnonymizeJobName(const std::string &jobName)
{
    size_t dotPos = jobName.find_last_of('.');
    if (dotPos != std::string::npos) {
        std::string extension = jobName.substr(dotPos);
        return "xxx" + extension;
    }
    return "xxx";
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
    Json::Value attrJson;
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
    want.SetParam(LAUNCH_PARAMETER_PRINT_ATTRIBUTE, (PrintJsonUtil::WriteString(attrJson)));
    PRINT_HILOGD("CallSpooler set printAttributes: %{public}s", (PrintJsonUtil::WriteString(attrJson)).c_str());
}

Json::Value PrintUtils::CreatePageRangeJson(const PrintAttributes &attrParam)
{
    Json::Value pageRangeJson;
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
        Json::Value pagesJson;
        for (const auto &item : pages) {
            pagesJson.append(item);
        }
        pageRangeJson["pages"] = pagesJson;
    }
    return pageRangeJson;
}

Json::Value PrintUtils::CreatePageSizeJson(const PrintAttributes &attrParam)
{
    Json::Value pageSizeJson;
    PrintPageSize pageSizeAttr;
    attrParam.GetPageSize(pageSizeAttr);
    pageSizeJson["id"] = pageSizeAttr.GetId();
    pageSizeJson["name"] = pageSizeAttr.GetName();
    pageSizeJson["width"] = pageSizeAttr.GetWidth();
    pageSizeJson["height"] = pageSizeAttr.GetHeight();
    return pageSizeJson;
}

Json::Value PrintUtils::CreateMarginJson(const PrintAttributes &attrParam)
{
    Json::Value marginJson;
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
    return marginJson;
}

void PrintUtils::ParseAttributesObjectParamForJson(const PrintAttributes &attrParam, Json::Value &attrJson)
{
    if (attrParam.HasPageRange()) {
        attrJson["pageRange"] = CreatePageRangeJson(attrParam);
    }
    if (attrParam.HasPageSize()) {
        attrJson["pageSize"] = CreatePageSizeJson(attrParam);
    }
    if (attrParam.HasMargin()) {
        attrJson["margin"] = CreateMarginJson(attrParam);
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
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(MINIMUN_RANDOM_NUMBER_100, MAXIMUN_RANDOM_NUMBER_999);
    int32_t randomNumber = dis(gen);
    std::string jobId = ss.str() + "_" + std::to_string(randomNumber);
    PRINT_HILOGI("jobId: %{public}s", jobId.c_str());
    return jobId;
}

bool PrintUtils::IsUsbPrinter(const std::string &printerId)
{
    auto pos = printerId.find(PRINTER_ID_USB_PREFIX);
    if (pos == std::string::npos) {
        return false;
    }
    return true;
}

std::string PrintUtils::ExtractHostFromUri(const std::string &uri)
{
    size_t startPos = uri.find("://");
    if (startPos == std::string::npos) {
        return "";
    }
    startPos += URI_HOST_START_STR_LEN;
    size_t atPos = uri.find('@', startPos);
    if (atPos != std::string::npos) {
        startPos = atPos + 1;
    }
    size_t endPos = uri.find_first_of("/?#:", startPos);
    if (endPos == std::string::npos) {
        return uri.substr(startPos);
    }
    return uri.substr(startPos, endPos - startPos);
}
}  // namespace OHOS::Print
