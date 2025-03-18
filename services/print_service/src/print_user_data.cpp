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

#include "print_user_data.h"
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <streambuf>
#include <json/json.h>

#include "print_log.h"
#include "print_constant.h"
#include "print_json_util.h"

namespace OHOS {
namespace Print {

void PrintUserData::RegisterPrinterCallback(const std::string &type, const sptr<IPrintCallback> &listener)
{
    registeredListeners_[type] = listener;
}

void PrintUserData::UnregisterPrinterCallback(const std::string &type)
{
    auto iter = registeredListeners_.find(type);
    if (iter != registeredListeners_.end()) {
        registeredListeners_.erase(iter);
    }
}

void PrintUserData::SendPrinterEvent(const std::string &type, int event, const PrinterInfo &info)
{
    auto iter = registeredListeners_.find(type);
    if (iter != registeredListeners_.end() && iter->second != nullptr) {
        iter->second->OnCallback(event, info);
    }
}

void PrintUserData::AddToPrintJobList(const std::string jobId, const std::shared_ptr<PrintJob> &printjob)
{
    printJobList_.insert(std::make_pair(jobId, printjob));
}

void PrintUserData::UpdateQueuedJobList(
    const std::string &jobId, const std::shared_ptr<PrintJob> &printJob, std::string jobOrderId)
{
    if (jobOrderId == "0") {
        jobOrderList_.clear();
    }
    auto jobIt = printJobList_.find(jobId);
    if (jobIt == printJobList_.end()) {
        PRINT_HILOGE("invalid job id");
        return;
    }
    printJobList_.erase(jobIt);

    if (queuedJobList_.find(jobId) != queuedJobList_.end()) {
        queuedJobList_[jobId] = printJob;
        jobOrderList_[jobOrderId] = jobId;
    } else {
        queuedJobList_.insert(std::make_pair(jobId, printJob));
        jobOrderList_.insert(std::make_pair(jobOrderId, jobId));
    }
}

int32_t PrintUserData::QueryPrintJobById(std::string &printJobId, PrintJob &printJob)
{
    if (printJobList_.empty()) {
        PRINT_HILOGE("printJobList is empty!");
        return E_PRINT_INVALID_PRINTJOB;
    }
    auto jobIt = printJobList_.find(printJobId);
    if (jobIt == printJobList_.end()) {
        PRINT_HILOGW("no print job exists");
        return E_PRINT_INVALID_PRINTJOB;
    } else {
        if (jobIt->second != nullptr) {
            printJob = *jobIt->second;
        }
    }
    PRINT_HILOGI("QueryPrintJobById End.");
    return E_PRINT_NONE;
}

int32_t PrintUserData::QueryAllPrintJob(std::vector<PrintJob> &printJobs)
{
    printJobs.clear();
    for (auto iter : jobOrderList_) {
        PRINT_HILOGI("QueryAllPrintJob queuedJobList_ jobOrderId: %{public}s, jobId: %{public}s",
            iter.first.c_str(),
            iter.second.c_str());
        auto jobIt = queuedJobList_.find(iter.second);
        if (jobIt == queuedJobList_.end()) {
            PRINT_HILOGW("This job dose not exist.");
            continue;
        } else {
            if (jobIt->second != nullptr) {
                printJobs.emplace_back(*jobIt->second);
            }
        }
    }
    PRINT_HILOGI("QueryAllPrintJob End.");
    return E_PRINT_NONE;
}

void PrintUserData::SetUserId(int32_t userId)
{
    userId_ = userId;
}

int32_t PrintUserData::SetLastUsedPrinter(const std::string &printerId)
{
    PRINT_HILOGI("begin SetLastUsedPrinter, printerId: %{private}s", printerId.c_str());
    if (printerId.empty()) {
        PRINT_HILOGE("printerId is empty");
        return E_PRINT_INVALID_PARAMETER;
    }
    std::lock_guard<std::recursive_mutex> lock(userDataMutex_);
    lastUsedPrinterId_ = printerId;
    
    DeletePrinterFromUsedPrinterList(printerId);
    usedPrinterList_.push_front(printerId);
    PRINT_HILOGI("put printer at the head of the queue, printerId: %{private}s", usedPrinterList_.front().c_str());
    if (useLastUsedPrinterForDefault_) {
        defaultPrinterId_ = printerId;
        PRINT_HILOGI("set the last used printer as the default printer");
    }
    if (!SetUserDataToFile()) {
        PRINT_HILOGE("SetUserDataToFile failed.");
        return E_PRINT_SERVER_FAILURE;
    }

    return E_PRINT_NONE;
}

std::string PrintUserData::GetLastUsedPrinter()
{
    std::lock_guard<std::recursive_mutex> lock(userDataMutex_);
    return lastUsedPrinterId_;
}

int32_t PrintUserData::SetDefaultPrinter(const std::string &printerId, uint32_t type)
{
    std::lock_guard<std::recursive_mutex> lock(userDataMutex_);
    PRINT_HILOGI("begin SetDefaultPrinter");
    PRINT_HILOGD("printerId: %{private}s", printerId.c_str());
    PRINT_HILOGI("type: %{public}d", type);
    if (type == DEFAULT_PRINTER_TYPE_SETTED_BY_USER) {
        defaultPrinterId_ = printerId;
        useLastUsedPrinterForDefault_ = false;
    } else if (type == DEFAULT_PRINTER_TYPE_LAST_USED_PRINTER || type == DELETE_DEFAULT_PRINTER) {
        defaultPrinterId_ = lastUsedPrinterId_;
        useLastUsedPrinterForDefault_ = true;
    } else if (type == DELETE_LAST_USED_PRINTER) {
        defaultPrinterId_ = lastUsedPrinterId_;
    }
    PRINT_HILOGD("defaultPrinterId_: %{private}s", defaultPrinterId_.c_str());
    if (!SetUserDataToFile()) {
        PRINT_HILOGE("SetUserDataToFile failed.");
        return E_PRINT_SERVER_FAILURE;
    }

    return E_PRINT_NONE;
}

std::string PrintUserData::GetDefaultPrinter()
{
    return defaultPrinterId_;
}

bool PrintUserData::CheckIfUseLastUsedPrinterForDefault()
{
    PRINT_HILOGI("useLastUsedPrinterForDefault_: %{public}d", useLastUsedPrinterForDefault_);
    return useLastUsedPrinterForDefault_;
}

void PrintUserData::DeletePrinter(const std::string &printerId)
{
    DeletePrinterFromUsedPrinterList(printerId);
    if (!strcmp(lastUsedPrinterId_.c_str(), printerId.c_str())) {
        std::lock_guard<std::recursive_mutex> lock(userDataMutex_);
        if (usedPrinterList_.size()) {
            auto it = usedPrinterList_.begin();
            lastUsedPrinterId_ = *it;
            PRINT_HILOGI(
                "change last used printer for delete printer, printerId: %{private}s", lastUsedPrinterId_.c_str());
        } else {
            lastUsedPrinterId_ = "";
            PRINT_HILOGW("last used printer is null");
        }
    }
    if (!SetUserDataToFile()) {
        PRINT_HILOGE("SetUserDataToFile failed.");
        return;
    }
}

void PrintUserData::DeletePrinterFromUsedPrinterList(const std::string &printerId)
{
    std::lock_guard<std::recursive_mutex> lock(userDataMutex_);
    for (auto it = usedPrinterList_.begin(); it != usedPrinterList_.end(); ++it) {
        std::string id = *it;
        PRINT_HILOGI("printerId in usedPrinterList_: %{private}s", id.c_str());
        if (!strcmp(id.c_str(), printerId.c_str())) {
            PRINT_HILOGI("find printerId in used printer list.");
            usedPrinterList_.erase(it);
            break;
        }
    }
}

bool PrintUserData::ParseUserData()
{
    std::string fileData = "";
    if (!GetFileData(fileData)) {
        PRINT_HILOGW("get file data failed");
        return false;
    }
    Json::Value jsonObject;
    if (CheckFileData(fileData, jsonObject)) {
        ParseUserDataFromJson(jsonObject);
    }
    return true;
}

void PrintUserData::ParseUserDataFromJson(Json::Value &jsonObject)
{
    if (!PrintJsonUtil::IsMember(jsonObject, "print_user_data")) {
        PRINT_HILOGW("can not find print_user_data");
        return;
    }
    PRINT_HILOGI("userId_: %{public}d", userId_);
    Json::Value userDataList = jsonObject["print_user_data"];
    if (!PrintJsonUtil::IsMember(userDataList, std::to_string(userId_)) ||
        !userDataList[std::to_string(userId_)].isObject()) {
        PRINT_HILOGW("can not find current userId");
        SetUserDataToFile();
    }
    Json::Value userData = userDataList[std::to_string(userId_)];
    if (!PrintJsonUtil::IsMember(userData, "defaultPrinter") || !userData["defaultPrinter"].isString()) {
        PRINT_HILOGW("can not find defaultPrinter");
        return;
    }
    defaultPrinterId_ = userData["defaultPrinter"].asString();
    if (!PrintJsonUtil::IsMember(userData, "lastUsedPrinter") || !userData["lastUsedPrinter"].isString()) {
        PRINT_HILOGW("can not find lastUsedPrinter");
        return;
    }
    lastUsedPrinterId_ = userData["lastUsedPrinter"].asString();
    if (!PrintJsonUtil::IsMember(userData, "useLastUsedPrinterForDefault") ||
        !userData["useLastUsedPrinterForDefault"].isBool()) {
        PRINT_HILOGW("can not find useLastUsedPrinterForDefault");
        return;
    }
    useLastUsedPrinterForDefault_ = userData["useLastUsedPrinterForDefault"].asBool();
    if (!PrintJsonUtil::IsMember(userData, "usedPrinterList") || !userData["usedPrinterList"].isArray()) {
        PRINT_HILOGW("can not find usedPrinterList");
        return;
    }
    if (!ConvertJsonToUsedPrinterList(userData)) {
        PRINT_HILOGW("convert json to usedPrinterList failed");
        return;
    }
    PRINT_HILOGI(
        "defaultPrinterId_: %{private}s, lastUsedPrinterId_: %{private}s, useLastUsedPrinterForDefault_: %{public}d",
        defaultPrinterId_.c_str(),
        lastUsedPrinterId_.c_str(),
        useLastUsedPrinterForDefault_);
}

bool PrintUserData::ConvertJsonToUsedPrinterList(Json::Value &userData)
{
    Json::Value usedPrinterListJson = userData["usedPrinterList"];
    uint32_t jsonSize = usedPrinterListJson.size();
    if (jsonSize > MAX_PRINTER_SIZE) {
        PRINT_HILOGE("usedPrinterList size is illegal");
    }
    for (uint32_t i = 0; i < jsonSize; i++) {
        if (!usedPrinterListJson[i].isString()) {
            PRINT_HILOGW("usedPrinterListJson item is not string");
            return false;
        }
        usedPrinterList_.push_back(usedPrinterListJson[i].asString());
    }
    uint32_t size = usedPrinterList_.size();
    PRINT_HILOGI("usedPrinterList_ size: %{public}d", size);
    for (auto it = usedPrinterList_.begin(); it != usedPrinterList_.end(); ++it) {
        PRINT_HILOGD("printerId in usedPrinterList_: %{private}s", it->c_str());
    }
    return true;
}

void PrintUserData::ConvertUsedPrinterListToJson(Json::Value &usedPrinterListJson)
{
    for (auto iter = usedPrinterList_.begin(); iter != usedPrinterList_.end(); ++iter) {
        usedPrinterListJson.append(*iter);
    }
}

bool PrintUserData::GetFileData(std::string &fileData)
{
    PRINT_HILOGI("begin GetFileData");
    std::string userDataFilePath = PRINTER_SERVICE_FILE_PATH + "/" + PRINT_USER_DATA_FILE;
    std::ifstream ifs(userDataFilePath.c_str(), std::ios::in | std::ios::binary);
    if (!ifs.is_open()) {
        PRINT_HILOGW("open printer list file fail");
        char realPidFile[PATH_MAX] = {};
        if (realpath(PRINTER_SERVICE_FILE_PATH.c_str(), realPidFile) == nullptr) {
            PRINT_HILOGE("The realPidFile is null, errno:%{public}s", std::to_string(errno).c_str());
            return false;
        }
        FILE *file = fopen(userDataFilePath.c_str(), "w+");
        if (file == nullptr) {
            PRINT_HILOGW("Failed to open file errno: %{public}s", std::to_string(errno).c_str());
            return false;
        }
        Json::Value userDataJson;
        Json::Value jsonObject;
        jsonObject["version"] = PRINT_USER_DATA_VERSION;
        jsonObject["print_user_data"] = userDataJson;
        fileData = PrintJsonUtil::WriteString(jsonObject);
        size_t jsonLength = fileData.length();
        size_t writeLength = fwrite(fileData.c_str(), 1, strlen(fileData.c_str()), file);
        int fcloseResult = fclose(file);
        if (fcloseResult != 0 || writeLength < 0 || writeLength != jsonLength) {
            PRINT_HILOGE("File Operation Failure.");
            return false;
        }
    } else {
        fileData.assign((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        ifs.close();
    }
    return true;
}

bool PrintUserData::SetUserDataToFile()
{
    PRINT_HILOGI("begin SetUserDataToFile");
    std::string fileData = "";
    if (!GetFileData(fileData)) {
        PRINT_HILOGW("get file data failed");
        return false;
    }
    Json::Value jsonObject;
    if (CheckFileData(fileData, jsonObject)) {
        PRINT_HILOGI("userId_: %{private}d", userId_);
        Json::Value userData;
        userData["defaultPrinter"] = defaultPrinterId_;
        userData["lastUsedPrinter"] = lastUsedPrinterId_;
        userData["useLastUsedPrinterForDefault"] = useLastUsedPrinterForDefault_;
        Json::Value usedPrinterListJson;
        ConvertUsedPrinterListToJson(usedPrinterListJson);
        userData["usedPrinterList"] = usedPrinterListJson;
        jsonObject["print_user_data"][std::to_string(userId_)] = userData;
        std::string temp = PrintJsonUtil::WriteString(jsonObject);
        PRINT_HILOGD("json temp: %{public}s", temp.c_str());
        char realPidFile[PATH_MAX] = {};
        std::string userDataFilePath = PRINTER_SERVICE_FILE_PATH + "/" + PRINT_USER_DATA_FILE;
        if (realpath(PRINTER_SERVICE_FILE_PATH.c_str(), realPidFile) == nullptr) {
            PRINT_HILOGE("The realPidFile is null, errno:%{public}s", std::to_string(errno).c_str());
            return false;
        }
        FILE *file = fopen(userDataFilePath.c_str(), "w+");
        if (file == nullptr) {
            PRINT_HILOGW("Failed to open file errno: %{public}s", std::to_string(errno).c_str());
            return false;
        }
        std::string jsonString = PrintJsonUtil::WriteString(jsonObject);
        size_t jsonLength = jsonString.length();
        size_t writeLength = fwrite(jsonString.c_str(), 1, strlen(jsonString.c_str()), file);
        int fcloseResult = fclose(file);
        if (fcloseResult != 0 || writeLength < 0) {
            PRINT_HILOGE("File Operation Failure.");
            return false;
        }
        PRINT_HILOGI("SetUserDataToFile finished");
        return writeLength == jsonLength;
    }
    return true;
}

bool PrintUserData::CheckFileData(std::string &fileData, Json::Value &jsonObject)
{
    if (!PrintJsonUtil::Parse(fileData, jsonObject)) {
        PRINT_HILOGW("json accept fail");
        return false;
    }
    if (!PrintJsonUtil::IsMember(jsonObject, "version") || !jsonObject["version"].isString()) {
        PRINT_HILOGW("can not find version");
        return false;
    }
    std::string version = jsonObject["version"].asString();
    PRINT_HILOGI("json version: %{public}s", version.c_str());
    if (version != PRINT_USER_DATA_VERSION || !PrintJsonUtil::IsMember(jsonObject, "print_user_data")) {
        PRINT_HILOGW("can not find print_user_data");
        return false;
    }
    return true;
}
}  // namespace Print
}  // namespace OHOS