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

#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <streambuf>
#include "nlohmann/json.hpp"

#include "print_user_data.h"
#include "print_log.h"
#include "print_constant.h"

namespace OHOS {
namespace Print {

using namespace std;

const std::string PRINT_USER_DATA_FILE = "/data/service/el1/public/print_service/print_user_data.json";
const std::string PRINT_USER_DATA_VERSION = "v1";

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
    PRINT_HILOGI("begin SetLastUsedPrinter, printerId: %{public}s", printerId.c_str());
    if (printerId.empty()) {
        PRINT_HILOGE("printerId is empty");
        return E_PRINT_INVALID_PARAMETER;
    }
    std::lock_guard<std::recursive_mutex> lock(userDataMutex_);
    lastUsedPrinterId_ = printerId;
    
    DeletePrinterFromUsedPrinterList(printerId);
    usedPrinterList_.push_front(printerId);
    PRINT_HILOGI("put printer at the head of the queue, printerId: %{public}s", usedPrinterList_.front().c_str());
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
    return lastUsedPrinterId_;
}

int32_t PrintUserData::SetDefaultPrinter(const std::string &printerId, uint32_t type)
{
    PRINT_HILOGI("begin SetDefaultPrinter");
    PRINT_HILOGI("printerId: %{public}s", printerId.c_str());
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
    PRINT_HILOGI("defaultPrinterId_: %{public}s", defaultPrinterId_.c_str());
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
        if (usedPrinterList_.size()) {
            auto it = usedPrinterList_.begin();
            lastUsedPrinterId_ = *it;
            PRINT_HILOGI(
                "change last used printer for delete printer, printerId: %{public}s", lastUsedPrinterId_.c_str());
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
        PRINT_HILOGI("printerId in usedPrinterList_: %{public}s", id.c_str());
        if (!strcmp(id.c_str(), printerId.c_str())) {
            PRINT_HILOGI("find printerId in used printer list.");
            usedPrinterList_.erase(it);
            break;
        }
    }
}

void PrintUserData::ParseUserData()
{
    std::string fileData = "";
    if (!GetFileData(fileData)) {
        PRINT_HILOGW("get file data failed");
        return;
    }
    nlohmann::json jsonObject;
    if (CheckFileData(fileData, jsonObject)) {
        ParseUserDataFromJson(jsonObject);
    }
}

void PrintUserData::ParseUserDataFromJson(nlohmann::json &jsonObject)
{
    if (!jsonObject.contains("print_user_data")) {
        PRINT_HILOGW("can not find print_user_data");
        return;
    }
    PRINT_HILOGI("userId_: %{public}d", userId_);
    nlohmann::json userDataList = jsonObject["print_user_data"];
    if (!userDataList.contains(std::to_string(userId_)) || !userDataList[std::to_string(userId_)].is_object()) {
        PRINT_HILOGW("can not find current userId");
        SetUserDataToFile();
    }
    nlohmann::json userData = userDataList[std::to_string(userId_)];
    if (!userData.contains("defaultPrinter") || !userData["defaultPrinter"].is_string()) {
        PRINT_HILOGW("can not find defaultPrinter");
        return;
    }
    defaultPrinterId_ = userData["defaultPrinter"];
    if (!userData.contains("lastUsedPrinter") || !userData["lastUsedPrinter"].is_string()) {
        PRINT_HILOGW("can not find lastUsedPrinter");
        return;
    }
    lastUsedPrinterId_ = userData["lastUsedPrinter"];
    if (!userData.contains("useLastUsedPrinterForDefault") || !userData["useLastUsedPrinterForDefault"].is_boolean()) {
        PRINT_HILOGW("can not find useLastUsedPrinterForDefault");
        return;
    }
    useLastUsedPrinterForDefault_ = userData["useLastUsedPrinterForDefault"].get<bool>();
    if (!userData.contains("usedPrinterList") || !userData["usedPrinterList"].is_array()) {
        PRINT_HILOGW("can not find usedPrinterList");
        return;
    }
    if (!ConvertJsonToUsedPrinterList(userData)) {
        PRINT_HILOGW("convert json to usedPrinterList failed");
        return;
    }
    PRINT_HILOGI(
        "defaultPrinterId_: %{public}s, lastUsedPrinterId_: %{public}s, useLastUsedPrinterForDefault_: %{public}d",
        defaultPrinterId_.c_str(),
        lastUsedPrinterId_.c_str(),
        useLastUsedPrinterForDefault_);
}

bool PrintUserData::ConvertJsonToUsedPrinterList(nlohmann::json &userData)
{
    nlohmann::json usedPrinterListJson = userData["usedPrinterList"];
    for (auto &item : usedPrinterListJson.items()) {
        if (!item.value().is_string()) {
            PRINT_HILOGW("usedPrinterListJson item is not string");
            return false;
        }
        nlohmann::json printerIdJson = item.value();
        usedPrinterList_.push_back(printerIdJson.get<std::string>());
    }
    uint32_t size = usedPrinterList_.size();
    PRINT_HILOGI("usedPrinterList_ size: %{public}d", size);
    for (auto it = usedPrinterList_.begin(); it != usedPrinterList_.end(); ++it) {
        PRINT_HILOGI("printerId in usedPrinterList_: %{public}s", it->c_str());
    }
    return true;
}

void PrintUserData::ConvertUsedPrinterListToJson(nlohmann::json &usedPrinterListJson)
{
    for (auto iter = usedPrinterList_.begin(); iter != usedPrinterList_.end(); ++iter) {
        usedPrinterListJson.push_back(*iter);
    }
}

bool PrintUserData::GetFileData(std::string &fileData)
{
    PRINT_HILOGI("begin GetFileData");
    std::ifstream ifs(PRINT_USER_DATA_FILE.c_str(), std::ios::in | std::ios::binary);
    if (!ifs.is_open()) {
        PRINT_HILOGW("open printer list file fail");
        int32_t fd = open(PRINT_USER_DATA_FILE.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0740);
        PRINT_HILOGI("create file fd: %{public}d", fd);
        if (fd < 0) {
            PRINT_HILOGW("Failed to open file errno: %{public}s", std::to_string(errno).c_str());
            close(fd);
            return false;
        }
        nlohmann::json userDataJson = nlohmann::json::object();
        nlohmann::json jsonObject;
        jsonObject["version"] = PRINT_USER_DATA_VERSION;
        jsonObject["print_user_data"] = userDataJson;
        fileData = jsonObject.dump();
        size_t jsonLength = fileData.length();
        auto writeLength = write(fd, fileData.c_str(), jsonLength);
        close(fd);
        if (writeLength < 0 && (size_t)writeLength != jsonLength) {
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
    nlohmann::json jsonObject;
    if (CheckFileData(fileData, jsonObject)) {
        PRINT_HILOGI("userId_: %{public}d", userId_);
        nlohmann::json userData = nlohmann::json::object();
        userData["defaultPrinter"] = defaultPrinterId_;
        userData["lastUsedPrinter"] = lastUsedPrinterId_;
        userData["useLastUsedPrinterForDefault"] = useLastUsedPrinterForDefault_;
        nlohmann::json usedPrinterListJson = nlohmann::json::array();
        ConvertUsedPrinterListToJson(usedPrinterListJson);
        userData["usedPrinterList"] = usedPrinterListJson;
        jsonObject["print_user_data"][std::to_string(userId_)] = userData;
        std::string temp = jsonObject.dump();
        PRINT_HILOGI("json temp: %{public}s", temp.c_str());
        int32_t fd = open(PRINT_USER_DATA_FILE.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0740);
        PRINT_HILOGI("SetUserDataToFile fd: %{public}d", fd);
        if (fd < 0) {
            PRINT_HILOGW("Failed to open file errno: %{public}s", std::to_string(errno).c_str());
            close(fd);
            return false;
        }
        std::string jsonString = jsonObject.dump();
        size_t jsonLength = jsonString.length();
        auto writeLength = write(fd, jsonString.c_str(), jsonLength);
        close(fd);
        PRINT_HILOGI("SetUserDataToFile finished");
        if (writeLength < 0) {
            return false;
        }
        return (size_t)writeLength == jsonLength;
    }
    return true;
}

bool PrintUserData::CheckFileData(std::string &fileData, nlohmann::json &jsonObject)
{
    if (!nlohmann::json::accept(fileData)) {
        PRINT_HILOGW("json accept fail");
        return false;
    }
    jsonObject = nlohmann::json::parse(fileData);
    if (!jsonObject.contains("version") || !jsonObject["version"].is_string()) {
        PRINT_HILOGW("can not find version");
        return false;
    }
    std::string version = jsonObject["version"].get<std::string>();
    PRINT_HILOGI("json version: %{public}s", version.c_str());
    if (version != PRINT_USER_DATA_VERSION || !jsonObject.contains("print_user_data")) {
        PRINT_HILOGW("can not find print_user_data");
        return false;
    }
    return true;
}
}  // namespace Print
}  // namespace OHOS