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
#include <algorithm>
#include <dirent.h>
#include <cstdlib>
#include <iomanip>
#include <json/json.h>
#include <filesystem>

#include "print_log.h"
#include "print_constant.h"
#include "print_json_util.h"

namespace OHOS {
namespace Print {
const uint32_t DEFAULT_BUFFER_SIZE_4K = 4096;
const uint32_t FD_INDEX_LEN = 4;

static const std::string FILE_INDEX_DELIMITER = "_";

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

int32_t PrintUserData::QueryPrintJobById(const std::string &printJobId, PrintJob &printJob)
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

int32_t PrintUserData::QueryHistoryPrintJobById(const std::string &printJobId, PrintJob &printJob)
{
    PRINT_HILOGI("QueryHistoryPrintJobById Start.");
    std::lock_guard<std::recursive_mutex> lock(userDataMutex_);
    for (auto it = printHistoryJobList_.begin(); it != printHistoryJobList_.end(); ++it) {
        if (it->second == nullptr) {
            PRINT_HILOGE("printerHistoryJobList_ is null.");
            return E_PRINT_INVALID_PRINTJOB;
        }
        for (auto innerIt = (it->second)->begin(); innerIt != (it->second)->end(); ++innerIt) {
            if (innerIt->second == nullptr) {
                PRINT_HILOGE("printJob object is null.");
                return E_PRINT_INVALID_PRINTJOB;
            }
            
            if (innerIt->first == printJobId) {
                printJob = *(innerIt->second);
                return E_PRINT_NONE;
            }
        }
    }
    return E_PRINT_INVALID_PRINTJOB;
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

int32_t PrintUserData::QueryAllHistoryPrintJob(std::vector<std::string> printerIds, std::vector<PrintJob> &printJobs)
{
    PRINT_HILOGI("QueryAllHistoryPrintJob Start.");
    printJobs.clear();
    for (auto iter : jobOrderList_) {
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
    for (std::string printerId : printerIds) {
        InitPrintHistoryJobList(printerId);
    }
    for (auto it = printHistoryJobList_.begin(); it != printHistoryJobList_.end(); ++it) {
        for (auto innerIt = (it->second)->begin(); innerIt != (it->second)->end(); ++innerIt) {
            if (innerIt->second == nullptr) {
                return E_PRINT_INVALID_PRINTJOB;
            }
            printJobs.emplace_back(*(innerIt->second));
        }
    }
    PRINT_HILOGI("QueryAllHistoryPrintJob End.");
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
        return false;
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

bool PrintUserData::FlushCacheFileToUserData(const std::string &jobId)
{
    PRINT_HILOGI("FlushCacheFileToUserData Start.");
    PrintJob printJob;
    if (QueryQueuedPrintJobById(jobId, printJob) != E_PRINT_NONE) {
        PRINT_HILOGE("Can not find print job");
        return false;
    }
    std::vector<uint32_t> fdList;
    printJob.GetFdList(fdList);
    if (fdList.empty()) {
        PRINT_HILOGE("fdList is empty, nothing to do");
        return false;
    }
    int32_t index = 1;
    bool ret = true;
    for (uint32_t fd : fdList) {
        if (!ret) { close(fd); } // close the remaining fd
        ret = FlushCacheFile(fd, printJob.GetJobId(), index);
        index++;
    }
    if (!ret) { DeleteCacheFileFromUserData(jobId); }
    return ret;
}

bool PrintUserData::FlushCacheFile(uint32_t fd, const std::string jobId, int32_t index)
{
    if (lseek(fd, 0, SEEK_SET) == -1) {
        PRINT_HILOGE("Unable to reset fd offset");
        close(fd);
        return false;
    }
    FILE *srcFile = fdopen(fd, "rb");
    if (srcFile == nullptr) {
        close(fd);
        return false;
    }
    char cachePath[PATH_MAX] = { 0 };
    std::string cacheDir = ObtainUserCacheDirectory();
    if (realpath(cacheDir.c_str(), cachePath) == nullptr) {
        PRINT_HILOGE("The real cache dir is null, errno:%{public}s", std::to_string(errno).c_str());
        return false;
    }
    cacheDir = cachePath;
    std::ostringstream destFileStream;
    destFileStream << cacheDir << "/" << jobId << "_" << std::setw(FD_INDEX_LEN) << std::setfill('0') << index;
    std::string destFilePath = destFileStream.str();
    FILE *destFile = fopen(destFilePath.c_str(), "wb");
    if (destFile == nullptr) {
        fclose(srcFile);
        return false;
    }

    char buffer[DEFAULT_BUFFER_SIZE_4K] = { 0 };
    size_t bytesRead = 0;
    bool ret = true;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), srcFile)) > 0) {
        if (fwrite(buffer, 1, bytesRead, destFile) < bytesRead) {
            ret = false;
            break;
        }
    }
    if (fclose(srcFile) != 0 || fclose(destFile) != 0) {
        PRINT_HILOGE("File Operation Failure.");
        ret = false;
    };
    return ret;
}

bool PrintUserData::DeleteCacheFileFromUserData(const std::string &jobId)
{
    PRINT_HILOGI("DeleteCacheFileFromUserData Start.");
    if (jobId.empty()) {
        PRINT_HILOGE("empty jobId, not find files");
        return false;
    }
    char cachePath[PATH_MAX] = { 0 };
    std::string cacheDir = ObtainUserCacheDirectory();
    if (realpath(cacheDir.c_str(), cachePath) == nullptr) {
        PRINT_HILOGE("The real cache dir is null, errno:%{public}s", std::to_string(errno).c_str());
        return false;
    }
    cacheDir = cachePath;
    DIR *dir = opendir(cachePath);
    struct dirent *file;
    std::vector<std::string> fileNames;
    std::string cacheFile;
    while ((file = readdir(dir)) != nullptr) {
        if (strncmp(file->d_name, jobId.c_str(), jobId.length()) == 0) {
            cacheFile = cacheDir + '/' + std::string(file->d_name);
            if (realpath(cacheFile.c_str(), cachePath) == nullptr) {
                PRINT_HILOGE("The realFile is null, errno:%{public}s", strerror(errno));
                continue;
            }
            if (std::remove(cachePath) != 0) {
                PRINT_HILOGW("error deleting file %{public}s err: %{public}s", cachePath, strerror(errno));
            }
        }
    }
    closedir(dir);
    return true;
}

bool PrintUserData::OpenCacheFileFd(const std::string &jobId, std::vector<uint32_t> &fdList)
{
    PRINT_HILOGI("OpenCacheFileFd Start.");
    fdList.clear();
    char cachePath[PATH_MAX] = { 0 };
    std::string cacheDir = ObtainUserCacheDirectory();
    if (realpath(cacheDir.c_str(), cachePath) == nullptr) {
        PRINT_HILOGE("The real cache dir is null, errno:%{public}s", std::to_string(errno).c_str());
        return false;
    }
    cacheDir = cachePath;

    DIR *dir = opendir(cacheDir.c_str());
    // dir real path
    if (dir == nullptr) {
        PRINT_HILOGE("Failed to find history file");
        return false;
    }
    if (access(cacheDir.c_str(), R_OK) != 0) {
        PRINT_HILOGE("Failed to find history file");
        closedir(dir);
        return false;
    }
    struct dirent *file;
    std::vector<std::string> fileNames;
    while ((file = readdir(dir)) != nullptr) {
        if (strncmp(file->d_name, jobId.c_str(), jobId.length()) == 0) {
            fileNames.push_back(std::string(file->d_name));
        }
    }

    std::string cacheFile;
    bool ret = true;
    for (auto fileName : fileNames) {
        cacheFile = cacheDir + "/" + fileName;
        if (realpath(cacheFile.c_str(), cachePath) == nullptr) {
            PRINT_HILOGE("The realFile is null, errno:%{public}s", std::to_string(errno).c_str());
            ret = false;
            break;
        }
        int32_t fd = open(cachePath, O_RDONLY);
        if (fd < 0) {
            PRINT_HILOGE("open file failed, errno:%{public}s", std::to_string(errno).c_str());
            ret = false;
            break;
        }
        fdList.push_back(fd);
    }
    if (!ret) {
        for (auto fd : fdList) { close(fd); }
    }
    closedir(dir);
    return ret;
}

std::string PrintUserData::ObtainUserCacheDirectory()
{
    std::ostringstream oss;
    oss << "/data/service/el2/" << userId_ << "/print_service";
    return oss.str();
}

int32_t PrintUserData::QueryQueuedPrintJobById(const std::string &printJobId, PrintJob &printJob)
{
    PRINT_HILOGI("QueryQueuedPrintJobById Start.");
    if (queuedJobList_.empty()) {
        PRINT_HILOGE("printJobList is empty!");
        return E_PRINT_INVALID_PRINTJOB;
    }
    auto jobIt = queuedJobList_.find(printJobId);
    if (jobIt == queuedJobList_.end()) {
        PRINT_HILOGW("no print job exists");
        return E_PRINT_INVALID_PRINTJOB;
    }
    if (jobIt->second == nullptr) {
        PRINT_HILOGW("no print job exists");
        return E_PRINT_INVALID_PRINTJOB;
    }
    printJob = *jobIt->second;
    PRINT_HILOGD("QueryQueuedPrintJobById End.");
    return E_PRINT_NONE;
}

bool PrintUserData::AddPrintJobToHistoryList(const std::string &printerId,
    const std::string &jobId, const std::shared_ptr<PrintJob> &printJob)
{
    PRINT_HILOGI("AddPrintJobToHistoryList Start.");
    if (printJob == nullptr) {
        PRINT_HILOGE("printJob is null.");
        return false;
    }
    InitPrintHistoryJobList(printerId);
    auto& printerHistroyJobList = printHistoryJobList_[printerId];
    if (!printerHistroyJobList) {
        PRINT_HILOGE("printerHistroyJobList is null.");
        return false;
    }
    std::string oldOption = printJob->GetOption();
    PRINT_HILOGD("Print job option: %{public}s", oldOption.c_str());
    Json::Value infoJson;
    if (!PrintJsonUtil::Parse(oldOption, infoJson)) {
        PRINT_HILOGW("old option not accepted");
        return false;
    }
    infoJson["isHistory"] = true;
    std::string updatedOption = PrintJsonUtil::WriteString(infoJson);
    PRINT_HILOGD("Updated print job option: %{public}s", updatedOption.c_str());
    printJob->SetOption(updatedOption);
    auto it = printerHistroyJobList->begin();
    // erase the history print jobs more than 500
    while (printerHistroyJobList->size() > MAX_HISTORY_JOB_NUM) {
        it = printerHistroyJobList->erase(it);
    }
    if ((printerHistroyJobList->insert(std::make_pair(jobId, printJob))).second) {
        FlushPrintHistoryJobFile(printerId);
        return true;
    }
    return false;
}

void PrintUserData::FlushPrintHistoryJobFile(const std::string &printerId)
{
    PRINT_HILOGI("FlushPrintHistoryJobFile Start.");
    std::string filePath = ObtainUserCacheDirectory();
    char cachePath[PATH_MAX] = { 0 };
    if (realpath(filePath.c_str(), cachePath) == nullptr) {
        PRINT_HILOGE("The real cache dir is null, errno:%{public}s", std::to_string(errno).c_str());
        return;
    }
    filePath.assign(cachePath);
    std::string printHistoryJobFilePath = filePath + "/" + printerId + ".json";
    if (printHistoryJobList_.find(printerId) == printHistoryJobList_.end()) {
        PRINT_HILOGE("printHistoryJobList_[printerId] is null.");
        std::filesystem::remove(printHistoryJobFilePath);
        return;
    }
    
    FILE *printHistoryJobFile = fopen(printHistoryJobFilePath.c_str(), "w+");
    if (printHistoryJobFile == nullptr) {
        PRINT_HILOGW("Failed to open file errno: %{public}s", std::to_string(errno).c_str());
        return;
    }
    std::string jsonString = ParsePrintHistoryJobListToJsonString(printerId);
    PRINT_HILOGI("ParsePrintHistoryJobListToJsonString: %{public}s", jsonString.c_str());
    size_t jsonLength = jsonString.length();
    size_t writeLength = fwrite(jsonString.c_str(), 1, strlen(jsonString.c_str()), printHistoryJobFile);
    int fcloseResult = fclose(printHistoryJobFile);
    if (fcloseResult != 0) {
        PRINT_HILOGE("Close File Failure.");
        return;
    }
    PRINT_HILOGI("FlushPrintHistoryJobFile End.");
    if (writeLength < 0 || writeLength != jsonLength) {
        PRINT_HILOGE("SavePrintHistoryJobFile error");
    }
}

std::string PrintUserData::ParsePrintHistoryJobListToJsonString(const std::string &printerId)
{
    PRINT_HILOGI("ParsePrintHistoryJobListToJsonString Start.");
    Json::Value allPrintJobJson;
    for (auto it = printHistoryJobList_.begin(); it != printHistoryJobList_.end(); ++it) {
        if (it->first == printerId) {
            if (it->second == nullptr) {
                return "";
            }
            
            Json::Value printJobJson;
            for (auto innerIt = (it->second)->begin(); innerIt != (it->second)->end(); innerIt++) {
                printJobJson[innerIt->first] = (innerIt->second)->ConvertToJsonObject();
            }
            allPrintJobJson[printerId] = printJobJson;
            return PrintJsonUtil::WriteString(allPrintJobJson);
        }
    }
    return "";
}

bool PrintUserData::GetPrintHistoryJobFromFile(const std::string &printerId)
{
    PRINT_HILOGI("GetPrintHistoryJobFromFile Start.");
    char cachePath[PATH_MAX] = { 0 };
    std::string filePath = ObtainUserCacheDirectory();
    if (realpath(filePath.c_str(), cachePath) == nullptr) {
        PRINT_HILOGE("The real cache dir is null, errno:%{public}s", std::to_string(errno).c_str());
        return false;
    }
    filePath.assign(cachePath);
    std::string printHistoryJobFilePath = filePath + "/" + printerId + ".json";
    Json::Value printHistoryJobJson;
    if (GetJsonObjectFromFile(printHistoryJobJson, printHistoryJobFilePath, printerId) &&
        ParseJsonObjectToPrintHistory(printHistoryJobJson, printerId)) {
        PRINT_HILOGI("parse print history job file success");
        return true;
    }
    return false;
}

bool PrintUserData::GetJsonObjectFromFile(Json::Value &jsonObject,
    const std::string &filePath, const std::string &printerId)
{
    PRINT_HILOGI("GetJsonObjectFromFile Start.");
    std::ifstream ifs(filePath.c_str(), std::ios::in | std::ios::binary);
    if (!ifs.is_open()) {
        PRINT_HILOGW("open printer list file fail");
        return false;
    }
    if (ifs.peek() == std::ifstream::traits_type::eof()) {
        PRINT_HILOGW("file is empty.");
        ifs.close();
        return false;
    }
    if (!PrintJsonUtil::ParseFromStream(ifs, jsonObject)) {
        PRINT_HILOGW("json accept fail");
        ifs.close();
        return false;
    }
    ifs.close();
    if (!PrintJsonUtil::IsMember(jsonObject, printerId)) {
        PRINT_HILOGW("can not find printer history job");
        return false;
    }
    return true;
}

bool PrintUserData::ParseJsonObjectToPrintHistory(Json::Value &jsonObject, const std::string &printerId)
{
    PRINT_HILOGI("ParseJsonObjectToPrintHistory Start.");
    if (!printHistoryJobList_[printerId]) {
        PRINT_HILOGE("printerHistoryJobList_ is not exist.");
        return false;
    }
    for (const auto& jobId : jsonObject[printerId].getMemberNames()) {
        const Json::Value& printJobInfoJson = jsonObject[printerId][jobId];
        auto& printHistoryJob = (*(printHistoryJobList_[printerId]))[jobId];
        if (!printHistoryJob) {
            PRINT_HILOGE("printHistoryJob is not exist.");
            printHistoryJob = std::make_shared<PrintJob>();
        }
        PRINT_HILOGI("printHistoryJob is created.");
        printHistoryJob->SetJobId(printJobInfoJson["jobId"].asString());
        printHistoryJob->SetPrinterId(printJobInfoJson["printerId"].asString());
        printHistoryJob->SetJobState(printJobInfoJson["jobState"].asInt());
        printHistoryJob->SetSubState(printJobInfoJson["subState"].asInt());
        printHistoryJob->SetCopyNumber(printJobInfoJson["copyNumber"].asInt());
        printHistoryJob->SetPageRange(ParseJsonObjectToPrintRange(printJobInfoJson["pageRange"]));
        printHistoryJob->SetIsSequential(printJobInfoJson["isSequential"].asBool());
        PrintPageSize pageSize;
        pageSize.SetId(printJobInfoJson["pageSize"]["id_"].asString());
        pageSize.SetName(printJobInfoJson["pageSize"]["name_"].asString());
        pageSize.SetWidth(printJobInfoJson["pageSize"]["width_"].asInt());
        pageSize.SetHeight(printJobInfoJson["pageSize"]["height_"].asInt());
        printHistoryJob->SetPageSize(pageSize);
        printHistoryJob->SetIsLandscape(printJobInfoJson["isLandscape"].asBool());
        printHistoryJob->SetColorMode(printJobInfoJson["colorMode"].asInt());
        printHistoryJob->SetDuplexMode(printJobInfoJson["duplexMode"].asInt());
        if (printJobInfoJson["hasmargin"].asBool()) {
            printHistoryJob->SetMargin(ParseJsonObjectToMargin(printJobInfoJson["margin"]));
        }
        if (printJobInfoJson["hasPreview"].asBool()) {
            PrintPreviewAttribute printPreviewAttribute;
            if (printJobInfoJson["preview"]["hasResult_"]) {
                printPreviewAttribute.SetResult(printJobInfoJson["preview"]["result_"].asInt());
            }
            printPreviewAttribute.SetPreviewRange(
                ParseJsonObjectToPrintRange(printJobInfoJson["preview"]["previewRange_"]));
            
            printHistoryJob->SetPreview(printPreviewAttribute);
        }
        if (printJobInfoJson["hasOption"].asBool()) {
            printHistoryJob->SetOption(printJobInfoJson["option"].asString());
        }
    }
    return true;
}

PrintRange PrintUserData::ParseJsonObjectToPrintRange(const Json::Value &jsonObject)
{
    PrintRange printRange;
    if (jsonObject["hasStartPage_"].asBool()) {
        printRange.SetStartPage(jsonObject["startPage"].asInt());
    }
    if (jsonObject["hasEndPage_"].asBool()) {
        printRange.SetStartPage(jsonObject["endPage"].asInt());
    }
    if (jsonObject["hasPages_"].asBool()) {
        std::vector<uint32_t> pages;
        Json::Value pagesJsonObject;
        for (const auto& item : pagesJsonObject) {
            pages.push_back(item.asInt());
        }
        printRange.SetPages(pages);
    }
    return printRange;
}

PrintMargin PrintUserData::ParseJsonObjectToMargin(const Json::Value &jsonObject)
{
    PrintMargin margin;
    if (jsonObject["hasTop_"].asBool()) {
        margin.SetTop(jsonObject["top_"].asInt());
    }
    if (jsonObject["hasLeft_"].asBool()) {
        margin.SetTop(jsonObject["left_"].asInt());
    }
    if (jsonObject["hasRight_"].asBool()) {
        margin.SetTop(jsonObject["right_"].asInt());
    }
    if (jsonObject["hasBottom_"].asBool()) {
        margin.SetTop(jsonObject["bottom_"].asInt());
    }
    return margin;
}

bool PrintUserData::DeletePrintJobFromHistoryList(const std::string &jobId)
{
    PRINT_HILOGI("DeletePrintJobFromHistoryList Start.");
    std::lock_guard<std::recursive_mutex> lock(userDataMutex_);
    for (const auto& [printerId, printerHistoryJobMap] : printHistoryJobList_) {
        if (!printerHistoryJobMap) {
            PRINT_HILOGE("printerHistoryJobMap is not exist.");
            continue;
        }
        auto printJob = printerHistoryJobMap->find(jobId);
        if (printJob != printerHistoryJobMap->end()) {
            std::string curPrinterId = printerId;
            printerHistoryJobMap->erase(jobId);
            DeleteCacheFileFromUserData(jobId);
            if (printerHistoryJobMap->empty()) {
                printHistoryJobList_.erase(curPrinterId);
            }
            FlushPrintHistoryJobFile(curPrinterId);
            return true;
        }
    }
    return false;
}

bool PrintUserData::DeletePrintJobFromHistoryListByPrinterId(const std::string &printerId)
{
    PRINT_HILOGI("DeletePrintJobFromHistoryListByPrinterId Start.");
    InitPrintHistoryJobList(printerId);
    std::lock_guard<std::recursive_mutex> lock(userDataMutex_);
    for (auto it = printHistoryJobList_.begin(); it != printHistoryJobList_.end(); ++it) {
        if (it->first == printerId && it->second != nullptr) {
            for (auto innerIt = (it->second)->begin(); innerIt != (it->second)->end(); ++innerIt) {
                DeleteCacheFileFromUserData(innerIt->first);
            }
            printHistoryJobList_.erase(printerId);
            FlushPrintHistoryJobFile(printerId);
            return true;
        }
    }
    return false;
}

void PrintUserData::InitPrintHistoryJobList(const std::string &printerId)
{
    PRINT_HILOGI("InitPrintHistoryJobList Start.");
    auto it = printHistoryJobList_.find(printerId);
    if (it == printHistoryJobList_.end()) {
        auto printerHistoryJobList = std::make_unique<std::map<std::string, std::shared_ptr<PrintJob>>>();
        if (printerHistoryJobList != nullptr) {
            printHistoryJobList_.emplace(printerId, std::move(printerHistoryJobList));
            GetPrintHistoryJobFromFile(printerId);
        }
    }
}

bool PrintUserData::ContainsHistoryPrintJob(std::vector<std::string> printerIds, const std::string jobId)
{
    for (std::string printerId : printerIds) {
        InitPrintHistoryJobList(printerId);
    }
    for (auto it = printHistoryJobList_.begin(); it != printHistoryJobList_.end(); it++) {
        if (it->second == nullptr) {
            return false;
        }
        if ((it->second)->find(jobId) != (it->second)->end()) {
            return true;
        }
    }
    return false;
}

}  // namespace Print
}  // namespace OHOS