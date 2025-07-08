/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef PRINT_USER_DATA_H
#define PRINT_USER_DATA_H

#include <charconv>
#include <string>
#include <map>
#include <deque>
#include <mutex>

#include "printer_info.h"
#include "print_util.h"
#include "iprint_callback.h"

namespace OHOS {
namespace Print {
using namespace std;
struct JobIdCmp {
    bool operator()(const std::string a, const std::string b) const
    {
        int32_t numA = 0;
        int32_t numB = 0;
        if (PrintUtil::ConvertToInt(a, numA) && PrintUtil::ConvertToInt(b, numB)) {
            return numA > numB;
        } else {
            // If invalid, By default, the number A is greater than the number B.
            return true;
        }
    }
};

const uint32_t DELETE_DEFAULT_PRINTER = 101;
const uint32_t DELETE_LAST_USED_PRINTER = 102;

class PrintUserData {
public:
    void RegisterPrinterCallback(const std::string &type, const sptr<IPrintCallback> &listener);
    void UnregisterPrinterCallback(const std::string &type);
    void SendPrinterEvent(const std::string &type, int event, const PrinterInfo &info);
    void AddToPrintJobList(const std::string jobId, const std::shared_ptr<PrintJob> &printjob);
    void UpdateQueuedJobList(
        const std::string &jobId, const std::shared_ptr<PrintJob> &printJob, std::string jobOrderId);
    int32_t QueryPrintJobById(const std::string &printJobId, PrintJob &printJob);
    int32_t QueryHistoryPrintJobById(const std::string &printJobId, PrintJob &printJob);
    int32_t QueryAllPrintJob(std::vector<PrintJob> &printJobs);
    int32_t QueryAllHistoryPrintJob(std::vector<std::string> printerIds, std::vector<PrintJob> &printJobs);
    int32_t SetDefaultPrinter(const std::string &printerId, uint32_t type);
    int32_t SetLastUsedPrinter(const std::string &printerId);
    bool ParseUserData();
    void SetUserId(int32_t userId);
    std::string GetLastUsedPrinter();
    std::string GetDefaultPrinter();
    bool CheckIfUseLastUsedPrinterForDefault();
    void DeletePrinter(const std::string &printerId);
    bool FlushCacheFileToUserData(const std::string &jobId);
    bool DeleteCacheFileFromUserData(const std::string &jobId);
    bool OpenCacheFileFd(const std::string &jobId, std::vector<uint32_t> &fdList);
    int32_t QueryQueuedPrintJobById(const std::string &printJobId, PrintJob &printJob);
    bool AddPrintJobToHistoryList(const std::string &printerId, const std::string &jobId,
        const std::shared_ptr<PrintJob> &printjob);
    bool DeletePrintJobFromHistoryList(const std::string &jobId);
    bool DeletePrintJobFromHistoryListByPrinterId(const std::string &printerId);
    bool ContainsHistoryPrintJob(const std::vector<std::string> &printerIds, const std::string &jobId);

private:
    bool SetUserDataToFile();
    bool GetFileData(std::string &fileData);
    void ParseUserDataFromJson(Json::Value &jsonObject);
    bool CheckFileData(std::string &fileData, Json::Value &jsonObject);
    bool ConvertJsonToUsedPrinterList(Json::Value &userData);
    void ConvertUsedPrinterListToJson(Json::Value &usedPrinterListJson);
    void DeletePrinterFromUsedPrinterList(const std::string &printerId);
    std::string ObtainUserCacheDirectory();
    bool FlushCacheFile(uint32_t fd, const std::string jobId, int32_t index);
    void FlushPrintHistoryJobFile(const std::string &printerId);
    std::string ParsePrintHistoryJobListToJsonString(const std::string &printerId);
    bool GetPrintHistoryJobFromFile(const std::string &printerId);
    bool GetJsonObjectFromFile(Json::Value &jsonObject, const std::string &filePath, const std::string &printerId);
    bool ParseJsonObjectToPrintHistory(Json::Value &jsonObject, const std::string &printerId);
    PrintMargin  ParseJsonObjectToMargin(const Json::Value &jsonObject);
    PrintRange ParseJsonObjectToPrintRange(const Json::Value &jsonObject);
    PrintPageSize ParseJsonObjectToPrintPageSize(const Json::Value &jsonObject);
    PrintPreviewAttribute ParseJsonObjectToPrintPreviewAttribute(const Json::Value &jsonObject);
    void ParseOptionalJsonObjectToPrintJob(
        const Json::Value &printJobInfoJson, std::shared_ptr<PrintJob> &printHistoryJob);
    bool ParseJsonObjectToPrintJob(const Json::Value &printJobInfoJson, std::shared_ptr<PrintJob> &printHistoryJob);
    void InitPrintHistoryJobList(const std::string &printerId);
    bool CheckOptionalParam(const Json::Value &jsonObject, const std::string &param);

public:
    std::map<std::string, sptr<IPrintCallback>> registeredListeners_;
    std::map<std::string, std::shared_ptr<PrintJob>> printJobList_;
    std::map<std::string, std::shared_ptr<PrintJob>> queuedJobList_;
    std::map<std::string, std::string, JobIdCmp> jobOrderList_;

private:
    std::string defaultPrinterId_ = "";
    std::string lastUsedPrinterId_ = "";
    int32_t userId_ = 0;
    bool useLastUsedPrinterForDefault_ = true;
    deque<std::string> usedPrinterList_;
    std::recursive_mutex userDataMutex_;
    const uint32_t MAX_PRINTER_SIZE = 1000;
    const uint32_t MAX_HISTORY_JOB_NUM = 500;
    std::map<std::string, std::unique_ptr<std::map<std::string, std::shared_ptr<PrintJob>>>>
        printHistoryJobList_;
};

}  // namespace Print
}  // namespace OHOS
#endif  // PRINT_USER_DATA_H
