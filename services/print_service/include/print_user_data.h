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

#include <string>
#include <map>

#include "printer_info.h"
#include "iprint_callback.h"

namespace OHOS {
namespace Print {
struct JobIdCmp {
    bool operator()(const std::string a, const std::string b) const
    {
        return atoi(a.c_str()) > atoi(b.c_str());
    }
};

class PrintUserData {
public:
    void RegisterPrinterCallback(const std::string &type, const sptr<IPrintCallback> &listener);
    void UnregisterPrinterCallback(const std::string &type);
    void SendPrinterEvent(const std::string &type, int event, const PrinterInfo &info);
    void AddToPrintJobList(const std::string jobId, const std::shared_ptr<PrintJob> &printjob);
    void UpdateQueuedJobList(
        const std::string &jobId, const std::shared_ptr<PrintJob> &printJob, std::string jobOrderId);
    int32_t QueryPrintJobById(std::string &printJobId, PrintJob &printJob);
    int32_t QueryAllPrintJob(std::vector<PrintJob> &printJobs);
    int32_t SetDefaultPrinter(const std::string &printerId);
    int32_t SetLastUsedPrinter(const std::string &printerId);
    void ParseUserData();
    void SetUserId(int32_t userId);
    std::string GetLastUsedPrinter();
    std::string GetDefaultPrinter();

private:
    bool SetUserDataToFile();
    bool GetFileData(std::string &fileData);

public:
    std::map<std::string, sptr<IPrintCallback>> registeredListeners_;
    std::map<std::string, std::shared_ptr<PrintJob>> printJobList_;
    std::map<std::string, std::shared_ptr<PrintJob>> queuedJobList_;
    std::map<std::string, std::string, JobIdCmp> jobOrderList_;

private:
    std::string defaultPrinterId_ = "";
    std::string lastUsedPrinterId_ = "";
    int32_t userId_ = 0;
};

}  // namespace Print
}  // namespace OHOS
#endif  // PRINT_USER_DATA_H