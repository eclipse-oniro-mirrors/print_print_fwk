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

#ifndef PRINT_CUPS_CLIENT_H
#define PRINT_CUPS_CLIENT_H

#include <vector>
#include <string>
#include <functional>
#include <json/json.h>

#include "singleton.h"
#include "print_cups_wrapper.h"
#include "print_service_ability.h"
#include "print_job.h"

namespace OHOS::Print {
typedef std::function<void()> CallbackFunc;

struct JobParameters {
    uint32_t cupsJobId;
    uint32_t borderless;
    uint32_t numCopies;
    bool isAutoRotate;
    bool isLandscape;
    std::string duplex;
    std::string printQuality;
    std::string jobName;
    std::string jobOriginatingUserName;
    std::string printerId;
    std::string printerName;
    std::string printerUri;
    std::string documentFormat;
    std::string mediaSize;
    std::string mediaType;
    std::string color;
    std::string serviceJobId;
    std::vector<uint32_t> fdList;
    PrintServiceAbility *serviceAbility;
    std::string printerAttrsOption_cupsOption;
};

enum StatePolicy {
    STATE_POLICY_STANDARD = 0,
    STATE_POLICY_BLOCK = 1,
    STATE_POLICY_HINT = 2,
    STATE_POLICY_DELAY = 3,
};
struct JobStatus {
    char printer_state_reasons[1024];
    ipp_jstate_t job_state;
    char job_state_reasons[1024];
};
struct JobMonitorParam {
    PrintServiceAbility *serviceAbility;
    std::string serviceJobId;
    int cupsJobId;
    std::string printerUri;
    std::string printerName;
    std::string printerId;
    http_t *http;

    StatePolicy policyArray[16] = {};
    ipp_jstate_t job_state = IPP_JOB_PENDING;
    char job_state_reasons[1024];
    char job_printer_state_reasons[1024];
    bool isFirstQueryState = true;
    int32_t timesOfSameState = -1;
    bool isBlock = false;
    uint32_t substate = 0;
    bool isPrinterStopped = false;

    ~JobMonitorParam()
    {
        httpClose(http);
    }
};
struct MediaSize {
    std::string name;
    const float WidthInInches;
    const float HeightInInches;
};

std::string GetUsbPrinterSerial(const std::string &deviceUri);
std::vector<PrinterInfo> GetUsbPrinters();
void ClearUsbPrinters();
void DeviceCb(const char *deviceClass, const char *deviceId, const char *deviceInfo,
    const char *deviceMakeAndModel, const char *deviceUri, const char *deviceLocation, void *userData);

class PrintCupsClient final : public DelayedSingleton<PrintCupsClient>,
    public std::enable_shared_from_this<PrintCupsClient> {
public:
    PrintCupsClient();
    ~PrintCupsClient();

    int32_t InitCupsResources();
    void StopCupsdService();
    bool IsCupsServerAlive();
    void QueryPPDInformation(const char *makeModel, std::vector<std::string> &ppds);
    int32_t AddPrinterToCups(const std::string &printerUri, const std::string &printerName,
        const std::string &printerMake);
    int32_t AddPrinterToCupsWithSpecificPpd(const std::string &printerUri, const std::string &printerName,
        const std::string &ppd);
    int32_t AddPrinterToCupsWithPpd(const std::string &printerUri, const std::string &printerName,
        const std::string &ppdName, const std::string &ppdData);
    int32_t QueryPrinterCapabilityByUri(const std::string &printerUri, const std::string &printerId,
        PrinterCapability &printerCaps);
    int32_t QueryPrinterStatusByUri(const std::string &printerUri, PrinterStatus &status);
    int32_t DeleteCupsPrinter(const char *printerName);
    void AddCupsPrintJob(const PrintJob &jobInfo);
    void CancelCupsJob(std::string serviceJobId);

    int32_t QueryAddedPrinterList(std::vector<std::string> &printerName);
    ppd_file_t* GetPPDFile(const std::string &printerName);
    int32_t SetDefaultPrinter(const std::string &printerName);

    int32_t QueryPrinterAttrList(const std::string &printerName, const std::vector<std::string> &keyList,
        std::vector<std::string> &valueList);
    int32_t QueryPrinterInfoByPrinterId(const std::string& printerId, PrinterInfo &info);
    int32_t DiscoverUsbPrinters(std::vector<PrinterInfo> &printers);
    int32_t QueryPrinterCapabilityFromPPD(const std::string &name, PrinterCapability &printerCaps);
    bool CheckPrinterOnline(JobMonitorParam *param, const uint32_t timeout = 3000);

private:
    bool HandleFiles(JobParameters *jobParams, uint32_t num_files, http_t *http, uint32_t jobId);
    void StartCupsJob(JobParameters *jobParams, CallbackFunc callback);
    static void SymlinkFile(std::string &srcFilePath, std::string &destFilePath);
    static void SymlinkDirectory(const char *srcDir, const char *destDir);
    static void CopyDirectory(const char *srcDir, const char *destDir);
    static bool ChangeFilterPermission(const std::string &path, mode_t mode);
    bool CheckPrinterMakeModel(JobParameters *jobParams);
    bool CheckPrinterDriverExist(const char *makeModel);
    bool VerifyPrintJob(JobParameters *jobParams, int &num_options, uint32_t &jobId,
        cups_option_t *options, http_t *http);
    static int FillBorderlessOptions(JobParameters *jobParams, int num_options, cups_option_t **options);
    static int FillLandscapeOptions(JobParameters *jobParams, int num_options, cups_option_t **options);
    static int FillJobOptions(JobParameters *jobParams, int num_options, cups_option_t **options);
    static float ConvertInchTo100MM(float num);
    static void UpdatePrintJobStateInJobParams(JobParameters *jobParams, uint32_t state, uint32_t subState);
    static std::string GetIpAddress(unsigned int number);
    static bool IsIpConflict(const std::string &printerId, std::string &nic);
    void StartMonitor(JobMonitorParam *jobParams);
    bool JobStatusCallback(JobMonitorParam *param);
    bool IsPrinterStopped(JobMonitorParam *param);
    bool GetBlockedAndUpdateSubstate(JobMonitorParam *param, StatePolicy policy,
        std::string substateString, PrintJobSubState jobSubstate);
    uint32_t GetNewSubstate(uint32_t substate, PrintJobSubState singleSubstate);
    bool QueryJobState(http_t *http, JobMonitorParam *param);
    bool UpdateJobState(JobMonitorParam *param, ipp_t *response);
    bool IfContinueToHandleJobState(JobMonitorParam *param);
    void BuildMonitorPolicy(JobMonitorParam *param);
    void ParseStateReasons(JobMonitorParam *param);

    int32_t StartCupsdServiceNotAlive();
    int32_t StartCupsdService();
    JobParameters *GetNextJob();
    void StartNextJob();
    void JobCompleteCallback();

    void UpdateBorderlessJobParameter(Json::Value& optionJson, JobParameters *params);
    void UpdateJobParameterByOption(Json::Value& optionJson, JobParameters *params);
    JobParameters* BuildJobParameters(const PrintJob &jobInfo);
    std::string GetColorString(uint32_t colorCode);
    std::string GetMedieSize(const PrintJob &jobInfo);
    std::string GetDulpexString(uint32_t duplexCode);
    void DumpJobParameters(JobParameters* jobParams);
    bool IsPrinterExist(const char *printerUri, const char *printerName, const char *ppdName);

    void ParsePPDInfo(ipp_t *response, const char *ppd_make_model, const char *ppd_name,
        std::vector<std::string> &ppds);
    ipp_t *QueryPrinterAttributesByUri(const std::string &printerUri, const std::string &nic, int num,
        const char * const *pattrs);
    bool ResumePrinter(const std::string &printerName);
    bool CancelPrinterJob(int cupsJobId);

private:
    bool toCups_ = true;
    IPrintAbilityBase* printAbility_ = nullptr;
    std::vector<JobParameters*> jobQueue_;
    JobParameters *currentJob_ = nullptr;
    std::vector<JobMonitorParam*> jobMonitorList_;
    std::mutex jobMonitorMutex_;
};
} // namespace OHOS::Print
#endif // PRINT_CUPS_CLIENT_H