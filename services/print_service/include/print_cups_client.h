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
#include <cups/cups-private.h>
#include <nlohmann/json.hpp>

#include "singleton.h"
#include "print_service_ability.h"
#include "print_job.h"

namespace OHOS::Print {
using json = nlohmann::json;
typedef std::function<void()> CallbackFunc;

enum MediaTypeCode {
    MEDIA_PLAIN = 0,
    MEDIA_SPECIAL = 1,
    MEDIA_PHOTO = 2,
    MEDIA_TRANSPARENCY = 3,
    MEDIA_IRON_ON = 4,
    MEDIA_IRON_ON_MIRROR = 5,
    MEDIA_ADVANCED_PHOTO = 6,
    MEDIA_FAST_TRANSPARENCY = 7,
    MEDIA_BROCHURE_GLOSSY = 8,
    MEDIA_BROCHURE_MATTE = 9,
    MEDIA_PHOTO_GLOSSY = 10,
    MEDIA_PHOTO_MATTE = 11,
    MEDIA_PREMIUM_PHOTO = 12,
    MEDIA_OTHER_PHOTO = 13,
    MEDIA_PRINTABLE_CD = 14,
    MEDIA_PREMIUM_PRESENTATION = 15,
    MEDIA_AUTO = 98,
    MEDIA_UNKNOWN = 99
};

enum DuplexModeCode {
    DUPLEX_MODE_ONE_SIDED = 0,
    DUPLEX_MODE_TWO_SIDED_LONG_EDGE = 1,
    DUPLEX_MODE_TWO_SIDED_SHORT_EDGE = 2,
};

enum ColorModeCode {
    COLOR_MODE_MONOCHROME = 0,
    COLOR_MODE_COLOR = 1,
    COLOR_MODE_AUTO = 2
};

enum PrintQualityCode {
    PRINT_QUALITY_DRAFT = 3,
    PRINT_QUALITY_NORMAL = 4,
    PRINT_QUALITY_HIGH = 5
};

struct JobParameters {
    uint32_t cupsJobId;
    uint32_t borderless;
    uint32_t numCopies;
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
};
struct MediaSize {
    std::string name;
    const float WidthInInches;
    const float HeightInInches;
};

class PrintCupsClient final : public DelayedSingleton<PrintCupsClient> {
public:
    PrintCupsClient();
    ~PrintCupsClient();

    int32_t InitCupsResources();
    void StopCupsdService();
    void QueryPPDInformation(const char *makeModel, std::vector<std::string> &ppds);
    int32_t AddPrinterToCups(const std::string &printerUri, const std::string &printerName,
        const std::string &printerMake);
    int32_t QueryPrinterCapabilityByUri(const std::string &printerUri, const std::string &printerId,
        PrinterCapability &printerCaps);
    int32_t DeleteCupsPrinter(const char *printerName);
    void AddCupsPrintJob(const PrintJob &jobInfo);
    void CancelCupsJob(std::string serviceJobId);

private:
    static void StartCupsJob(JobParameters *jobParams, CallbackFunc callback);
    static void MonitorJobState(JobMonitorParam *param, CallbackFunc callback);
    static void QueryJobState(http_t *http, JobMonitorParam *param, JobStatus *jobStatus);
    static bool CheckPrinterOnline(const char* printerUri, std::string printerId);
    static void JobStatusCallback(JobMonitorParam *param, JobStatus *jobStatus, bool isOffline);
    static void ReportBlockedReason(JobMonitorParam *param, JobStatus *jobStatus);
    static void SymlinkDirectory(const char *srcDir, const char *destDir);
    static void CopyDirectory(const char *srcDir, const char *destDir);
    static void ChangeFilterPermission(const std::string &path, mode_t mode);
    static bool CheckPrinterMakeModel(JobParameters *jobParams);
    static bool VerifyPrintJob(JobParameters *jobParams, int &num_options, uint32_t &jobId,
        cups_option_t *options, http_t *http);
    static int FillBorderlessOptions(JobParameters *jobParams, int num_options, cups_option_t **options);
    static int FillJobOptions(JobParameters *jobParams, int num_options, cups_option_t **options);
    static float ConvertInchTo100MM(float num);
    static std::string GetIpAddress(unsigned int number);
    static bool IsIpConflict(const std::string &printerId, std::string &nic);

    int32_t StartCupsdService();
    void StartNextJob();
    void JobCompleteCallback();
    JobParameters* BuildJobParameters(const PrintJob &jobInfo);
    std::string GetColorString(uint32_t colorCode);
    std::string GetMedieSize(const PrintJob &jobInfo);
    std::string GetDulpexString(uint32_t duplexCode);
    void DumpJobParameters(JobParameters* jobParams);
    bool IsCupsServerAlive();
    bool IsPrinterExist(const char *printerUri, const char *printerName, const char *ppdName);

    void ParsePrinterAttributes(ipp_t *response, PrinterCapability &printerCaps);
    void SetOptionAttribute(ipp_t *response, PrinterCapability &printerCaps);
    void GetSupportedDuplexType(ipp_t *response, PrinterCapability &printerCaps);
    nlohmann::json ParseSupportQualities(ipp_t *response);
    nlohmann::json ParseSupportMediaTypes(ipp_t *response);
    void ParsePPDInfo(ipp_t *response, const char *ppd_make_model, const char *ppd_name,
        std::vector<std::string> &ppds);

private:
    std::vector<JobParameters*> jobQueue_;
    JobParameters *currentJob_ = nullptr;
};
} // namespace OHOS::Print
#endif // PRINT_CUPS_CLIENT_H