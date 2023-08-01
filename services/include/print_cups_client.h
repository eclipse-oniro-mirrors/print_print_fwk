/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
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

#include <string>
#include <vector>
#include <functional>
#include <cups/cups-private.h>
#include <nlohmann/json.hpp>

#include "print_service_ability.h"
#include "print_job.h"

namespace OHOS::Print {
using json = nlohmann::json;
typedef std::function<void()> CallbackFunc;

typedef struct {
    const char *uri;
    int valid;
} parsed_uri;

#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

enum MediaTypeCode {
    MEDIA_PLAIN,
    MEDIA_SPECIAL,
    MEDIA_PHOTO,
    MEDIA_TRANSPARENCY,
    MEDIA_IRON_ON,
    MEDIA_IRON_ON_MIRROR,
    MEDIA_ADVANCED_PHOTO,
    MEDIA_FAST_TRANSPARENCY,
    MEDIA_BROCHURE_GLOSSY,
    MEDIA_BROCHURE_MATTE,
    MEDIA_PHOTO_GLOSSY,
    MEDIA_PHOTO_MATTE,
    MEDIA_PREMIUM_PHOTO,
    MEDIA_OTHER_PHOTO,
    MEDIA_PRINTABLE_CD,
    MEDIA_PREMIUM_PRESENTATION,
    MEDIA_AUTO = 98,
    MEDIA_UNKNOWN = 99 // New types above this line
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
    int cupsJobId;
    uint32_t borderless;
    uint32_t numCopies;
    std::string duplex;
    std::string printQuality;
    std::string jobName;
    std::string jobOriginatingUserName;
    std::string printerName;
    std::string printerUri;
    std::string documentFormat;
    std::string mediaSize;
    std::string mediaType;
    std::string color;
    std::string serviceJobId;
    std::vector<uint32_t> fdList;
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
};
struct MediaSize {
    std::string name;
    const float WidthInInches;
    const float HeightInInches;
};

class PrintCupsClient final {
  public:
    PrintCupsClient();
    ~PrintCupsClient();
    static PrintCupsClient *GetInstance();

    int32_t StartCupsdService();
    void StopCupsdService();
    int32_t SetCupsPrinter(const std::string &printerUri, const std::string &printerName);
    int32_t GetPrinterCapabilities(const std::string &printerUri, PrinterCapability &printerCaps);
    void AddCupsPrintJob(const PrintJob &jobInf);
    void CancelCupsJob(std::string serviceJobId);

  private:
    static void MonitorJobState(JobMonitorParam *param, CallbackFunc callback);
    static void QueryJobState(http_t *http, JobMonitorParam *param, JobStatus *jobStatus);
    static bool CheckPrinterOnline(const char* printerUri);
    static void JobStatusCallback(JobMonitorParam *param, JobStatus *jobStatus, bool isOffline);
    static void ReportBlockedReason(JobMonitorParam *param, JobStatus *jobStatus);

    void StartNextJob();
    void JobCompleteCallback();
    void StartCupsJob(JobParameters *jobParams);
    int FillBorderlessOptions(JobParameters *jobParams, int num_options, cups_option_t **options);
    int FillJobOptions(JobParameters *jobParams, int num_options, cups_option_t **options);
    JobParameters* BuildJobParameters(const PrintJob &jobInfo);
    std::string GetColorString(uint32_t colorCode);
    std::string GetMedieSize(const PrintJob &jobInfo);
    std::string GetDulpexString(uint32_t duplexCode);
    void DumpJobParameters(JobParameters* jobParams);
    bool IsCupsServerAlive();
    bool IsPrinterExist(const char* printerName);

    void ParsePrinterAttributes(ipp_t *response, PrinterCapability &printerCaps);
    void SetOptionAttribute(ipp_t *response, PrinterCapability &printerCaps);
    void GetSupportedDuplexType(ipp_t *response, PrinterCapability &printerCaps);
    nlohmann::json ParseSupportQualities(ipp_t *response);
    nlohmann::json ParseSupportMediaTypes(ipp_t *response);
    std::string ParsePrinterUris(ipp_t *response);

  private:
    static std::mutex instanceLock_;
    static PrintCupsClient* instance_;
    std::vector<JobParameters*> jobQueue;
    JobParameters *currentJob = nullptr;
};
} // namespace OHOS::Print
#endif // PRINT_CUPS_CLIENT_H