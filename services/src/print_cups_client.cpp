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

#include "print_cups_client.h"

#include <string>
#include <cups/cups-private.h>
#include <thread>
#include <semaphore.h>
#include <csignal>
#include <cstdlib>

#include "nlohmann/json.hpp"
#include "print_service_ability.h"
#include "print_log.h"
#include "print_constant.h"

namespace OHOS::Print {
using namespace std;
using json = nlohmann::json;

const uint32_t THOUSAND_INCH = 1000;
const uint32_t CUPS_SEVER_PORT = 1631;
const uint32_t TIME_OUT = 2000;
const uint32_t CONVERSION_UNIT = 2540;
const uint32_t LONG_TIME_OUT = 3000;
const uint32_t LONG_LONG_TIME_OUT = 30000;
const uint32_t INTERVAL_FOR_QUERY = 2;
const uint32_t OFFLINE_RETRY_TIMES = 5;

static const std::string DEFAULT_USER = "default";
static const std::string PRINTER_STATE_WAITING_COMPLETE = "cups-waiting-for-job-completed";
static const std::string PRINTER_STATE_NONE = "none";
static const std::string PRINTER_STATE_EMPTY = "";
static const std::string PRINTER_STATE_MEDIA_EMPTY = "media-empty";
static const std::string PRINTER_STATE_MEDIA_JAM = "media-jam";
static const std::string PRINTER_STATE_PAUSED = "paused";
static const std::string PRINTER_STATE_TONER_LOW = "toner-low";
static const std::string PRINTER_STATE_TONER_EMPTY = "toner-empty";
static const std::string PRINTER_STATE_DOOR_EMPTY = "door-open";
static const std::string PRINTER_STATE_MEDIA_NEEDED = "media-needed";
static const std::string PRINTER_STATE_MARKER_LOW = "marker-supply-low";
static const std::string PRINTER_STATE_MARKER_EMPTY = "marker-supply-empty";
static const std::string PRINTER_STATE_INK_EMPTY = "marker-ink-almost-empty";
static const std::string PRINTER_STATE_COVER_OPEN = "cover-open";
static const std::string PRINTER_STATE_OFFLINE = "offline";
static const std::string DEFAULT_JOB_NAME = "test";

std::mutex PrintCupsClient::instanceLock_;
PrintCupsClient *PrintCupsClient::instance_ = nullptr;

PrintCupsClient::PrintCupsClient()
{}

PrintCupsClient::~PrintCupsClient()
{}

PrintCupsClient *PrintCupsClient::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(instanceLock_);
        if (instance_ == nullptr) {
            instance_ = new (std::nothrow) PrintCupsClient;
        }
    }
    return instance_;
}

int32_t PrintCupsClient::StartCupsdService()
{
    PRINT_HILOGD("StartCupsdService enter");
    int ret = 0;
    char pid[256];
    FILE *pid_fp = nullptr;
    pid_fp = popen("pidof cupsd", "r");
    if (pid_fp == nullptr) {
        PRINT_HILOGE("Failed to call popen function");
        ret = -1;
    } else {
        if (fgets(pid, sizeof(pid), pid_fp) != nullptr) {
            PRINT_HILOGD("The Process of CUPSD has existed, pid: %{public}s.", pid);
            ret = 0;
        } else {
            FILE *start_fp = nullptr;
            start_fp = popen("/system/bin/cupsd -f -c /etc/cups/cupsd.conf -s /etc/cups/cups-files.conf &", "r");
            if (start_fp == nullptr) {
                PRINT_HILOGE("Failed to call popen function");
                ret = -1;
            } else {
                PRINT_HILOGI("Start cupsd process success.");
                sleep(1);
                ret = 0;
            }
            pclose(start_fp);
        }
    }
    pclose(pid_fp);
    return ret;
}

void PrintCupsClient::StopCupsdService()
{
    PRINT_HILOGD("StopCupsdService enter");
    char pid[256];
    FILE *pid_fp = nullptr;
    pid_fp = popen("pidof cupsd", "r");
    if (pid_fp == nullptr) {
        PRINT_HILOGE("Failed to call popen function");
        return;
    }
    if (fgets(pid, sizeof(pid), pid_fp) != nullptr) {
        PRINT_HILOGI("Stop CUPSD Process");
        sleep(1);
        if (kill(atoi(pid), SIGTERM) == -1) {
            PRINT_HILOGE("Failed to kill cupsd process");
            return;
        }
        PRINT_HILOGE("kill cupsd process success");
    } else {
        PRINT_HILOGI("The Process of CUPSD is not existed.");
    }
    pclose(pid_fp);
}

int32_t PrintCupsClient::AddPrinterToCups(const std::string &printerUri, const std::string &printerName)
{
    PRINT_HILOGD("PrintCupsClient AddPrinterToCups start.");
    ipp_t *request;
    http_t *http = NULL;
    char uri[HTTP_MAX_URI];

    if (!IsCupsServerAlive())
        StartCupsdService();
    ippSetPort(CUPS_SEVER_PORT);
    request = ippNewRequest(IPP_OP_CUPS_ADD_MODIFY_PRINTER);
    httpAssembleURIf(HTTP_URI_CODING_ALL, uri, sizeof(uri), "ipp", NULL, "localhost", 0, "/printers/%s",
                     printerName.c_str());
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri", NULL, uri);
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name", NULL, cupsUser());
    ippAddString(request, IPP_TAG_PRINTER, IPP_TAG_TEXT, "printer-info", NULL, printerName.c_str());
    ippAddString(request, IPP_TAG_PRINTER, IPP_TAG_URI, "device-uri", NULL, printerUri.c_str());
    ippAddInteger(request, IPP_TAG_PRINTER, IPP_TAG_ENUM, "printer-state", IPP_PRINTER_IDLE);
    ippAddString(request, IPP_TAG_PRINTER, IPP_TAG_NAME, "ppd-name", NULL, "everywhere");
    ippAddBoolean(request, IPP_TAG_PRINTER, "printer-is-accepting-jobs", 1);
    ippAddBoolean(request, IPP_TAG_PRINTER, "printer-is-shared", 1);
    PRINT_HILOGD("IPP_OP_CUPS_ADD_MODIFY_PRINTER cupsDoRequest");
    ippDelete(cupsDoRequest(http, request, "/admin/"));
    if (cupsLastError() > IPP_STATUS_OK_CONFLICTING) {
        PRINT_HILOGE("add error: %s", cupsLastErrorString());
        return -1;
    }
    httpClose(http);
    PRINT_HILOGI("add success");
    return E_PRINT_NONE;
}
int32_t PrintCupsClient::QueryPrinterCapabilityByUri(const std::string &printerUri, PrinterCapability &printerCaps)
{
    PRINT_HILOGD("PrintCupsClient QueryPrinterCapabilityByUri start.");
    ipp_t *request; /* IPP Request */
    ipp_t *response; /* IPP Request */
    http_t *http = NULL;
    char scheme[HTTP_MAX_URI]; /* Method portion of URI */
    char username[HTTP_MAX_URI]; /* Username portion of URI */
    char host[HTTP_MAX_URI]; /* Host portion of URI */
    char resource[HTTP_MAX_URI]; /* Resource portion of URI */
    int port; /* Port portion of URI */

    static const char * const pattrs[] = {
        "all"
    };
    PRINT_HILOGD("QueryPrinterCapabilityByUri enter");
    httpSeparateURI(HTTP_URI_CODING_ALL, printerUri.c_str(), scheme, sizeof(scheme), username, sizeof(username), host,
                    sizeof(host), &port, resource, sizeof(resource));

    http = httpConnect2(host, port, NULL, AF_UNSPEC, HTTP_ENCRYPTION_IF_REQUESTED, 1, TIME_OUT, NULL);
    if (http == nullptr) {
        PRINT_HILOGD("connect printer failed");
        return -1;
    }
    request = ippNewRequest(IPP_OP_GET_PRINTER_ATTRIBUTES);
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri", NULL, printerUri.c_str());
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name", NULL, cupsUser());
    ippAddStrings(request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD, "requested-attributes", 1, NULL, pattrs);
    response = cupsDoRequest(http, request, "/");

    if (cupsLastError() > IPP_STATUS_OK_CONFLICTING) {
        PRINT_HILOGE("set default printers error: %s", cupsLastErrorString());
        ippDelete(response);
        return -1;
    }
    PRINT_HILOGD("get caps success: %s", cupsLastErrorString());
    ParsePrinterAttributes(response, printerCaps);
    httpClose(http);
    return E_PRINT_NONE;
}

void PrintCupsClient::AddCupsPrintJob(const PrintJob &jobInfo)
{
    JobParameters *jobParams =  BuildJobParameters(jobInfo);
    if (jobParams == nullptr) {
        PrintServiceAbility::GetInstance()->UpdatePrintJobState(jobParams->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_UNKNOWN);
        return;
    }
    DumpJobParameters(jobParams);
    jobQueue.push_back(jobParams);
    StartNextJob();
}

void PrintCupsClient::StartNextJob()
{
    if (jobQueue.size() == 0) {
        PRINT_HILOGE("no active job in jobQueue");
        return;
    }
    if (currentJob != nullptr) {
        PRINT_HILOGE("a active job is running, job len: %{public}zd", jobQueue.size());
        return;
    }
    PRINT_HILOGI("start next job from queue");

    currentJob = jobQueue.at(0);
    jobQueue.erase(jobQueue.begin());
    if (!currentJob) {
        PRINT_HILOGE("currentJob is nullptr");
        return;
    }
    StartCupsJob(currentJob);
}

void PrintCupsClient::JobCompleteCallback()
{
    PRINT_HILOGI("Previous job complete, start next job");
    if (!currentJob) {
        free(currentJob);
    }
    currentJob = nullptr;
    StartNextJob();
}

int PrintCupsClient::FillBorderlessOptions(JobParameters *jobParams, int num_options, cups_option_t **options)
{
    if (jobParams->borderless == 1 && jobParams->mediaType == CUPS_MEDIA_TYPE_PHOTO_GLOSSY) {
        PRINT_HILOGD("borderless job options");
        std::vector<MediaSize> mediaSizes;
        mediaSizes.push_back( { CUPS_MEDIA_4X6, 4000, 6000 } );
        mediaSizes.push_back( { CUPS_MEDIA_5X7, 5000, 7000 } );
        mediaSizes.push_back( { CUPS_MEDIA_A4, 8268, 11692 } );
        int sizeIndex = -1;
        float meidaWidth = 0;
        float mediaHeight = 0;
        for (size_t i = 0; i < mediaSizes.size(); i++) {
            if (mediaSizes[i].name == jobParams->mediaSize) {
                sizeIndex = i;
                break;
            }
        }
        if (sizeIndex >= 0) {
            meidaWidth = floorf(ConvertInchTo100MM(mediaSizes[sizeIndex].WidthInInches));
            mediaHeight = floorf(ConvertInchTo100MM(mediaSizes[sizeIndex].HeightInInches));
        } else {
            meidaWidth = floorf(ConvertInchTo100MM(mediaSizes[0].WidthInInches));
            mediaHeight = floorf(ConvertInchTo100MM(mediaSizes[0].HeightInInches));
        }
        PRINT_HILOGD("meidaWidth: %f", meidaWidth);
        PRINT_HILOGD("mediaHeight: %f", mediaHeight);
        std::stringstream value;
        value << "{media-size={x-dimension=" << meidaWidth << " y-dimension=" << mediaHeight;
        value << "} media-bottom-margin=" << 0 << " media-left-margin=" << 0 << " media-right-margin=" << 0;
        value << " media-top-margin=" << 0 << " media-type=\"" << jobParams->mediaType << "\"}";
        PRINT_HILOGD("value: %s", value.str().c_str());
        num_options = cupsAddOption("media-col", value.str().c_str(), num_options, options);
    } else {
        PRINT_HILOGD("not borderless job options");
        if (!jobParams->mediaSize.empty()) {
            num_options = cupsAddOption(CUPS_MEDIA, jobParams->mediaSize.c_str(), num_options, options);
        } else {
            num_options = cupsAddOption(CUPS_MEDIA, CUPS_MEDIA_A4, num_options, options);
        }
        if (!jobParams->mediaType.empty()) {
            num_options = cupsAddOption(CUPS_MEDIA_TYPE, jobParams->mediaType.c_str(), num_options, options);
        } else {
            num_options = cupsAddOption(CUPS_MEDIA_TYPE, CUPS_MEDIA_TYPE_PLAIN, num_options, options);
        }
    }
    return num_options;
}

int PrintCupsClient::FillJobOptions(JobParameters *jobParams, int num_options, cups_option_t **options)
{
    if (jobParams->numCopies >= 1) {
        num_options = cupsAddIntegerOption(CUPS_COPIES, jobParams->numCopies, num_options, options);
    } else {
        num_options = cupsAddIntegerOption(CUPS_COPIES, 1, num_options, options);
    }

    if (!jobParams->duplex.empty()) {
        num_options = cupsAddOption(CUPS_SIDES, jobParams->duplex.c_str(), num_options, options);
    } else {
        num_options = cupsAddOption(CUPS_SIDES, CUPS_SIDES_ONE_SIDED, num_options, options);
    }
    if (!jobParams->printQuality.empty()) {
        num_options = cupsAddOption(CUPS_PRINT_QUALITY, jobParams->printQuality.c_str(), num_options, options);
    } else {
        num_options = cupsAddOption(CUPS_PRINT_QUALITY, CUPS_PRINT_QUALITY_NORMAL, num_options, options);
    }
    if (!jobParams->color.empty()) {
        num_options = cupsAddOption(CUPS_PRINT_COLOR_MODE, jobParams->color.c_str(), num_options, options);
    } else {
        num_options = cupsAddOption(CUPS_PRINT_COLOR_MODE, CUPS_PRINT_COLOR_MODE_AUTO, num_options, options);
    }
    num_options = FillBorderlessOptions(jobParams, num_options, options);
    return num_options;
}

void PrintCupsClient::StartCupsJob(JobParameters *jobParams)
{
    http_t *http = nullptr;
    int num_options = 0;
    cups_option_t *options;
    cups_file_t *fp;
    int job_id;
    http_status_t status;
    char buffer[8192];
    ssize_t bytes;

    if (!IsCupsServerAlive())
        StartCupsdService();
    int num_files = jobParams->fdList.size();
    PRINT_HILOGD("StartCupsJob fill job options, num_files: %{public}d", num_files);
    num_options = FillJobOptions(jobParams, num_options, &options);
    if ((job_id = cupsCreateJob(http, jobParams->printerName.c_str(), jobParams->jobName.c_str(),
        num_options, options)) == 0) {
        PRINT_HILOGE("Unable to cupsCreateJob: %s", cupsLastErrorString());
        PrintServiceAbility::GetInstance()->UpdatePrintJobState(jobParams->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_UNKNOWN);
        JobCompleteCallback();
        return;
    }
    for (int i = 0; i < num_files; i++) {
        if ((fp = cupsFileOpenFd(jobParams->fdList[i], "rb")) == NULL) {
            PRINT_HILOGE("Unable to open print file, cancel the job");
            cupsCancelJob2(http, jobParams->printerName.c_str(), job_id, 0);
            JobCompleteCallback();
            return;
        }
        status = cupsStartDocument(http, jobParams->printerName.c_str(), job_id, jobParams->jobName.c_str(),
            jobParams->documentFormat.c_str(), i == (num_files - 1));
        while (status == HTTP_STATUS_CONTINUE && (bytes = cupsFileRead(fp, buffer, sizeof(buffer))) > 0)
            status = cupsWriteRequestData(http, buffer, (size_t)bytes);
        cupsFileClose(fp);
        if (status != HTTP_STATUS_CONTINUE || cupsFinishDocument(http, jobParams->printerName.c_str())
            != IPP_STATUS_OK) {
            PRINT_HILOGE("Unable to queue, error is %s, cancel the job and return...", cupsLastErrorString());
            cupsCancelJob2(http, jobParams->printerUri.c_str(), job_id, 0);
            PrintServiceAbility::GetInstance()->UpdatePrintJobState(jobParams->serviceJobId, PRINT_JOB_BLOCKED,
                PRINT_JOB_BLOCKED_UNKNOWN);
            JobCompleteCallback();
            return;
        }
    }
    jobParams->cupsJobId = job_id;
    PRINT_HILOGD("start job success, job_id: %d", job_id);
    JobMonitorParam *param = new (std::nothrow) JobMonitorParam { PrintServiceAbility::GetInstance(),
        jobParams->serviceJobId, job_id, jobParams->printerUri.c_str() };

    CallbackFunc callback = [this]() { JobCompleteCallback(); };
    std::thread jobMonitorThread(PrintCupsClient::MonitorJobState, param, callback);
    jobMonitorThread.detach();
}

void PrintCupsClient::MonitorJobState(JobMonitorParam *param, CallbackFunc callback)
{
    http_t *http = NULL;
    uint32_t fail_connect_times = 0;
    PRINT_HILOGD("MonitorJobState enter, cupsJobId: %{public}d", param->cupsJobId);
    ippSetPort(CUPS_SEVER_PORT);
    http = httpConnect2(cupsServer(), ippPort(), NULL, AF_UNSPEC, HTTP_ENCRYPTION_IF_REQUESTED, 1, LONG_TIME_OUT, NULL);
    JobStatus *jobStatus = new (std::nothrow) JobStatus { {'\0'}, (ipp_jstate_t)0, {'\0'}};
    JobStatus *prevousJobStatus = new (std::nothrow) JobStatus { {'\0'}, (ipp_jstate_t)0, {'\0'}};
    while (jobStatus->job_state < IPP_JSTATE_CANCELED) {
        if (httpGetFd(http) < 0) {
            PRINT_HILOGE("http is NULL");
            httpReconnect2(http, LONG_LONG_TIME_OUT, NULL);
        }
        if (httpGetFd(http) > 0 && CheckPrinterOnline(param->printerUri.c_str())) {
            fail_connect_times = 0;
            QueryJobState(http, param, jobStatus);
        } else if (fail_connect_times < OFFLINE_RETRY_TIMES) {
            PRINT_HILOGE("unable connect to printer, retry: %{public}d", fail_connect_times);
            fail_connect_times++;
            sleep(INTERVAL_FOR_QUERY);
            continue;
        } else {
            PRINT_HILOGE("_start(): The maximum number of connection failures has been exceeded");
            JobStatusCallback(param, jobStatus, true);
            break;
        }
        if (jobStatus->job_state < IPP_JSTATE_CANCELED)
            sleep(INTERVAL_FOR_QUERY);
        if (jobStatus->job_state == 0) {
            PRINT_HILOGD("job_state is 0, continue");
            continue;
        }
        if (prevousJobStatus != nullptr && prevousJobStatus->job_state == jobStatus->job_state &&
        strcmp(prevousJobStatus->printer_state_reasons, jobStatus->printer_state_reasons) == 0) {
            PRINT_HILOGD("the prevous jobState is the same as current, ignore");
            continue;
        }
        prevousJobStatus->job_state = jobStatus->job_state;
        strlcpy(prevousJobStatus->printer_state_reasons, jobStatus->printer_state_reasons,
                sizeof(jobStatus->printer_state_reasons));
        JobStatusCallback(param, jobStatus, false);
    }
    httpClose(http);
    delete param;
    delete jobStatus;
    delete prevousJobStatus;
    PRINT_HILOGI("FINISHED MONITORING JOB %{public}d\n", param->cupsJobId);
    callback();
    return;
}

void PrintCupsClient::JobStatusCallback(JobMonitorParam *param, JobStatus *jobStatus, bool isOffline)
{
    PRINT_HILOGD("JobStatusCallback enter, job_state: %{public}d", jobStatus->job_state);
    PRINT_HILOGD("JobStatusCallback enter, printer_state_reasons: %{public}s", jobStatus->printer_state_reasons);
    if (isOffline) {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_OFFLINE);
        return;
    }
    if (jobStatus->job_state == IPP_JOB_COMPLETED) {
        PRINT_HILOGD("IPP_JOB_COMPLETED");
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_COMPLETED,
            PRINT_JOB_COMPLETED_SUCCESS);
    } else if (jobStatus->job_state == IPP_JOB_PROCESSING) {
        PRINT_HILOGD("IPP_JOB_PROCESSING");
        if (strcmp(jobStatus->printer_state_reasons, PRINTER_STATE_WAITING_COMPLETE.c_str()) == 0 ||
            strcmp(jobStatus->printer_state_reasons, PRINTER_STATE_NONE.c_str()) == 0 ||
            strcmp(jobStatus->printer_state_reasons, PRINTER_STATE_EMPTY.c_str()) == 0) {
            param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_RUNNING,
                PRINT_JOB_BLOCKED_BUSY);
        } else {
            ReportBlockedReason(param, jobStatus);
        }
    } else if (jobStatus->job_state == IPP_JOB_CANCELED || jobStatus->job_state == IPP_JOB_ABORTED) {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_COMPLETED,
            PRINT_JOB_COMPLETED_CANCELLED);
    } else if (jobStatus->job_state == IPP_JOB_PENDING || jobStatus->job_state == IPP_JOB_HELD) {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_QUEUED,
            PRINT_JOB_BLOCKED_UNKNOWN);
    } else {
        PRINT_HILOGE("wrong job state: %{public}d", jobStatus->job_state);
    }
}

void PrintCupsClient::ReportBlockedReason(JobMonitorParam *param, JobStatus *jobStatus)
{
    if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_MEDIA_EMPTY.c_str()) != NULL) {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    } else if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_MEDIA_JAM.c_str()) != NULL) {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_JAMMED);
    } else if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_PAUSED.c_str()) != NULL) {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_SERVICE_REQUEST);
    } else if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_TONER_LOW.c_str()) != NULL) {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_LOW_ON_TONER);
    } else if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_TONER_EMPTY.c_str()) != NULL) {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_OUT_OF_TONER);
    } else if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_DOOR_EMPTY.c_str()) != NULL) {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_DOOR_OPEN);
    } else if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_MEDIA_NEEDED.c_str()) != NULL) {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_OUT_OF_PAPER);
    } else if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_MARKER_LOW.c_str()) != NULL) {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_LOW_ON_INK);
    } else if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_MARKER_EMPTY.c_str()) != NULL) {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_OUT_OF_INK);
    } else if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_INK_EMPTY.c_str()) != NULL) {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_OUT_OF_INK);
    } else if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_COVER_OPEN.c_str()) != NULL) {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_DOOR_OPEN);
    } else if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_OFFLINE.c_str()) != NULL) {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_OFFLINE);
    } else {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_UNKNOWN);
    }
}

void PrintCupsClient::QueryJobState(http_t *http, JobMonitorParam *param, JobStatus *jobStatus)
{
    ipp_t *request; /* IPP request */
    ipp_t *response; /* IPP response */
    ipp_attribute_t *attr; /* Attribute in response */
    int jattrsLen = 3;
    static const char * const jattrs[] = {
        "job-state",
        "job-state-reasons",
        "job-printer-state-reasons"
    };
    if (param->cupsJobId > 0) {
        request = ippNewRequest(IPP_OP_GET_JOB_ATTRIBUTES);
        ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri", NULL, param->printerUri.c_str());
        ippAddInteger(request, IPP_TAG_OPERATION, IPP_TAG_INTEGER, "job-id", param->cupsJobId);
        ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name", NULL, DEFAULT_USER.c_str());
        ippAddStrings(request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD, "requested-attributes", jattrsLen, NULL, jattrs);
        PRINT_HILOGD("get job state from cups service: start");
        response = cupsDoRequest(http, request, "/");
        if ((attr = ippFindAttribute(response, "job-state", IPP_TAG_ENUM)) != NULL) {
            jobStatus->job_state = (ipp_jstate_t)ippGetInteger(attr, 0);
        }
        if ((attr = ippFindAttribute(response, "job-state-reasons", IPP_TAG_KEYWORD)) != NULL) {
            ippAttributeString(attr, jobStatus->job_state_reasons, sizeof(jobStatus->job_state_reasons));
        }
        if ((attr = ippFindAttribute(response, "job-printer-state-reasons", IPP_TAG_KEYWORD)) != NULL) {
            ippAttributeString(attr, jobStatus->printer_state_reasons, sizeof(jobStatus->printer_state_reasons));
        }
        PRINT_HILOGE("JOB %{public}d: %{public}s (%{public}s), PRINTER: %s\n", param->cupsJobId,
            ippEnumString("job-state", (int)jobStatus->job_state), jobStatus->job_state_reasons,
            jobStatus->printer_state_reasons);
        ippDelete(response);
    }
}

bool PrintCupsClient::CheckPrinterOnline(const char* printerUri)
{
    http_t *http;
    char scheme[32];
    char userpass[256];
    char host[256];
    char resource[256];
    int port;
    httpSeparateURI(HTTP_URI_CODING_ALL, printerUri, scheme, sizeof(scheme), userpass, sizeof(userpass), host,
                    sizeof(host), &port, resource, sizeof(resource));
    http = httpConnect2(host, port, NULL, AF_UNSPEC, HTTP_ENCRYPTION_IF_REQUESTED, 1, LONG_TIME_OUT, NULL);
    if (http == nullptr) {
        PRINT_HILOGE("httpConnect2 printer failed");
        return false;
    }
    httpClose(http);
    return true;
}

void PrintCupsClient::CancelCupsJob(std::string serviceJobId)
{
    PRINT_HILOGD("CancelCupsJob(): Enter, serviceJobId: %{public}s", serviceJobId.c_str());
    int jobIndex = -1;
    for (size_t index = 0; index < jobQueue.size(); index++) {
        PRINT_HILOGD("jobQueue[index]->serviceJobId: %{public}s", jobQueue[index]->serviceJobId.c_str());
        if (jobQueue[index]->serviceJobId == serviceJobId) {
        jobIndex = index;
        break;
        }
    }
    PRINT_HILOGI("jobIndex: %{public}d", jobIndex);
    if (jobIndex >= 0) {
        PRINT_HILOGI("job in queue, delete");
        jobQueue.erase(jobQueue.begin() + jobIndex);
        PrintServiceAbility::GetInstance()->UpdatePrintJobState(serviceJobId, PRINT_JOB_COMPLETED,
            PRINT_JOB_COMPLETED_CANCELLED);
    } else {
        // 任务正在运行中
        if (currentJob && currentJob->serviceJobId == serviceJobId) {
            PRINT_HILOGI("cancel current job");
            if (cupsCancelJob2(CUPS_HTTP_DEFAULT, currentJob->printerName.c_str(),
                currentJob->cupsJobId, 0) != IPP_OK) {
                PRINT_HILOGE("cancel Joob Error %s", cupsLastErrorString());
                return;
            }
        } else {
            PRINT_HILOGI("job is not exist");
            PrintServiceAbility::GetInstance()->UpdatePrintJobState(serviceJobId, PRINT_JOB_COMPLETED,
                PRINT_JOB_COMPLETED_CANCELLED);
        }
    }
}

JobParameters* PrintCupsClient::BuildJobParameters(const PrintJob &jobInfo)
{
    JobParameters *params = nullptr;
    if (!jobInfo.HasOption()) {
        PRINT_HILOGE("option is empty");
        return params;
    }
    std::string option = jobInfo.GetOption();
    if (!json::accept(option)) {
        PRINT_HILOGE("option can not parse to json object");
        return params;
    }
    json optionJson = json::parse(option);
    PRINT_HILOGD("test optionJson: %{private}s", optionJson.dump().c_str());
    if (!optionJson.contains("printerUri") || !optionJson.contains("printerName")
        || !optionJson.contains("documentFormat")) {
        PRINT_HILOGE("The option does not have a necessary attribute.");
        return params;
    }
    params = new (std::nothrow) JobParameters {};
    jobInfo.GetFdList(params->fdList);
    params->serviceJobId = jobInfo.GetJobId();
    params->numCopies = jobInfo.GetCopyNumber();
    params->duplex = GetDulpexString(jobInfo.GetDuplexMode());
    params->jobOriginatingUserName = DEFAULT_USER;
    params->mediaSize = GetMedieSize(jobInfo);
    params->color = GetColorString(jobInfo.GetColorMode());
    params->printerName = optionJson["printerName"];
    params->printerUri = optionJson["printerUri"];
    params->documentFormat = optionJson["documentFormat"];
    if (optionJson.contains("documentCategory")) {
        params->borderless = optionJson["documentCategory"];
    } else {
        params->borderless = 0;
    }
    if (optionJson.contains("printQuality")) {
        params->printQuality = optionJson["printQuality"];
    } else {
        params->printQuality = CUPS_PRINT_QUALITY_NORMAL;
    }
    if (optionJson.contains("jobName")) {
        params->jobName = optionJson["jobName"];
    } else {
        params->jobName = DEFAULT_JOB_NAME;
    }
    if (optionJson.contains("mediaType")) {
        params->mediaType = optionJson["mediaType"];
    } else {
        params->mediaType = CUPS_MEDIA_TYPE_PLAIN;
    }
    return params;
}

void PrintCupsClient::DumpJobParameters(JobParameters* jobParams)
{
    PRINT_HILOGD("jobParams->serviceJobId: %{public}s", jobParams->serviceJobId.c_str());
    PRINT_HILOGD("jobParams->borderless: %{public}d", jobParams->borderless);
    PRINT_HILOGD("jobParams->numCopies: %{public}d", jobParams->numCopies);
    PRINT_HILOGD("jobParams->duplex: %{public}s", jobParams->duplex.c_str());
    PRINT_HILOGD("jobParams->printQuality: %{public}s", jobParams->printQuality.c_str());
    PRINT_HILOGD("jobParams->jobName: %{public}s", jobParams->jobName.c_str());
    PRINT_HILOGD("jobParams->jobOriginatingUserName: %{public}s", jobParams->jobOriginatingUserName.c_str());
    PRINT_HILOGD("jobParams->printerName: %{private}s", jobParams->printerName.c_str());
    PRINT_HILOGD("jobParams->printerUri: %{private}s", jobParams->printerUri.c_str());
    PRINT_HILOGD("jobParams->documentFormat: %{public}s", jobParams->documentFormat.c_str());
    PRINT_HILOGD("jobParams->mediaSize: %{public}s", jobParams->mediaSize.c_str());
    PRINT_HILOGD("jobParams->mediaType: %{public}s", jobParams->mediaType.c_str());
    PRINT_HILOGD("jobParams->color: %{public}s", jobParams->color.c_str());
}


std::string PrintCupsClient::GetMedieSize(const PrintJob &jobInfo)
{
    PrintPageSize pageSize;
    jobInfo.GetPageSize(pageSize);
    return pageSize.GetName();
}

std::string PrintCupsClient::GetDulpexString(uint32_t duplexCode)
{
    DuplexModeCode duplex = static_cast<DuplexModeCode>(duplexCode);
    switch (duplex) {
        case DUPLEX_MODE_ONE_SIDED:
            return CUPS_SIDES_ONE_SIDED;
        case DUPLEX_MODE_TWO_SIDED_LONG_EDGE:
            return CUPS_SIDES_TWO_SIDED_PORTRAIT;
        case DUPLEX_MODE_TWO_SIDED_SHORT_EDGE:
            return CUPS_SIDES_TWO_SIDED_LANDSCAPE;
        default:
            return CUPS_SIDES_ONE_SIDED;
    }
}

std::string PrintCupsClient::GetColorString(uint32_t colorCode)
{
    ColorModeCode color = static_cast<ColorModeCode>(colorCode);
    switch (color) {
        case COLOR_MODE_MONOCHROME:
            return CUPS_PRINT_COLOR_MODE_MONOCHROME;
        case COLOR_MODE_COLOR:
            return CUPS_PRINT_COLOR_MODE_COLOR;
        default:
            return CUPS_PRINT_COLOR_MODE_AUTO;
    }
}

bool PrintCupsClient::IsCupsServerAlive()
{
    http_t *http;
    ippSetPort(CUPS_SEVER_PORT);
    http = httpConnect2(cupsServer(), ippPort(), NULL, AF_UNSPEC, HTTP_ENCRYPTION_IF_REQUESTED, 1, LONG_TIME_OUT, NULL);
    if (http == nullptr) {
        PRINT_HILOGE("cups server is not alive");
        return false;
    }
    httpClose(http);
    return true;
}

/**
 * @brief check printer is exist
 * @param printerName printer name
 * @return true printer exist
 * @return false printer is not exist
 */
bool PrintCupsClient::IsPrinterExist(const char* printerName)
{
    int i; /* Looping var */
    bool printerExist = false;
    cups_dest_t *dests;
    PRINT_HILOGD("QueryPrinterExist enter");
    int num_dests = cupsGetDests2(CUPS_HTTP_DEFAULT, &dests);
    for (i = 0; i < num_dests; i++) {
        cups_dest_t *dest = dests + i;
        if (strcmp(dest->name, printerName) == 0) {
            printerExist = true;
            break;
        }
    }
    cupsFreeDests(num_dests, dests);
    return printerExist;
}

void PrintCupsClient::ParsePrinterAttributes(ipp_t *response, PrinterCapability &printerCaps)
{
    int i;
    ipp_attribute_t *attrptr;
    SetOptionAttribute(response, printerCaps);
    GetSupportedDuplexType(response, printerCaps);

    if ((attrptr = ippFindAttribute(response, "color-supported", IPP_TAG_BOOLEAN)) != NULL) {
        if (ippGetBoolean(attrptr, 0)) {
            printerCaps.SetColorMode(1);
        }
    }
    if ((attrptr = ippFindAttribute(response, "media-supported", IPP_TAG_KEYWORD)) != NULL) {
        PRINT_HILOGD("media-supported found; number of values %{public}d", ippGetCount(attrptr));
        std::vector<PrintPageSize> supportedMediaSizes;
        for (i = 0; i < ippGetCount(attrptr); i++) {
            const char* meidaSize = ippGetString(attrptr, i, NULL);
            PRINT_HILOGD("media-supported found; mediaSizes: %s", meidaSize);
            auto nativeObj = std::make_shared<PrintPageSize>();
            nativeObj->SetName(meidaSize);
            supportedMediaSizes.emplace_back(*nativeObj);
        }
        printerCaps.SetPageSize(supportedMediaSizes);
    }
}

void PrintCupsClient::SetOptionAttribute(ipp_t *response, PrinterCapability &printerCaps)
{
    ipp_attribute_t *attrptr;
    nlohmann::json options;
    if ((attrptr = ippFindAttribute(response, "printer-make-and-model", IPP_TAG_TEXT)) != NULL) {
        options["make"] = ippGetString(attrptr, 0, NULL);
    }
    if ((attrptr = ippFindAttribute(response, "printer-uuid", IPP_TAG_URI)) != NULL) {
        options["uuid"] = ippGetString(attrptr, 0, NULL);
    }
    if ((attrptr = ippFindAttribute(response, "printer-name", IPP_TAG_TEXT)) != NULL) {
        options["printerName"] = ippGetString(attrptr, 0, NULL);
    }
    nlohmann::json supportTypes = ParseSupportMediaTypes(response);
    options["supportedMediaTypes"] = supportTypes;
    nlohmann::json supportQualities = ParseSupportQualities(response);
    options["supportQualities"] = supportQualities;
    std::string optionStr = options.dump();
    printerCaps.SetOption(optionStr);
}

void PrintCupsClient::GetSupportedDuplexType(ipp_t *response, PrinterCapability &printerCaps)
{
    ipp_attribute_t *attrptr;
    if ((attrptr = ippFindAttribute(response, "sides-supported", IPP_TAG_KEYWORD)) != NULL) {
        if (ippContainsString(attrptr, CUPS_SIDES_TWO_SIDED_PORTRAIT)) {
            printerCaps.SetDuplexMode((uint32_t)DUPLEX_MODE_TWO_SIDED_LONG_EDGE);
        } else if (ippContainsString(attrptr, CUPS_SIDES_TWO_SIDED_LANDSCAPE)) {
            printerCaps.SetDuplexMode((uint32_t)DUPLEX_MODE_TWO_SIDED_SHORT_EDGE);
        } else {
            printerCaps.SetDuplexMode((uint32_t)DUPLEX_MODE_ONE_SIDED);
        }
    }
}

nlohmann::json PrintCupsClient::ParseSupportQualities(ipp_t *response)
{
    int i;
    ipp_attribute_t *attrptr;
    nlohmann::json supportedQualities = nlohmann::json::array();
    if ((attrptr = ippFindAttribute(response, "print-quality-supported", IPP_TAG_ENUM)) != NULL) {
        for (i = 0; i < ippGetCount(attrptr); i++) {
            uint32_t mediaQuality = ippGetInteger(attrptr, i);
            PRINT_HILOGD("print-quality-supported: %{public}d", mediaQuality);
            supportedQualities.push_back(mediaQuality);
        }
    }
    return supportedQualities;
}

nlohmann::json PrintCupsClient::ParseSupportMediaTypes(ipp_t *response)
{
    int i;
    ipp_attribute_t *attrptr;
    nlohmann::json _supportedMediaTypes = nlohmann::json::array();
    if (((attrptr = ippFindAttribute(response, "media-type-supported", IPP_TAG_KEYWORD)) != NULL)
          || ((attrptr = ippFindAttribute(response, "media-type-supported", IPP_TAG_NAME)) != NULL)) {
        PRINT_HILOGD("media-type-supported found; number of values %d", ippGetCount(attrptr));
        for (i = 0; i < ippGetCount(attrptr); i++) {
            const char* mediaType = ippGetString(attrptr, i, NULL);
            PRINT_HILOGD("media-type-supported found; mediaType: %s", mediaType);
            if (strcasestr(mediaType, "photographic-glossy")) {
                _supportedMediaTypes.push_back((uint32_t)MEDIA_PHOTO_GLOSSY);
            } else if (strcasestr(mediaType, "photo")) {
                _supportedMediaTypes.push_back((uint32_t)MEDIA_PHOTO);
            } else if (strcasestr(mediaType, "stationery")) {
                _supportedMediaTypes.push_back((uint32_t)MEDIA_PLAIN);
            } else if (strcasestr(mediaType, "auto")) {
                _supportedMediaTypes.push_back((uint32_t)MEDIA_AUTO);
            }
        }
        if (_supportedMediaTypes.size() == 0) {
            _supportedMediaTypes.push_back((uint32_t)MEDIA_PLAIN);
            _supportedMediaTypes.push_back((uint32_t)MEDIA_PHOTO);
            _supportedMediaTypes.push_back((uint32_t)MEDIA_PHOTO_GLOSSY);
        }
    }
    return _supportedMediaTypes;
}

float PrintCupsClient::ConvertInchTo100MM(float num)
{
    return ((num / THOUSAND_INCH) * CONVERSION_UNIT);
}
}