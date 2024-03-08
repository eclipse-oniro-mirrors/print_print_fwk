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

#include "print_cups_client.h"

#include <string>
#include <cups/cups-private.h>
#include <thread>
#include <semaphore.h>
#include <csignal>
#include <cstdlib>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <wifi_device.h>
#include <wifi_p2p.h>
#include <wifi_p2p_msg.h>

#include "system_ability_definition.h"
#include "parameter.h"
#include "nlohmann/json.hpp"
#include "print_service_ability.h"
#include "print_log.h"
#include "print_constant.h"
#include "print_utils.h"

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
const uint32_t RESOURCE_COUNT = 2;
const uint32_t DIR_COUNT = 3;
const uint32_t INDEX_ZERO = 0;
const uint32_t INDEX_ONE = 1;
const uint32_t INDEX_TWO = 2;
const uint32_t MAX_RETRY_TIMES = 5;
const uint32_t BUFFER_LEN = 256;
const uint32_t DIR_MODE = 0771;
const uint32_t IP_RIGHT_SHIFT_0 = 0;
const uint32_t IP_RIGHT_SHIFT_8 = 8;
const uint32_t IP_RIGHT_SHIFT_16 = 16;
const uint32_t IP_RIGHT_SHIFT_24 = 24;

static const std::string CUPS_ROOT_DIR = "/data/service/el1/public/print_service/cups";
static const std::string CUPS_RUN_DIR = "/data/service/el1/public/print_service/cups/run";
static const std::string DEFAULT_PPD_NAME = "everywhere";
static const std::string DEFAULT_MAKE_MODEL = "IPP Everywhere";
static const std::string DEFAULT_USER = "default";
static const std::string PRINTER_STATE_WAITING_COMPLETE = "cups-waiting-for-job-completed";
static const std::string PRINTER_STATE_WIFI_NOT_CONFIGURED = "wifi-not-configured-report";
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
static const std::string CUPSD_CONTROL_PARAM = "print.cupsd.ready";
static const std::string P2P_PRINTER = "p2p";
static const std::vector<std::string> IGNORE_STATE_LIST = {
    PRINTER_STATE_WAITING_COMPLETE, PRINTER_STATE_NONE, PRINTER_STATE_EMPTY, PRINTER_STATE_WIFI_NOT_CONFIGURED
};

PrintCupsClient::PrintCupsClient()
{}

PrintCupsClient::~PrintCupsClient()
{}

int32_t PrintCupsClient::StartCupsdService()
{
    PRINT_HILOGD("StartCupsdService enter");
    if (!IsCupsServerAlive()) {
        PRINT_HILOGI("The cupsd process is not started, start it now.");
        int result = SetParameter(CUPSD_CONTROL_PARAM.c_str(), "true");
        if (result) {
            PRINT_HILOGD("SetParameter failed: %{public}d.", result);
            return E_PRINT_SERVER_FAILURE;
        }
        const int bufferSize = 96;
        char value[bufferSize] = {0};
        GetParameter(CUPSD_CONTROL_PARAM.c_str(), "", value, bufferSize-1);
        PRINT_HILOGD("print.cupsd.ready value: %{public}s.", value);
        return E_PRINT_NONE;
    }
    std::string pidFile = CUPS_RUN_DIR + "/cupsd.pid";
    struct stat sb;
    if (stat(pidFile.c_str(), &sb) != 0) {
        PRINT_HILOGI("stat pidFile failed.");
        return E_PRINT_SERVER_FAILURE;
    }
    char realPidFile[PATH_MAX] = {};
    if (realpath(pidFile.c_str(), realPidFile) == nullptr) {
        PRINT_HILOGE("The realPidFile is null.");
        return E_PRINT_SERVER_FAILURE;
    }
    int fd;
    if ((fd = open(realPidFile, O_RDONLY)) < 0) {
        PRINT_HILOGE("Open pidFile error!");
        return E_PRINT_SERVER_FAILURE;
    }
    lseek(fd, 0, SEEK_SET);
    char buf[BUFFER_LEN] = {0};
    ssize_t bytes;
    if ((bytes = read(fd, buf, sb.st_size)) < 0) {
        PRINT_HILOGE("Read pidFile error!");
        close(fd);
        return E_PRINT_SERVER_FAILURE;
    }
    close(fd);
    PRINT_HILOGD("The Process of CUPSD has existed, pid: %{public}s.", buf);
    return E_PRINT_NONE;
}

void PrintCupsClient::ChangeFilterPermission(const std::string &path, mode_t mode)
{
    DIR *dir = opendir(path.c_str());
    if (dir == nullptr) {
        return;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string fileName = entry->d_name;
        if (fileName == "." || fileName == "..") {
            continue;
        }
        std::string filePath = path + "/" + fileName;
        struct stat fileStat;
        if (stat(filePath.c_str(), &fileStat) == -1) {
            continue;
        }
        if (S_ISDIR(fileStat.st_mode)) {
            ChangeFilterPermission(filePath.c_str(), mode);
        } else if (S_ISREG(fileStat.st_mode)) {
            if (chmod(filePath.c_str(), mode) == -1) {
                PRINT_HILOGE("Failed to change mode: %{private}s", filePath.c_str());
            }
        }
    }
    closedir(dir);
}

void PrintCupsClient::SymlinkDirectory(const char *srcDir, const char *destDir)
{
    DIR *dir = opendir(srcDir);
    if (dir == nullptr) {
        PRINT_HILOGE("Failed to open Dir: %{private}s", srcDir);
        return;
    }
    if (access(destDir, F_OK) != 0) {
        mkdir(destDir, DIR_MODE);
    }
    struct dirent *file;
    struct stat filestat;
    while ((file = readdir(dir)) != nullptr) {
        if (strcmp(file->d_name, ".") == 0 || strcmp(file->d_name, "..") == 0) {
            continue;
        }
        std::string srcFilePath = std::string(srcDir) + "/" + std::string(file->d_name);
        std::string destFilePath = std::string(destDir) + "/" + std::string(file->d_name);

        stat(srcFilePath.c_str(), &filestat);
        if (S_ISDIR(filestat.st_mode)) {
            SymlinkDirectory(srcFilePath.c_str(), destFilePath.c_str());
        } else {
            int ret = symlink(srcFilePath.c_str(), destFilePath.c_str());
            PRINT_HILOGI("symlink ret = %{public}d, errno = %{public}d", ret, errno);
            if (ret == 0) {
                PRINT_HILOGE("symlink success");
            } else {
                PRINT_HILOGE("symlink failed");
            }
        }
    }
    closedir(dir);
}

void PrintCupsClient::CopyDirectory(const char *srcDir, const char *destDir)
{
    DIR *dir = opendir(srcDir);
    if (dir == nullptr) {
        PRINT_HILOGE("Failed to open Dir: %{private}s", srcDir);
        return;
    }
    if (access(destDir, F_OK) != 0) {
        mkdir(destDir, DIR_MODE);
    }
    struct dirent *file;
    struct stat filestat;
    while ((file = readdir(dir)) != nullptr) {
        if (strcmp(file->d_name, ".") == 0 || strcmp(file->d_name, "..") == 0) {
            continue;
        }
        std::string srcFilePath = std::string(srcDir) + "/" + std::string(file->d_name);
        std::string destFilePath = std::string(destDir) + "/" + std::string(file->d_name);

        stat(srcFilePath.c_str(), &filestat);
        if (S_ISDIR(filestat.st_mode)) {
            CopyDirectory(srcFilePath.c_str(), destFilePath.c_str());
            chmod(destFilePath.c_str(), filestat.st_mode);
        } else {
            char realSrc[PATH_MAX] = {};
            if (realpath(srcFilePath.c_str(), realSrc) == nullptr) {
                PRINT_HILOGE("The realSrc is null.");
                continue;
            }
            FILE *srcFile = fopen(realSrc, "rb");
            if (srcFile == nullptr) {
                continue;
            }
            FILE *destFile = fopen(destFilePath.c_str(), "wb");
            if (destFile == nullptr) {
                fclose(srcFile);
                continue;
            }
            char buffer[4096];
            size_t bytesRead;
            while ((bytesRead = fread(buffer, 1, sizeof(buffer), srcFile)) > 0) {
                fwrite(buffer, 1, bytesRead, destFile);
            }
            fclose(srcFile);
            fclose(destFile);
            chmod(destFilePath.c_str(), filestat.st_mode);
        }
    }
    closedir(dir);
}

int32_t PrintCupsClient::InitCupsResources()
{
    string array[RESOURCE_COUNT][DIR_COUNT] = {
        {"/system/bin/cups/", CUPS_ROOT_DIR + "/serverbin", CUPS_ROOT_DIR + "/serverbin/daemon"},
        {"/system/etc/cups/share/", CUPS_ROOT_DIR + "/datadir", CUPS_ROOT_DIR + "/datadir/mime"}
    };
    for (uint32_t i = 0; i < RESOURCE_COUNT; i++) {
        if (access(array[i][INDEX_TWO].c_str(), F_OK) != -1) {
            PRINT_HILOGD("The resource has been copied.");
            continue;
        }
        if (i == 0) {
            SymlinkDirectory(array[i][INDEX_ZERO].c_str(), array[i][INDEX_ONE].c_str());
        } else {
            CopyDirectory(array[i][INDEX_ZERO].c_str(), array[i][INDEX_ONE].c_str());
        }
    }
    return StartCupsdService();
}

void PrintCupsClient::StopCupsdService()
{
    PRINT_HILOGD("StopCupsdService enter");
    if (!IsCupsServerAlive()) {
        PRINT_HILOGI("The cupsd process is not started, no need stop.");
        return;
    }
    PRINT_HILOGI("The cupsd process is started, stop it now.");
    int result = SetParameter(CUPSD_CONTROL_PARAM.c_str(), "false");
    if (result) {
        PRINT_HILOGD("SetParameter failed: %{public}d.", result);
        return;
    }
    const int bufferSize = 96;
    char value[bufferSize] = {0};
    GetParameter(CUPSD_CONTROL_PARAM.c_str(), "", value, bufferSize-1);
    PRINT_HILOGD("print.cupsd.ready value: %{public}s.", value);
}

void PrintCupsClient::QueryPPDInformation(const char *makeModel, std::vector<std::string> &ppds)
{
    ipp_t *request;
    ipp_t *response;
    const char *ppd_make_model;
    const char *ppd_name;

    request = ippNewRequest(CUPS_GET_PPDS);
    if (makeModel)
        ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_TEXT, "ppd-make-and-model", NULL, makeModel);
 
    PRINT_HILOGD("CUPS_GET_PPDS start.");
    if ((response = cupsDoRequest(CUPS_HTTP_DEFAULT, request, "/")) != NULL) {
        if (response->request.status.status_code > IPP_OK_CONFLICT) {
            PRINT_HILOGE("GetAvaiablePPDS failed: %{public}s", cupsLastErrorString());
            ippDelete(response);
            return;
        }
        ParsePPDInfo(response, ppd_make_model, ppd_name, ppds);
        ippDelete(response);
    } else {
        PRINT_HILOGE("GetAvaiablePPDS failed: %{public}s", cupsLastErrorString());
    }
}

void PrintCupsClient::ParsePPDInfo(ipp_t *response, const char *ppd_make_model, const char *ppd_name,
    std::vector<std::string> &ppds)
{
    for (ipp_attribute_t *attr = response->attrs; attr != NULL; attr = attr->next) {
        while (attr != NULL && attr->group_tag != IPP_TAG_PRINTER)
            attr = attr->next;
        if (attr == NULL) {
            break;
        }
        ppd_make_model = NULL;
        ppd_name = NULL;

        while (attr != NULL && attr->group_tag == IPP_TAG_PRINTER) {
            if (!strcmp(attr->name, "ppd-make-and-model") && attr->value_tag == IPP_TAG_TEXT)
                ppd_make_model = attr->values[0].string.text;
            else if (!strcmp(attr->name, "ppd-name") && attr->value_tag == IPP_TAG_NAME)
                ppd_name = attr->values[0].string.text;
            attr = attr->next;
        }
        if (ppd_make_model == NULL || ppd_name == NULL) {
            if (attr == NULL)
                break;
            else
                continue;
        }
        ppds.push_back(ppd_name);
        PRINT_HILOGI("ppd: name = %{private}s, make-and-model = %{private}s", ppd_name, ppd_make_model);
        if (attr == NULL)
            break;
    }
}

int32_t PrintCupsClient::AddPrinterToCups(const std::string &printerUri, const std::string &printerName,
    const std::string &printerMake)
{
    PRINT_HILOGD("PrintCupsClient AddPrinterToCups start, printerMake: %{public}s", printerMake.c_str());
    ipp_t *request;
    http_t *http = NULL;
    char uri[HTTP_MAX_URI];
    std::vector<string> ppds;
    std::string ppd = DEFAULT_PPD_NAME;
    std::string standardName = PrintUtil::StandardizePrinterName(printerName);

    ippSetPort(CUPS_SEVER_PORT);
    QueryPPDInformation(printerMake.c_str(), ppds);
    if (!ppds.empty()) {
        ppd = ppds[0];
        std::string serverBin = CUPS_ROOT_DIR + "/serverbin";
        mode_t permissions = S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH;
        ChangeFilterPermission(serverBin, permissions);
    }
    PRINT_HILOGI("ppd driver: %{public}s", ppd.c_str());
    if (IsPrinterExist(printerUri.c_str(), standardName.c_str(), ppd.c_str())) {
        PRINT_HILOGI("add success, printer has added");
        return E_PRINT_NONE;
    }
    request = ippNewRequest(IPP_OP_CUPS_ADD_MODIFY_PRINTER);
    httpAssembleURIf(HTTP_URI_CODING_ALL, uri, sizeof(uri), "ipp", NULL, "localhost", 0, "/printers/%s",
                     standardName.c_str());
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri", NULL, uri);
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name", NULL, cupsUser());
    ippAddString(request, IPP_TAG_PRINTER, IPP_TAG_TEXT, "printer-info", NULL, standardName.c_str());
    ippAddString(request, IPP_TAG_PRINTER, IPP_TAG_URI, "device-uri", NULL, printerUri.c_str());
    ippAddInteger(request, IPP_TAG_PRINTER, IPP_TAG_ENUM, "printer-state", IPP_PRINTER_IDLE);
    ippAddString(request, IPP_TAG_PRINTER, IPP_TAG_NAME, "ppd-name", NULL, ppd.c_str());
    ippAddBoolean(request, IPP_TAG_PRINTER, "printer-is-accepting-jobs", 1);
    ippAddBoolean(request, IPP_TAG_PRINTER, "printer-is-shared", 1);
    PRINT_HILOGD("IPP_OP_CUPS_ADD_MODIFY_PRINTER cupsDoRequest");
    ippDelete(cupsDoRequest(http, request, "/admin/"));
    if (cupsLastError() > IPP_STATUS_OK_CONFLICTING) {
        PRINT_HILOGE("add error: %s", cupsLastErrorString());
        return E_PRINT_SERVER_FAILURE;
    }
    httpClose(http);
    PRINT_HILOGI("add success");
    return E_PRINT_NONE;
}

int32_t PrintCupsClient::DeleteCupsPrinter(const char *printerName)
{
    ipp_t *request;
    char uri[HTTP_MAX_URI];
    http_t *http = NULL;

    PRINT_HILOGD("PrintCupsClient DeleteCupsPrinter start: %{private}s", printerName);
    request = ippNewRequest(IPP_OP_CUPS_DELETE_PRINTER);
    httpAssembleURIf(HTTP_URI_CODING_ALL, uri, sizeof(uri), "ipp", NULL, "localhost", 0, "/printers/%s", printerName);
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri", NULL, uri);
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name", NULL, cupsUser());
    ippDelete(cupsDoRequest(http, request, "/admin/"));
    if (cupsLastError() > IPP_STATUS_OK_CONFLICTING) {
        PRINT_HILOGE("DeleteCupsPrinter error: %{public}s", cupsLastErrorString());
        return E_PRINT_SERVER_FAILURE;
    }
    return E_PRINT_NONE;
}

int32_t PrintCupsClient::QueryPrinterCapabilityByUri(const std::string &printerUri, const std::string &printerId,
    PrinterCapability &printerCaps)
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

    std::string nic;
    if (IsIpConflict(printerId, nic)) {
        http = httpConnect3(host, port, NULL, AF_UNSPEC, HTTP_ENCRYPTION_IF_REQUESTED, 1, TIME_OUT, NULL, nic.c_str());
    } else {
        http = httpConnect2(host, port, NULL, AF_UNSPEC, HTTP_ENCRYPTION_IF_REQUESTED, 1, TIME_OUT, NULL);
    }
    if (http == nullptr) {
        PRINT_HILOGD("connect printer failed");
        return E_PRINT_SERVER_FAILURE;
    }
    request = ippNewRequest(IPP_OP_GET_PRINTER_ATTRIBUTES);
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri", NULL, printerUri.c_str());
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name", NULL, cupsUser());
    ippAddStrings(request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD, "requested-attributes", 1, NULL, pattrs);
    response = cupsDoRequest(http, request, "/");

    if (cupsLastError() > IPP_STATUS_OK_CONFLICTING) {
        PRINT_HILOGE("set default printers error: %{public}s", cupsLastErrorString());
        ippDelete(response);
        return E_PRINT_SERVER_FAILURE;
    }
    PRINT_HILOGD("get caps success: %{public}s", cupsLastErrorString());
    ParsePrinterAttributes(response, printerCaps);
    httpClose(http);
    return E_PRINT_NONE;
}

void PrintCupsClient::AddCupsPrintJob(const PrintJob &jobInfo)
{
    JobParameters *jobParams =  BuildJobParameters(jobInfo);
    if (jobParams == nullptr) {
        return;
    }
    DumpJobParameters(jobParams);
    jobQueue_.push_back(jobParams);
    StartNextJob();
}

void PrintCupsClient::StartNextJob()
{
    if (jobQueue_.empty()) {
        PRINT_HILOGE("no active job in jobQueue_");
        return;
    }
    if (currentJob_ != nullptr) {
        JobParameters *lastJob = jobQueue_.back();
        PrintServiceAbility::GetInstance()->UpdatePrintJobState(lastJob->serviceJobId, PRINT_JOB_QUEUED,
            PRINT_JOB_BLOCKED_UNKNOWN);
        PRINT_HILOGE("a active job is running, job len: %{public}zd", jobQueue_.size());
        return;
    }
    PRINT_HILOGI("start next job from queue");

    currentJob_ = jobQueue_.at(0);
    jobQueue_.erase(jobQueue_.begin());
    if (!currentJob_) {
        PRINT_HILOGE("currentJob_ is nullptr");
        return;
    }
    CallbackFunc callback = [this]() { JobCompleteCallback(); };
    std::thread StartPrintThread(StartCupsJob, currentJob_, callback);
    StartPrintThread.detach();
}

void PrintCupsClient::JobCompleteCallback()
{
    PRINT_HILOGI("Previous job complete, start next job");
    if (!currentJob_) {
        free(currentJob_);
    }
    currentJob_ = nullptr;
    StartNextJob();
}

int PrintCupsClient::FillBorderlessOptions(JobParameters *jobParams, int num_options, cups_option_t **options)
{
    if (jobParams->borderless == 1 && jobParams->mediaType == CUPS_MEDIA_TYPE_PHOTO_GLOSSY) {
        PRINT_HILOGD("borderless job options");
        std::vector<MediaSize> mediaSizes;
        mediaSizes.push_back({ CUPS_MEDIA_4X6, 4000, 6000 });
        mediaSizes.push_back({ CUPS_MEDIA_5X7, 5000, 7000 });
        mediaSizes.push_back({ CUPS_MEDIA_A4, 8268, 11692 });
        int sizeIndex = -1;
        float meidaWidth = 0;
        float mediaHeight = 0;
        for (int i = 0; i < static_cast<int>(mediaSizes.size()); i++) {
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
    std::string nic;
    if (IsIpConflict(jobParams->printerId, nic)) {
        num_options = cupsAddOption("nic", nic.c_str(), num_options, options);
    }
    num_options = FillBorderlessOptions(jobParams, num_options, options);
    return num_options;
}

bool PrintCupsClient::CheckPrinterMakeModel(JobParameters *jobParams)
{
    cups_dest_t *dest = nullptr;
    bool isMakeModelRight = false;
    uint32_t retryCount = 0;
    PRINT_HILOGD("CheckPrinterMakeModel start.");
    if (jobParams == nullptr) {
        PRINT_HILOGE("The jobParams is null");
        return isMakeModelRight;
    }
    while (retryCount < MAX_RETRY_TIMES) {
        dest = cupsGetNamedDest(CUPS_HTTP_DEFAULT, jobParams->printerName.c_str(), NULL);
        if (dest != NULL) {
            const char *makeModel = cupsGetOption("printer-make-and-model", dest->num_options, dest->options);
            PRINT_HILOGD("makeModel=%{private}s", makeModel);
            if (strcmp(makeModel, "Local Raw Printer") != 0) {
                isMakeModelRight = true;
                cupsFreeDests(1, dest);
                break;
            }
            cupsFreeDests(1, dest);
        } else {
            PRINT_HILOGE("The dest is null");
        }
        retryCount++;
        sleep(INDEX_TWO);
    }
    return isMakeModelRight;
}

bool PrintCupsClient::VerifyPrintJob(JobParameters *jobParams, int &num_options, uint32_t &jobId,
    cups_option_t *options, http_t *http)
{
    if (jobParams == nullptr) {
        PRINT_HILOGE("The jobParams is null");
        return false;
    }
    uint32_t retryCount = 0;
    bool isPrinterOnline = false;
    while (retryCount < MAX_RETRY_TIMES) {
        if (CheckPrinterOnline(jobParams->printerUri.c_str(), jobParams->printerId)) {
            isPrinterOnline = true;
            break;
        }
        retryCount++;
        sleep(INDEX_ONE);
    }
    if (!isPrinterOnline) {
        jobParams->serviceAbility->UpdatePrintJobState(jobParams->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_OFFLINE);
        return false;
    }
    if (!CheckPrinterMakeModel(jobParams)) {
        PRINT_HILOGE("VerifyPrintJob printer make model is error");
        jobParams->serviceAbility->UpdatePrintJobState(jobParams->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_DRIVER_EXCEPTION);
        return false;
    }
    num_options = FillJobOptions(jobParams, num_options, &options);
    if ((jobId = static_cast<uint32_t>(cupsCreateJob(http, jobParams->printerName.c_str(), jobParams->jobName.c_str(),
        num_options, options))) == 0) {
        PRINT_HILOGE("Unable to cupsCreateJob: %s", cupsLastErrorString());
        jobParams->serviceAbility->UpdatePrintJobState(jobParams->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_SERVER_CONNECTION_ERROR);
        return false;
    }
    return true;
}
void PrintCupsClient::StartCupsJob(JobParameters *jobParams, CallbackFunc callback)
{
    http_t *http = nullptr;
    int num_options = 0;
    cups_option_t *options = nullptr;
    cups_file_t *fp = nullptr;
    uint32_t jobId;
    http_status_t status;
    char buffer[8192];
    ssize_t bytes = -1;

    if (!VerifyPrintJob(jobParams, num_options, jobId, options, http)) {
        callback();
        return;
    }
    uint32_t num_files = jobParams->fdList.size();
    PRINT_HILOGD("StartCupsJob fill job options, num_files: %{public}d", num_files);
    for (uint32_t i = 0; i < num_files; i++) {
        if ((fp = cupsFileOpenFd(jobParams->fdList[i], "rb")) == NULL) {
            PRINT_HILOGE("Unable to open print file, cancel the job");
            cupsCancelJob2(http, jobParams->printerName.c_str(), jobId, 0);
            jobParams->serviceAbility->UpdatePrintJobState(jobParams->serviceJobId, PRINT_JOB_BLOCKED,
                PRINT_JOB_COMPLETED_FILE_CORRUPT);
            callback();
            return;
        }
        status = cupsStartDocument(http, jobParams->printerName.c_str(), jobId, jobParams->jobName.c_str(),
            jobParams->documentFormat.c_str(), i == (num_files - 1));
        if (status == HTTP_STATUS_CONTINUE)
            bytes = cupsFileRead(fp, buffer, sizeof(buffer));
        while (status == HTTP_STATUS_CONTINUE && bytes > 0) {
            status = cupsWriteRequestData(http, buffer, (size_t)bytes);
            bytes = cupsFileRead(fp, buffer, sizeof(buffer));
        }
        cupsFileClose(fp);
        if (status != HTTP_STATUS_CONTINUE || cupsFinishDocument(http, jobParams->printerName.c_str())
            != IPP_STATUS_OK) {
            PRINT_HILOGE("Unable to queue, error is %s, cancel the job and return...", cupsLastErrorString());
            cupsCancelJob2(http, jobParams->printerUri.c_str(), jobId, 0);
            jobParams->serviceAbility->UpdatePrintJobState(jobParams->serviceJobId, PRINT_JOB_BLOCKED,
                PRINT_JOB_BLOCKED_UNKNOWN);
            callback();
            return;
        }
    }
    jobParams->cupsJobId = jobId;
    PRINT_HILOGD("start job success, jobId: %d", jobId);
    JobMonitorParam *param = new (std::nothrow) JobMonitorParam { jobParams->serviceAbility,
        jobParams->serviceJobId, jobId, jobParams->printerUri, jobParams->printerName, jobParams->printerId };
    if (param == nullptr)
        return;
    MonitorJobState(param, callback);
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
        if (httpGetFd(http) > 0 && CheckPrinterOnline(param->printerUri.c_str(), param->printerId)) {
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
        if (prevousJobStatus != nullptr) {
            prevousJobStatus->job_state = jobStatus->job_state;
            strlcpy(prevousJobStatus->printer_state_reasons, jobStatus->printer_state_reasons,
                sizeof(jobStatus->printer_state_reasons));
        }
        JobStatusCallback(param, jobStatus, false);
    }
    httpClose(http);
    delete param;
    delete jobStatus;
    delete prevousJobStatus;
    PRINT_HILOGI("FINISHED MONITORING JOB %{public}d\n", param->cupsJobId);
    callback();
}

void PrintCupsClient::JobStatusCallback(JobMonitorParam *param, JobStatus *jobStatus, bool isOffline)
{
    PRINT_HILOGD("JobStatusCallback enter, job_state: %{public}d", jobStatus->job_state);
    PRINT_HILOGD("JobStatusCallback enter, printer_state_reasons: %{public}s", jobStatus->printer_state_reasons);
    if (isOffline) {
        cupsCancelJob2(CUPS_HTTP_DEFAULT, param->printerName.c_str(), param->cupsJobId, 0);
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
        std::string printerState(jobStatus->printer_state_reasons);
        if (find(IGNORE_STATE_LIST.begin(), IGNORE_STATE_LIST.end(), printerState) != IGNORE_STATE_LIST.end()) {
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
    if (param == nullptr || param->serviceAbility == nullptr || jobStatus == nullptr) {
        PRINT_HILOGE("ReportBlockedReason parameter is nullptr");
        return;
    }
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
        PRINT_HILOGE("JOB %{public}d: %{public}s (%{public}s), PRINTER: %{public}s\n", param->cupsJobId,
            ippEnumString("job-state", (int)jobStatus->job_state), jobStatus->job_state_reasons,
            jobStatus->printer_state_reasons);
        ippDelete(response);
    }
}

bool PrintCupsClient::CheckPrinterOnline(const char* printerUri, std::string printerId)
{
    http_t *http;
    char scheme[32];
    char userpass[BUFFER_LEN];
    char host[BUFFER_LEN];
    char resource[BUFFER_LEN];
    int port;
    httpSeparateURI(HTTP_URI_CODING_ALL, printerUri, scheme, sizeof(scheme), userpass, sizeof(userpass), host,
                    sizeof(host), &port, resource, sizeof(resource));
    std::string nic;
    if (IsIpConflict(printerId, nic)) {
        http = httpConnect3(host, port, NULL, AF_UNSPEC, HTTP_ENCRYPTION_IF_REQUESTED, 1, LONG_TIME_OUT, NULL,
            nic.c_str());
    } else {
        http = httpConnect2(host, port, NULL, AF_UNSPEC, HTTP_ENCRYPTION_IF_REQUESTED, 1, LONG_TIME_OUT, NULL);
    }
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
    for (int index = 0; index < static_cast<int>(jobQueue_.size()); index++) {
        PRINT_HILOGD("jobQueue_[index]->serviceJobId: %{public}s", jobQueue_[index]->serviceJobId.c_str());
        if (jobQueue_[index]->serviceJobId == serviceJobId) {
            jobIndex = index;
            break;
        }
    }
    PRINT_HILOGI("jobIndex: %{public}d", jobIndex);
    if (jobIndex >= 0) {
        PRINT_HILOGI("job in queue, delete");
        jobQueue_.erase(jobQueue_.begin() + jobIndex);
        PrintServiceAbility::GetInstance()->UpdatePrintJobState(serviceJobId, PRINT_JOB_COMPLETED,
            PRINT_JOB_COMPLETED_CANCELLED);
    } else {
        // 任务正在运行中
        if (currentJob_ && currentJob_->serviceJobId == serviceJobId) {
            PRINT_HILOGI("cancel current job");
            if (cupsCancelJob2(CUPS_HTTP_DEFAULT, currentJob_->printerName.c_str(),
                currentJob_->cupsJobId, 0) != IPP_OK) {
                PRINT_HILOGE("cancel Joob Error %{public}s", cupsLastErrorString());
                PrintServiceAbility::GetInstance()->UpdatePrintJobState(serviceJobId, PRINT_JOB_COMPLETED,
                    PRINT_JOB_COMPLETED_CANCELLED);
                JobCompleteCallback();
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
    params->printerId = jobInfo.GetPrinterId();
    params->printerName = PrintUtil::StandardizePrinterName(optionJson["printerName"]);
    params->printerUri = optionJson["printerUri"];
    params->documentFormat = optionJson["documentFormat"];
    if (optionJson.contains("documentCategory")) {
        params->borderless = optionJson["documentCategory"];
    } else {
        params->borderless = 0;
    }
    if (optionJson.contains("printQuality"))
        params->printQuality = optionJson["printQuality"];
    else
        params->printQuality = CUPS_PRINT_QUALITY_NORMAL;
    if (optionJson.contains("jobName"))
        params->jobName = optionJson["jobName"];
    else
        params->jobName = DEFAULT_JOB_NAME;
    if (optionJson.contains("mediaType"))
        params->mediaType = optionJson["mediaType"];
    else
        params->mediaType = CUPS_MEDIA_TYPE_PLAIN;
    params->serviceAbility = PrintServiceAbility::GetInstance();
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
    PRINT_HILOGD("jobParams->printerId: %{private}s", jobParams->printerId.c_str());
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
bool PrintCupsClient::IsPrinterExist(const char *printerUri, const char *printerName, const char *ppdName)
{
    bool printerExist = false;
    cups_dest_t *dest;
    PRINT_HILOGD("IsPrinterExist enter");
    dest = cupsGetNamedDest(CUPS_HTTP_DEFAULT, printerName, NULL);
    if (dest != NULL) {
        const char *deviceUri = cupsGetOption("device-uri", dest->num_options, dest->options);
        PRINT_HILOGD("deviceUri=%{private}s", deviceUri);
        const char *makeModel = cupsGetOption("printer-make-and-model", dest->num_options, dest->options);
        PRINT_HILOGD("makeModel=%{private}s", makeModel);
        int printerState = cupsGetIntegerOption("printer-state", dest->num_options, dest->options);
        PRINT_HILOGD("printerState=%{private}d", printerState);
        if (printerState == IPP_PRINTER_STOPPED || makeModel == nullptr || strcmp(deviceUri, printerUri) != 0) {
            cupsFreeDests(1, dest);
            PRINT_HILOGI("Printer information needs to be modified");
            return printerExist;
        }
        if (strcmp(ppdName, DEFAULT_PPD_NAME.c_str()) == 0) {
            // 没查到驱动
            printerExist = (strstr(makeModel, DEFAULT_MAKE_MODEL.c_str()) != NULL);
        } else {
            // 查到驱动
            printerExist = !(strstr(makeModel, DEFAULT_MAKE_MODEL.c_str()) != NULL);
            if (!printerExist) {
                // 私有驱动已卸载，需要先删除打印机再添加，不然下发任务找不到驱动
                DeleteCupsPrinter(printerName);
            }
        }
        cupsFreeDests(1, dest);
    }
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
        if (ippContainsString(attrptr, CUPS_SIDES_TWO_SIDED_LANDSCAPE)) {
            printerCaps.SetDuplexMode((uint32_t)DUPLEX_MODE_TWO_SIDED_SHORT_EDGE);
        } else if (ippContainsString(attrptr, CUPS_SIDES_TWO_SIDED_PORTRAIT)) {
            printerCaps.SetDuplexMode((uint32_t)DUPLEX_MODE_TWO_SIDED_LONG_EDGE);
        } else {
            printerCaps.SetDuplexMode((uint32_t)DUPLEX_MODE_ONE_SIDED);
        }
    }
}

nlohmann::json PrintCupsClient::ParseSupportQualities(ipp_t *response)
{
    ipp_attribute_t *attrptr;
    nlohmann::json supportedQualities = nlohmann::json::array();
    if ((attrptr = ippFindAttribute(response, "print-quality-supported", IPP_TAG_ENUM)) != NULL) {
        for (int i = 0; i < ippGetCount(attrptr); i++) {
            int mediaQuality = ippGetInteger(attrptr, i);
            PRINT_HILOGD("print-quality-supported: %{public}d", mediaQuality);
            supportedQualities.push_back(mediaQuality);
        }
    }
    return supportedQualities;
}

nlohmann::json PrintCupsClient::ParseSupportMediaTypes(ipp_t *response)
{
    ipp_attribute_t *attrptr;
    nlohmann::json _supportedMediaTypes = nlohmann::json::array();
    attrptr = ippFindAttribute(response, "media-type-supported", IPP_TAG_KEYWORD);
    if (attrptr == NULL) {
        attrptr = ippFindAttribute(response, "media-type-supported", IPP_TAG_NAME);
    }
    if (attrptr != NULL) {
        PRINT_HILOGD("media-type-supported found; number of values %d", ippGetCount(attrptr));
        for (int i = 0; i < ippGetCount(attrptr); i++) {
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
        if (_supportedMediaTypes.empty()) {
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

bool PrintCupsClient::IsIpConflict(const std::string &printerId, std::string &nic)
{
    if (printerId.find(P2P_PRINTER) == std::string::npos) {
        PRINT_HILOGD("The printer is not p2p: %{private}s", printerId.c_str());
        return false;
    }
    bool isWifiConnected = false;
    Wifi::WifiDevice::GetInstance(OHOS::WIFI_DEVICE_SYS_ABILITY_ID)->IsConnected(isWifiConnected);
    PRINT_HILOGD("isWifiConnected: %{public}d", isWifiConnected);
    Wifi::WifiP2pLinkedInfo p2pLinkedInfo;
    Wifi::WifiP2p::GetInstance(OHOS::WIFI_P2P_SYS_ABILITY_ID)->QueryP2pLinkedInfo(p2pLinkedInfo);
    PRINT_HILOGD("P2pConnectedState: %{public}d", p2pLinkedInfo.GetConnectState());
    if (isWifiConnected && p2pLinkedInfo.GetConnectState() == Wifi::P2pConnectedState::P2P_CONNECTED) {
        Wifi::IpInfo info;
        Wifi::WifiDevice::GetInstance(OHOS::WIFI_DEVICE_SYS_ABILITY_ID)->GetIpInfo(info);
        PRINT_HILOGD("wifi server ip: %{private}s", GetIpAddress(info.serverIp).c_str());
        PRINT_HILOGD("p2p go ip: %{private}s", p2pLinkedInfo.GetGroupOwnerAddress().c_str());
        if (GetIpAddress(info.serverIp) == p2pLinkedInfo.GetGroupOwnerAddress()) {
            Wifi::WifiP2pGroupInfo group;
            Wifi::WifiP2p::GetInstance(OHOS::WIFI_P2P_SYS_ABILITY_ID)->GetCurrentGroup(group);
            nic = group.GetInterface();
            PRINT_HILOGI("The P2P ip conflicts with the wlan ip, p2p nic: %{public}s", nic.c_str());
            return true;
        }
    }
    return false;
}

std::string PrintCupsClient::GetIpAddress(unsigned int number)
{
    unsigned int ip3 = (number << IP_RIGHT_SHIFT_0) >> IP_RIGHT_SHIFT_24;
    unsigned int ip2 = (number << IP_RIGHT_SHIFT_8) >> IP_RIGHT_SHIFT_24;
    unsigned int ip1 = (number << IP_RIGHT_SHIFT_16) >> IP_RIGHT_SHIFT_24;
    unsigned int ip0 = (number << IP_RIGHT_SHIFT_24) >> IP_RIGHT_SHIFT_24;
    return std::to_string(ip3) + "." + std::to_string(ip2) + "." + std::to_string(ip1) + "." + std::to_string(ip0);
}
}