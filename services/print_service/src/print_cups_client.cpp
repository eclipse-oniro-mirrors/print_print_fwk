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

#include <mutex>
#include <string>
#include <cups/cups-private.h>
#include <cups/adminutil.h>
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
#include "print_service_converter.h"
#include "print_cups_attribute.h"

namespace OHOS::Print {
using namespace std;
using json = nlohmann::json;

const uint32_t THOUSAND_INCH = 1000;
const uint32_t CUPS_SEVER_PORT = 1631;
const uint32_t TIME_OUT = 2000;
const uint32_t CONVERSION_UNIT = 2540;
const uint32_t LONG_TIME_OUT = 3000;
const uint32_t LONG_LONG_TIME_OUT = 30000;
const uint32_t INTERVAL_FOR_FIRST_QUERY = 1;
const uint32_t INTERVAL_FOR_QUERY = 2;
const uint32_t OFFLINE_RETRY_TIMES = 5;
const uint32_t RESOURCE_COUNT = 2;
const uint32_t DIR_COUNT = 3;
const uint32_t INDEX_ZERO = 0;
const uint32_t INDEX_ONE = 1;
const uint32_t INDEX_TWO = 2;
const uint32_t INDEX_THREE = 3;
const uint32_t MAX_RETRY_TIMES = 5;
const uint32_t BUFFER_LEN = 256;
const uint32_t DIR_MODE = 0771;
const uint32_t IP_RIGHT_SHIFT_0 = 0;
const uint32_t IP_RIGHT_SHIFT_8 = 8;
const uint32_t IP_RIGHT_SHIFT_16 = 16;
const uint32_t IP_RIGHT_SHIFT_24 = 24;
const uint32_t NUMBER_FOR_SPLICING_SUBSTATE = 100;
const uint32_t SERIAL_LENGTH = 6;

static bool g_isFirstQueryState = false;

static const std::string CUPS_ROOT_DIR = "/data/service/el1/public/print_service/cups";
static const std::string CUPS_RUN_DIR = "/data/service/el1/public/print_service/cups/run";
static const std::string DEFAULT_PPD_NAME = "everywhere";
static const std::string DEFAULT_MAKE_MODEL = "IPP Everywhere";
static const std::string REMOTE_PRINTER_MAKE_MODEL = "Remote Printer";
static const std::string DEFAULT_USER = "default";
static const std::string PRINTER_STATE_WAITING_COMPLETE = "cups-waiting-for-job-completed";
static const std::string PRINTER_STATE_WIFI_NOT_CONFIGURED = "wifi-not-configured-report";
static const std::string PRINTER_STATE_MEDIA_LOW_WARNING = "media-low-warning";
static const std::string PRINTER_STATE_TONER_LOW_WARNING = "toner-low-warning";
static const std::string PRINTER_STATE_TONER_LOW_REPORT = "toner-low-report";
static const std::string PRINTER_STATE_IGNORE_HP = "wifi-not-configured-report,cups-waiting-for-job-completed";
static const std::string PRINTER_STATE_IGNORE_BUSY =
    "cups-ipp-conformance-failure-report,cups-ipp-missing-job-history,cups-waiting-for-job-completed";
static const std::string PRINTER_STATE_IGNORE_BUSY_COMPLETED =
    "cups-ipp-conformance-failure-report,cups-ipp-missing-job-history";
static const std::string PRINTER_STATE_IGNORE_BUSY_MISSING_JOB_STATE =
    "cups-ipp-conformance-failure-report,cups-ipp-missing-job-state";
static const std::string PRINTER_STATE_IGNORE_BUSY_MISSING_JOB_STATE_COMPLETED =
    "cups-ipp-conformance-failure-report,cups-ipp-missing-job-state,cups-waiting-for-job-completed";
static const std::string PRINTER_STATE_IGNORE_TONER_LOW_JOB_STATE_COMPLETED =
    "toner-low-warning,cups-waiting-for-job-completed";
static const std::string PRINTER_STATE_IGNORE_MEDIA_LOW_JOB_STATE_COMPLETED =
    "media-low-warning,cups-waiting-for-job-completed";
static const std::string PRINTER_STATE_IGNORE_BUSY_WAITING_COMPLETE_OTHER_REPORT =
    "cups-waiting-for-job-completed,other-report";
static const std::string PRINTER_STATE_IGNORE_BUSY_OTHER_REPORT = "other-report";
static const std::string PRINTER_STATE_MARKER_LOW_WARNING = "marker-supply-low-warning";
static const std::string PRINTER_STATE_MEDIA_EMPTY_WARNING = "media-empty-warning";
static const std::string PRINTER_STATE_NONE = "none";
static const std::string PRINTER_STATE_EMPTY = "";
static const std::string PRINTER_STATE_ERROR = "error";
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
static const std::string PRINTER_STATE_OTHER = "other";
static const std::string PRINTER_STATE_OFFLINE = "offline";
static const std::string DEFAULT_JOB_NAME = "test";
static const std::string CUPSD_CONTROL_PARAM = "print.cupsd.ready";
static const std::string P2P_PRINTER = "p2p";
static const std::string USB_PRINTER = "usb";
static const std::string PRINTER_ID_USB_PREFIX = "USB";
static const std::string PRINTER_MAKE_UNKNOWN = "Unknown";
static const std::string SPOOLER_BUNDLE_NAME = "com.ohos.spooler";
static const std::string VENDOR_MANAGER_PREFIX = "fwk.";
static const std::vector<std::string> IGNORE_STATE_LIST = {PRINTER_STATE_WAITING_COMPLETE,
    PRINTER_STATE_NONE,
    PRINTER_STATE_EMPTY,
    PRINTER_STATE_WIFI_NOT_CONFIGURED,
    PRINTER_STATE_MEDIA_LOW_WARNING,
    PRINTER_STATE_TONER_LOW_WARNING,
    PRINTER_STATE_TONER_LOW_REPORT,
    PRINTER_STATE_IGNORE_HP,
    PRINTER_STATE_IGNORE_BUSY,
    PRINTER_STATE_IGNORE_BUSY_COMPLETED,
    PRINTER_STATE_IGNORE_BUSY_MISSING_JOB_STATE,
    PRINTER_STATE_IGNORE_BUSY_MISSING_JOB_STATE_COMPLETED,
    PRINTER_STATE_IGNORE_TONER_LOW_JOB_STATE_COMPLETED,
    PRINTER_STATE_IGNORE_MEDIA_LOW_JOB_STATE_COMPLETED,
    PRINTER_STATE_IGNORE_BUSY_WAITING_COMPLETE_OTHER_REPORT,
    PRINTER_STATE_IGNORE_BUSY_OTHER_REPORT};
std::mutex jobMutex;

static std::vector<PrinterInfo> usbPrinters;
static void DeviceCb(const char *deviceClass, const char *deviceId, const char *deviceInfo,
    const char *deviceMakeAndModel, const char *deviceUri, const char *deviceLocation, void *userData)
{
    PRINT_HILOGD("Device: uri = %{private}s\n", deviceUri);
    PRINT_HILOGD("class = %{private}s\n", deviceClass);
    PRINT_HILOGD("make-and-model = %{private}s\n", deviceMakeAndModel);
    PRINT_HILOGD("location = %{private}s\n", deviceLocation);
    std::string printerUri(deviceUri);
    std::string printerMake(deviceMakeAndModel);
    if (printerUri.length() > SERIAL_LENGTH && printerUri.substr(INDEX_ZERO, INDEX_THREE) == USB_PRINTER &&
        printerMake != PRINTER_MAKE_UNKNOWN) {
        std::string printerName(deviceInfo);
        std::string serial = printerUri.substr(printerUri.length() - SERIAL_LENGTH);
        PrinterInfo info;
        info.SetPrinterId(PRINTER_ID_USB_PREFIX + "-" + printerName + "-" + serial);
        info.SetPrinterName(PRINTER_ID_USB_PREFIX + "-" + printerName + "-" + serial);
        info.SetPrinterMake(printerMake);
        info.SetUri(printerUri);
        info.SetPrinterState(PRINTER_ADDED);
        PrinterCapability printerCapability;
        info.SetCapability(printerCapability);
        info.SetDescription("usb");
        nlohmann::json infoOps;
        infoOps["printerUri"] = printerUri;
        infoOps["printerMake"] = printerMake;
        info.SetOption(infoOps.dump());
        usbPrinters.emplace_back(info);
    }
}

PrintCupsClient::PrintCupsClient()
{
    printAbility_ = new (std::nothrow) PrintCupsWrapper();
}

PrintCupsClient::~PrintCupsClient()
{
    if (printAbility_ != nullptr) {
        delete printAbility_;
        printAbility_ = nullptr;
    }
}

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
        GetParameter(CUPSD_CONTROL_PARAM.c_str(), "", value, bufferSize - 1);
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
        PRINT_HILOGE("The realPidFile is null, errno:%{public}s", std::to_string(errno).c_str());
        return E_PRINT_SERVER_FAILURE;
    }
    int fd;
    if ((fd = open(realPidFile, O_RDONLY)) < 0) {
        PRINT_HILOGE("Open pidFile error!");
        return E_PRINT_SERVER_FAILURE;
    }
    lseek(fd, 0, SEEK_SET);
    char buf[BUFFER_LEN] = {0};
    if ((read(fd, buf, sb.st_size)) < 0) {
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
        if (stat(filePath.c_str(), &fileStat) != 0) {
            continue;
        }
        if (S_ISDIR(fileStat.st_mode)) {
            ChangeFilterPermission(filePath.c_str(), mode);
        } else if (S_ISREG(fileStat.st_mode)) {
            if (chmod(filePath.c_str(), mode) == -1) {
                PRINT_HILOGE("Failed to change mode");
            }
        }
    }
    closedir(dir);
}

void PrintCupsClient::SymlinkFile(std::string srcFilePath, std::string destFilePath)
{
    int ret = symlink(srcFilePath.c_str(), destFilePath.c_str());
    if (!ret) {
        PRINT_HILOGD("symlink success, ret = %{public}d, errno = %{public}d", ret, errno);
    } else {
        PRINT_HILOGE("symlink failed, ret = %{public}d, errno = %{public}d", ret, errno);
    }
}

void PrintCupsClient::SymlinkDirectory(const char *srcDir, const char *destDir)
{
    DIR *dir = opendir(srcDir);
    if (dir == nullptr) {
        PRINT_HILOGE("Failed to open Dir: %{private}s", srcDir);
        return;
    }
    if (access(destDir, F_OK)) {
        mkdir(destDir, DIR_MODE);
    }
    struct dirent *file;
    struct stat filestat = {};
    struct stat destFilestat = {};
    while ((file = readdir(dir)) != nullptr) {
        if (!strcmp(file->d_name, ".") || !strcmp(file->d_name, "..")) {
            continue;
        }
        std::string srcFilePath = std::string(srcDir) + "/" + std::string(file->d_name);
        std::string destFilePath = std::string(destDir) + "/" + std::string(file->d_name);

        stat(srcFilePath.c_str(), &filestat);
        if (S_ISDIR(filestat.st_mode)) {
            SymlinkDirectory(srcFilePath.c_str(), destFilePath.c_str());
        } else if (lstat(destFilePath.c_str(), &destFilestat) == 0) {
            PRINT_HILOGD("symlink lstat %{public}s err: %{public}s", destFilePath.c_str(), strerror(errno));

            if (S_ISLNK(destFilestat.st_mode)) {
                PRINT_HILOGW("symlink already exists, continue.");
                continue;
            }
            if (std::remove(destFilePath.c_str()) != 0) {
                PRINT_HILOGE("error deleting file %{public}s err: %{public}s",
                    destFilePath.c_str(), strerror(errno));
                continue;
            } else {
                PRINT_HILOGW("file successfully deleted");
            }
            SymlinkFile(srcFilePath, destFilePath);
        } else {
            PRINT_HILOGE("symlink lstat %{public}s err: %{public}s", destFilePath.c_str(), strerror(errno));
            SymlinkFile(srcFilePath, destFilePath);
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
            char destSrc[PATH_MAX] = {};
            if (realpath(srcFilePath.c_str(), realSrc) == nullptr ||
                realpath(destDir, destSrc) == nullptr) {
                PRINT_HILOGE("The realSrc is null, errno:%{public}s", std::to_string(errno).c_str());
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
        if (!i) {
            SymlinkDirectory(array[i][INDEX_ZERO].c_str(), array[i][INDEX_ONE].c_str());
        } else {
            if (access(array[i][INDEX_TWO].c_str(), F_OK) != -1) {
                PRINT_HILOGD("The resource has been copied.");
                continue;
            }
            CopyDirectory(array[i][INDEX_ZERO].c_str(), array[i][INDEX_ONE].c_str());
        }
    }
    std::string dstDir = CUPS_ROOT_DIR + "/serverbin/filter";
    SymlinkDirectory("/system/bin/uni_print_driver/filter/", dstDir.c_str());
    dstDir = CUPS_ROOT_DIR + "/serverbin/backend";
    SymlinkDirectory("/system/bin/uni_print_driver/backend/", dstDir.c_str());
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
    GetParameter(CUPSD_CONTROL_PARAM.c_str(), "", value, bufferSize - 1);
    PRINT_HILOGD("print.cupsd.ready value: %{public}s.", value);
}

void PrintCupsClient::QueryPPDInformation(const char *makeModel, std::vector<std::string> &ppds)
{
    ipp_t *request;
    ipp_t *response;
    const char *ppd_make_model;
    const char *ppd_name;

    if (printAbility_ == nullptr) {
        PRINT_HILOGW("printAbility_ is null");
        return;
    }
    request = ippNewRequest(CUPS_GET_PPDS);
    if (request == nullptr) {
        return;
    }
    if (makeModel) {
        ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_TEXT, "ppd-make-and-model", NULL, makeModel);
    }

    PRINT_HILOGD("CUPS_GET_PPDS start.");
    response = printAbility_->DoRequest(CUPS_HTTP_DEFAULT, request, "/");
    if (response == NULL) {
        PRINT_HILOGE("GetAvaiablePPDS failed: %{public}s", cupsLastErrorString());
        return;
    }
    if (response->request.status.status_code > IPP_OK_CONFLICT) {
        PRINT_HILOGE("GetAvaiablePPDS failed: %{public}s", cupsLastErrorString());
        printAbility_->FreeRequest(response);
        return;
    }
    ParsePPDInfo(response, ppd_make_model, ppd_name, ppds);
    printAbility_->FreeRequest(response);
}

void PrintCupsClient::ParsePPDInfo(ipp_t *response, const char *ppd_make_model, const char *ppd_name,
    std::vector<std::string> &ppds)
{
    if (response == nullptr) {
        return;
    }
    for (ipp_attribute_t *attr = response->attrs; attr != NULL; attr = attr->next) {
        while (attr != NULL && attr->group_tag != IPP_TAG_PRINTER) {
            attr = attr->next;
        }
        if (attr == NULL) {
            break;
        }
        ppd_make_model = NULL;
        ppd_name = NULL;

        while (attr != NULL && attr->group_tag == IPP_TAG_PRINTER) {
            if (!strcmp(attr->name, "ppd-make-and-model") && attr->value_tag == IPP_TAG_TEXT) {
                ppd_make_model = attr->values[0].string.text;
            } else if (!strcmp(attr->name, "ppd-name") && attr->value_tag == IPP_TAG_NAME) {
                ppd_name = attr->values[0].string.text;
            }
            attr = attr->next;
        }
        if (ppd_make_model != NULL && ppd_name != NULL) {
            ppds.push_back(ppd_name);
            PRINT_HILOGI("ppd: name = %{private}s, make-and-model = %{private}s", ppd_name, ppd_make_model);
        }
        if (attr == NULL) {
            break;
        }
    }
}

int32_t PrintCupsClient::AddPrinterToCups(const std::string &printerUri, const std::string &printerName,
    const std::string &printerMake)
{
    PRINT_HILOGD("PrintCupsClient AddPrinterToCups start, printerMake: %{public}s", printerMake.c_str());
    ipp_t *request;
    char uri[HTTP_MAX_URI] = {0};
    std::vector<string> ppds;
    std::string ppd = DEFAULT_PPD_NAME;
    std::string standardName = PrintUtil::StandardizePrinterName(printerName);

    ippSetPort(CUPS_SEVER_PORT);
    QueryPPDInformation(printerMake.c_str(), ppds);
    if (!ppds.empty()) {
        ppd = ppds[0];
        std::string serverBin = CUPS_ROOT_DIR + "/serverbin";
        mode_t permissions = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH;
        ChangeFilterPermission(serverBin, permissions);
    }
    PRINT_HILOGI("ppd driver: %{public}s", ppd.c_str());
    if (IsPrinterExist(printerUri.c_str(), standardName.c_str(), ppd.c_str())) {
        PRINT_HILOGI("add success, printer has added");
        return E_PRINT_NONE;
    }
    if (printAbility_ == nullptr) {
        PRINT_HILOGW("printAbility_ is null");
        return E_PRINT_SERVER_FAILURE;
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
    PRINT_HILOGD("IPP_OP_CUPS_ADD_MODIFY_PRINTER cupsDoRequest");
    ippDelete(printAbility_->DoRequest(NULL, request, "/admin/"));
    if (cupsLastError() > IPP_STATUS_OK_EVENTS_COMPLETE) {
        PRINT_HILOGE("add error: %s", cupsLastErrorString());
        return E_PRINT_SERVER_FAILURE;
    }
    PRINT_HILOGI("add success");
    return E_PRINT_NONE;
}

int32_t PrintCupsClient::AddPrinterToCupsWithPpd(const std::string &printerUri, const std::string &printerName,
    const std::string &ppdName, const std::string &ppdData)
{
    PRINT_HILOGD("AddPrinterToCupsWithPpd, ppdName: %{public}s", ppdName.c_str());
    ipp_t *request = nullptr;
    char uri[HTTP_MAX_URI] = {0};
    std::vector<string> ppds;
    std::string standardName = PrintUtil::StandardizePrinterName(printerName);
    if (IsPrinterExist(printerUri.c_str(), standardName.c_str(), ppdName.c_str())) {
        PRINT_HILOGI("add success, printer has added");
        return E_PRINT_NONE;
    }
    ippSetPort(CUPS_SEVER_PORT);
    _cupsSetError(IPP_STATUS_OK, NULL, 0);
    request = ippNewRequest(IPP_OP_CUPS_ADD_MODIFY_PRINTER);
    if (request == nullptr) {
        PRINT_HILOGW("request is null");
        return E_PRINT_SERVER_FAILURE;
    }
    httpAssembleURIf(HTTP_URI_CODING_ALL, uri, sizeof(uri), "ipp", NULL, "localhost", 0, "/printers/%s",
        standardName.c_str());
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri", NULL, uri);
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name", NULL, cupsUser());
    ippAddString(request, IPP_TAG_PRINTER, IPP_TAG_TEXT, "printer-info", NULL, standardName.c_str());
    ippAddString(request, IPP_TAG_PRINTER, IPP_TAG_URI, "device-uri", NULL, printerUri.c_str());
    ippAddInteger(request, IPP_TAG_PRINTER, IPP_TAG_ENUM, "printer-state", IPP_PRINTER_IDLE);
    ippAddBoolean(request, IPP_TAG_PRINTER, "printer-is-accepting-jobs", 1);
    ippAddBoolean(request, IPP_TAG_PRINTER, "printer-is-shared", 1);
    PRINT_HILOGD("IPP_OP_CUPS_ADD_MODIFY_PRINTER cupsDoRequest");
    http_status_t status = cupsSendRequest(CUPS_HTTP_DEFAULT, request, "/admin/",
        ippLength(request) + ppdData.length());
    if (status == HTTP_STATUS_CONTINUE && request->state == IPP_STATE_DATA) {
        status = cupsWriteRequestData(CUPS_HTTP_DEFAULT, ppdData.c_str(), ppdData.length());
    } else {
        ippDelete(request);
        request = nullptr;
        PRINT_HILOGW("ppd not send, status = %{public}d", static_cast<int>(status));
        return E_PRINT_SERVER_FAILURE;
    }
    ippDelete(request);
    request = nullptr;
    if (status != HTTP_STATUS_OK && status != HTTP_STATUS_CONTINUE) {
        PRINT_HILOGW("add error, status = %{public}d", static_cast<int>(status));
        return E_PRINT_SERVER_FAILURE;
    }
    if (cupsLastError() > IPP_STATUS_OK_CONFLICTING) {
        PRINT_HILOGE("add error: %s", cupsLastErrorString());
        return E_PRINT_SERVER_FAILURE;
    }
    PRINT_HILOGI("add success");
    return E_PRINT_NONE;
}

int32_t PrintCupsClient::DeleteCupsPrinter(const char *printerName)
{
    ipp_t *request;
    char uri[HTTP_MAX_URI] = {0};

    PRINT_HILOGD("PrintCupsClient DeleteCupsPrinter start: %{private}s", printerName);
    if (printAbility_ == nullptr) {
        PRINT_HILOGW("printAbility_ is null");
        return E_PRINT_SERVER_FAILURE;
    }
    request = ippNewRequest(IPP_OP_CUPS_DELETE_PRINTER);
    httpAssembleURIf(HTTP_URI_CODING_ALL, uri, sizeof(uri), "ipp", NULL, "localhost", 0, "/printers/%s", printerName);
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri", NULL, uri);
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name", NULL, cupsUser());
    ippDelete(printAbility_->DoRequest(NULL, request, "/admin/"));
    if (cupsLastError() > IPP_STATUS_OK_EVENTS_COMPLETE) {
        PRINT_HILOGW("DeleteCupsPrinter error: %{public}s", cupsLastErrorString());
    }
    return E_PRINT_NONE;
}

ipp_t *PrintCupsClient::QueryPrinterAttributesByUri(const std::string &printerUri, const std::string &nic, int num,
    const char * const *pattrs)
{
    ipp_t *request = nullptr; /* IPP Request */
    ipp_t *response = nullptr; /* IPP Request */
    http_t *http = nullptr;
    char scheme[HTTP_MAX_URI] = {0}; /* Method portion of URI */
    char username[HTTP_MAX_URI] = {0}; /* Username portion of URI */
    char host[HTTP_MAX_URI] = {0}; /* Host portion of URI */
    char resource[HTTP_MAX_URI] = {0}; /* Resource portion of URI */
    int port = 0; /* Port portion of URI */
    PRINT_HILOGD("QueryPrinterAttributesByUri enter");
    if (printAbility_ == nullptr) {
        PRINT_HILOGW("printAbility_ is null");
        return nullptr;
    }
    httpSeparateURI(HTTP_URI_CODING_ALL, printerUri.c_str(), scheme, sizeof(scheme), username, sizeof(username), host,
        sizeof(host), &port, resource, sizeof(resource));
    if (nic.empty()) {
        http = httpConnect2(host, port, NULL, AF_UNSPEC, HTTP_ENCRYPTION_IF_REQUESTED, 1, TIME_OUT, NULL);
    } else {
        http = httpConnect3(host, port, NULL, AF_UNSPEC, HTTP_ENCRYPTION_IF_REQUESTED, 1, TIME_OUT, NULL, nic.c_str());
    }
    if (http == nullptr) {
        PRINT_HILOGW("connect printer failed");
        return nullptr;
    }
    _cupsSetError(IPP_STATUS_OK, NULL, 0);
    request = ippNewRequest(IPP_OP_GET_PRINTER_ATTRIBUTES);
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri", NULL, printerUri.c_str());
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name", NULL, cupsUser());
    ippAddStrings(request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD, "requested-attributes", num, NULL, pattrs);
    response = printAbility_->DoRequest(http, request, "/");
    httpClose(http);
    http = nullptr;
    if (response == nullptr) {
        PRINT_HILOGW("response is null");
        return nullptr;
    }
    if (cupsLastError() > IPP_STATUS_OK_CONFLICTING) {
        PRINT_HILOGE("get printer attributes error: %{public}s", cupsLastErrorString());
        ippDelete(response);
        response = nullptr;
        return nullptr;
    }
    return response;
}

int32_t PrintCupsClient::QueryPrinterCapabilityByUri(const std::string &printerUri, const std::string &printerId,
    PrinterCapability &printerCaps)
{
    PRINT_HILOGD("PrintCupsClient QueryPrinterCapabilityByUri start.");
    static const char * const pattrs[] = {
        "all"
    };
    std::string nic;
    IsIpConflict(printerId, nic);
    ipp_t *response = QueryPrinterAttributesByUri(printerUri, nic, sizeof(pattrs) / sizeof(pattrs[0]), pattrs);
    if (response == nullptr) {
        PRINT_HILOGW("get attributes fail");
        return E_PRINT_SERVER_FAILURE;
    }
    PRINT_HILOGD("get attributes success");
    ParsePrinterAttributes(response, printerCaps);
    ippDelete(response);
    response = nullptr;
    return E_PRINT_NONE;
}

int32_t PrintCupsClient::QueryPrinterStatusByUri(const std::string &printerUri, PrinterStatus &status)
{
    PRINT_HILOGD("PrintCupsClient QueryPrinterStatusByUri start.");
    static const char * const pattrs[] = {
        "printer-state"
    };
    ipp_t *response = QueryPrinterAttributesByUri(printerUri, "", sizeof(pattrs) / sizeof(pattrs[0]), pattrs);
    if (response == nullptr) {
        PRINT_HILOGW("get attributes fail");
        return E_PRINT_SERVER_FAILURE;
    }
    PRINT_HILOGD("get attributes success");
    bool result = ParsePrinterStatusAttributes(response, status);
    ippDelete(response);
    response = nullptr;
    if (!result) {
        PRINT_HILOGW("parse state failed");
        return E_PRINT_SERVER_FAILURE;
    }
    return E_PRINT_NONE;
}

int32_t PrintCupsClient::QueryPrinterCapabilityFromPPD(const std::string &printerName, PrinterCapability &printerCaps)
{
    std::string standardName = PrintUtil::StandardizePrinterName(printerName);
    PRINT_HILOGI("QueryPrinterCapabilityFromPPD printerName: %{public}s", standardName.c_str());

    cups_dest_t *dest = nullptr;
    if (printAbility_ == nullptr) {
        PRINT_HILOGW("printAbility_ is null");
        return E_PRINT_SERVER_FAILURE;
    }
    dest = printAbility_->GetNamedDest(CUPS_HTTP_DEFAULT, standardName.c_str(), NULL);
    if (dest == nullptr) {
        PRINT_HILOGE("the printer is not found");
        return E_PRINT_SERVER_FAILURE;
    }
    cups_dinfo_t *dinfo = printAbility_->CopyDestInfo(CUPS_HTTP_DEFAULT, dest);
    if (dinfo == nullptr) {
        PRINT_HILOGE("cupsCopyDestInfo failed");
        printAbility_->FreeDests(1, dest);
        return E_PRINT_SERVER_FAILURE;
    }

    ParsePrinterAttributes(dinfo->attrs, printerCaps);
    printerCaps.Dump();

    printAbility_->FreeDestInfo(dinfo);
    printAbility_->FreeDests(1, dest);
    PRINT_HILOGI("QueryPrinterCapabilityFromPPD out\n");
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

JobParameters *PrintCupsClient::GetNextJob()
{
    if (jobQueue_.empty()) {
        PRINT_HILOGE("no active job in jobQueue_");
        return nullptr;
    }
    if (currentJob_ != nullptr) {
        JobParameters *lastJob = jobQueue_.back();
        if (lastJob != nullptr) {
            PrintServiceAbility::GetInstance()->UpdatePrintJobState(lastJob->serviceJobId, PRINT_JOB_QUEUED,
                PRINT_JOB_BLOCKED_UNKNOWN);
        }
        PRINT_HILOGE("a active job is running, job len: %{public}zd", jobQueue_.size());
        return nullptr;
    }
    PRINT_HILOGI("start next job from queue");

    std::lock_guard<std::mutex> lock(jobMutex);
    currentJob_ = jobQueue_.at(0);
    jobQueue_.erase(jobQueue_.begin());
    return currentJob_;
}

void PrintCupsClient::StartNextJob()
{
    auto nextJob = GetNextJob();
    if (nextJob == nullptr) {
        PRINT_HILOGW("nextJob is nullptr");
        return;
    }
    if (toCups_) {
        auto self = shared_from_this();
        CallbackFunc callback = [self]() { self->JobCompleteCallback(); };
        std::thread StartPrintThread([self, callback] {self->StartCupsJob(self->currentJob_, callback);});
        StartPrintThread.detach();
    }
}

void PrintCupsClient::JobCompleteCallback()
{
    PRINT_HILOGI("Previous job complete, start next job");
    if (!currentJob_) {
        delete currentJob_;
    }
    currentJob_ = nullptr;
    StartNextJob();
}

int PrintCupsClient::FillBorderlessOptions(JobParameters *jobParams, int num_options, cups_option_t **options)
{
    if (jobParams == nullptr) {
        PRINT_HILOGE("FillBorderlessOptions Params is nullptr");
        return num_options;
    }
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
        PRINT_HILOGD("meidaWidth: %f, mediaHeight: %f", meidaWidth, mediaHeight);
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
    if (jobParams == nullptr) {
        PRINT_HILOGE("FillJobOptions Params is nullptr");
        return num_options;
    }
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

int32_t PrintCupsClient::QueryAddedPrinterList(std::vector<std::string> &printerNameList)
{
    if (!IsCupsServerAlive()) {
        PRINT_HILOGI("The cupsd process is not started, start it now.");
        int32_t ret = StartCupsdService();
        if (ret != 0) {
            return E_PRINT_SERVER_FAILURE;
        }
    }
    printerNameList.clear();
    cups_dest_t *dests = NULL;
    int num = cupsGetDests(&dests);
    PRINT_HILOGI("QueryAddedPrinterList, num: %{public}d.", num);
    for (int i = 0; i < num; i++) {
        PRINT_HILOGD("QueryAddedPrinterList, printerIsDefault: %{public}d.", dests[i].is_default);
        printerNameList.emplace_back(dests[i].name);
    }
    cupsFreeDests(num, dests);
    return E_PRINT_NONE;
}

int32_t PrintCupsClient::SetDefaultPrinter(const std::string &printerName)
{
    http_t *http;
    if (printAbility_ == nullptr) {
        PRINT_HILOGW("printAbility_ is null");
        return E_PRINT_SERVER_FAILURE;
    }
    ippSetPort(CUPS_SEVER_PORT);
    http = httpConnect2(cupsServer(), ippPort(), NULL, AF_UNSPEC, HTTP_ENCRYPTION_IF_REQUESTED, 1, LONG_TIME_OUT, NULL);
    if (http == nullptr) {
        PRINT_HILOGE("cups server is not alive");
        return E_PRINT_SERVER_FAILURE;
    }
    ipp_t *request;         /* IPP Request */
    char uri[HTTP_MAX_URI] = {0}; /* URI for printer/class */
    httpAssembleURIf(HTTP_URI_CODING_ALL, uri, sizeof(uri), "ipp", NULL,
        "localhost", 0, "/printers/%s", printerName.c_str());
    request = ippNewRequest(IPP_OP_CUPS_SET_DEFAULT);
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI,
        "printer-uri", NULL, uri);
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name",
        NULL, cupsUser());
    ippDelete(printAbility_->DoRequest(http, request, "/admin/"));
    httpClose(http);

    const char* default_printer = cupsGetDefault();
    PRINT_HILOGI("default_printer=%{public}s", default_printer);
    if (cupsLastError() > IPP_STATUS_OK_CONFLICTING) {
        PRINT_HILOGI("[ERROR] occur a error when do cups-request{setDefault}. error is:> ");
        return E_PRINT_SERVER_FAILURE;
    }
    return E_PRINT_NONE;
}

ppd_file_t* PrintCupsClient::GetPPDFile(const std::string &printerName)
{
    if (!IsCupsServerAlive()) {
        PRINT_HILOGI("The cupsd process is not started, start it now.");
        int32_t ret = StartCupsdService();
        if (ret != 0) {
            return nullptr;
        }
    }
    if (printerName.find("../") == 0) {
        PRINT_HILOGE("GetPPDFile printerName is out of fileDir");
        return nullptr;
    }
    ppd_file_t *ppd = 0;
    std::string fileDir = "/data/service/el1/public/print_service/cups/ppd/";
    std::string pName = printerName;
    std::string filePath = fileDir + pName + ".ppd";
    PRINT_HILOGI("GetPPDFile started filePath %{public}s", filePath.c_str());
    char realPath[PATH_MAX] = {};
    if (realpath(filePath.c_str(), realPath) == nullptr) {
        PRINT_HILOGE("The realPidFile is null, errno:%{public}s", std::to_string(errno).c_str());
        return nullptr;
    }
    int fd;
    if ((fd = open(realPath, O_RDWR)) < 0) {
        PRINT_HILOGE("Open ppdFile error!");
        return nullptr;
    }
    PRINT_HILOGI("GetPPDFile %{public}d", fd);
    ppd = ppdOpenFd(fd);
    close(fd);
    if (ppd == nullptr) {
        PRINT_HILOGE("ppdfile open is nullptr");
    } else {
        PRINT_HILOGI("GetPPDFile groups:%{public}d,pagesize_num:%{public}d", ppd->num_groups, ppd->num_sizes);
    }
    return ppd;
}

int32_t PrintCupsClient::QueryPrinterAttrList(const std::string &printerName, const std::vector<std::string> &keyList,
    std::vector<std::string> &valueList)
{
    if (printAbility_ == nullptr) {
        PRINT_HILOGW("printAbility_ is null");
        return E_PRINT_SERVER_FAILURE;
    }
    cups_dest_t *dest = nullptr;
    dest = printAbility_->GetNamedDest(CUPS_HTTP_DEFAULT, printerName.c_str(), NULL);
    if (dest == nullptr) {
        PRINT_HILOGW("the printer is not found");
        return E_PRINT_SERVER_FAILURE;
    }
    for (auto &key : keyList) {
        const char *ret = cupsGetOption(key.c_str(), dest->num_options, dest->options);
        if (ret != NULL) {
            std::string valueStr = ret;
            std::string value = key + "&" + valueStr;
            valueList.emplace_back(value);
        }
    }
    printAbility_->FreeDests(1, dest);
    PRINT_HILOGI("QueryPrinterAttr end");
    return E_PRINT_NONE;
}

int32_t PrintCupsClient::QueryPrinterInfoByPrinterId(const std::string& printerId, PrinterInfo &info)
{
    PRINT_HILOGD("the printerInfo printerName %{public}s", info.GetPrinterName().c_str());
    if (printAbility_ == nullptr) {
        PRINT_HILOGW("printAbility_ is null");
        return E_PRINT_SERVER_FAILURE;
    }
    cups_dest_t *dest = nullptr;
    dest = printAbility_->GetNamedDest(CUPS_HTTP_DEFAULT, info.GetPrinterName().c_str(), NULL);
    if (dest == nullptr) {
        PRINT_HILOGW("the printer is not found");
        return E_PRINT_SERVER_FAILURE;
    }
    printAbility_->FreeDests(1, dest);
    if (info.HasOption()) {
        PRINT_HILOGI("the printerInfo option");
        PrinterCapability printerCaps;
        std::string infoOpt = info.GetOption();
        PRINT_HILOGD("the printerInfo option %{public}s", infoOpt.c_str());
        if (!json::accept(infoOpt)) {
            PRINT_HILOGE("infoOpt can not parse to json object");
            return E_PRINT_INVALID_PARAMETER;
        }
        nlohmann::json infoJson = nlohmann::json::parse(infoOpt);
        if (!infoJson.contains("printerUri") || !infoJson["printerUri"].is_string()) {
            PRINT_HILOGE("The infoJson does not have a necessary printerUri attribute.");
            return E_PRINT_INVALID_PARAMETER;
        }
        std::string printerUri = infoJson["printerUri"].get<std::string>();
        PRINT_HILOGD("QueryPrinterInfoByPrinterId in %{public}s", printerUri.c_str());
        if (infoJson.contains("printerName") && infoJson["printerName"].is_string()) {
            info.SetPrinterName(infoJson["printerName"].get<std::string>());
        }
        int32_t ret = QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
        PRINT_HILOGI("QueryPrinterInfoByPrinterId out");
        if (ret != 0) {
            PRINT_HILOGE("QueryPrinterInfoByPrinterId QueryPrinterCapabilityByUri fail");
            return E_PRINT_SERVER_FAILURE;
        }
        nlohmann::json cupsOptionsJson = printerCaps.GetPrinterAttrGroupJson();
        infoJson["cupsOptions"] = cupsOptionsJson;
        info.SetOption(infoJson.dump());
        info.Dump();
    }
    return E_PRINT_NONE;
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
    if (printAbility_ == nullptr) {
        PRINT_HILOGW("printAbility_ is null");
        return isMakeModelRight;
    }
    const uint32_t GET_OPTION_TIMES = 40;
    while (retryCount < GET_OPTION_TIMES) {
        dest = printAbility_->GetNamedDest(CUPS_HTTP_DEFAULT, jobParams->printerName.c_str(), NULL);
        if (dest != NULL) {
            const char *makeModel = cupsGetOption("printer-make-and-model", dest->num_options, dest->options);
            PRINT_HILOGD("makeModel=%{private}s", makeModel);
            if (makeModel != nullptr && strcmp(makeModel, "Local Raw Printer") != 0) {
                isMakeModelRight = true;
                printAbility_->FreeDests(1, dest);
                break;
            }
            printAbility_->FreeDests(1, dest);
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
    JobMonitorParam *monitorParam = new (std::nothrow) JobMonitorParam { jobParams->serviceAbility,
        jobParams->serviceJobId, jobId, jobParams->printerUri, jobParams->printerName, jobParams->printerId };
    if (monitorParam == nullptr) {
        PRINT_HILOGE("monitorParam is null");
        return false;
    }
    while (retryCount < MAX_RETRY_TIMES) {
        if (CheckPrinterOnline(monitorParam)) {
            isPrinterOnline = true;
            break;
        }
        retryCount++;
        sleep(INDEX_ONE);
    }
    delete monitorParam;
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

bool PrintCupsClient::HandleFiles(JobParameters *jobParams, uint32_t num_files, http_t *http, uint32_t jobId)
{
    if (jobParams == nullptr) {
        PRINT_HILOGW("jobParams is null");
        return false;
    }
    cups_file_t *fp = nullptr;
    http_status_t status;
    char buffer[8192];
    ssize_t bytes = -1;

    for (uint32_t i = 0; i < num_files; i++) {
        if ((fp = cupsFileOpenFd(jobParams->fdList[i], "rb")) == NULL) {
            PRINT_HILOGE("Unable to open print file, cancel the job");
            cupsCancelJob2(http, jobParams->printerName.c_str(), jobId, 0);
            UpdatePrintJobStateInJobParams(jobParams, PRINT_JOB_BLOCKED, PRINT_JOB_COMPLETED_FILE_CORRUPT);
            return false;
        }
        status = cupsStartDocument(http, jobParams->printerName.c_str(), jobId, jobParams->jobName.c_str(),
            jobParams->documentFormat.c_str(), i == (num_files - 1));
        if (status == HTTP_STATUS_CONTINUE) {
            bytes = cupsFileRead(fp, buffer, sizeof(buffer));
        }
        while (status == HTTP_STATUS_CONTINUE && bytes > 0) {
            status = cupsWriteRequestData(http, buffer, (size_t)bytes);
            bytes = cupsFileRead(fp, buffer, sizeof(buffer));
        }
        cupsFileClose(fp);
        if (status != HTTP_STATUS_CONTINUE || cupsFinishDocument(http, jobParams->printerName.c_str())
            != IPP_STATUS_OK) {
            PRINT_HILOGE("Unable to queue, error is %{public}s, cancel the job and return...", cupsLastErrorString());
            cupsCancelJob2(http, jobParams->printerUri.c_str(), jobId, 0);
            UpdatePrintJobStateInJobParams(jobParams, PRINT_JOB_BLOCKED, PRINT_JOB_BLOCKED_UNKNOWN);
            return false;
        }
    }
    return true;
}

void PrintCupsClient::StartCupsJob(JobParameters *jobParams, CallbackFunc callback)
{
    http_t *http = nullptr;
    int num_options = 0;
    cups_option_t *options = nullptr;
    uint32_t jobId;

    if (!VerifyPrintJob(jobParams, num_options, jobId, options, http)) {
        callback();
        return;
    }
    if (ResumePrinter(jobParams->printerName)) {
        PRINT_HILOGW("ResumePrinter fail");
    }
    uint32_t num_files = jobParams->fdList.size();
    PRINT_HILOGD("StartCupsJob fill job options, num_files: %{public}d", num_files);
    if (!HandleFiles(jobParams, num_files, http, jobId)) {
        callback();
        return;
    }
    jobParams->cupsJobId = jobId;
    PRINT_HILOGD("start job success, jobId: %{public}d", jobId);
    JobMonitorParam *param = new (std::nothrow) JobMonitorParam { jobParams->serviceAbility,
        jobParams->serviceJobId, jobId, jobParams->printerUri, jobParams->printerName, jobParams->printerId };
    if (param == nullptr) {
        PRINT_HILOGW("param is null");
        callback();
        return;
    }
    g_isFirstQueryState = true;
    PRINT_HILOGD("MonitorJobState enter, cupsJobId: %{public}d", param->cupsJobId);
    MonitorJobState(param, callback);
    PRINT_HILOGI("FINISHED MONITORING JOB %{public}d\n", param->cupsJobId);
    delete param;
}

void PrintCupsClient::UpdatePrintJobStateInJobParams(JobParameters *jobParams, uint32_t state, uint32_t subState)
{
    if (jobParams != nullptr && jobParams->serviceAbility != nullptr) {
        jobParams->serviceAbility->UpdatePrintJobState(jobParams->serviceJobId, state, subState);
    }
}

void PrintCupsClient::HandleJobState(http_t *http, JobMonitorParam *param, JobStatus *jobStatus,
    JobStatus *prevousJobStatus)
{
    QueryJobState(http, param, jobStatus);
    if (g_isFirstQueryState) {
        QueryJobStateAgain(http, param, jobStatus);
    }
    if (jobStatus->job_state < IPP_JSTATE_CANCELED) {
        sleep(INTERVAL_FOR_QUERY);
    }
    if (jobStatus->job_state == 0) {
        PRINT_HILOGD("job_state is 0, continue");
        return;
    }
    if (prevousJobStatus != nullptr && prevousJobStatus->job_state == jobStatus->job_state &&
        strcmp(prevousJobStatus->printer_state_reasons, jobStatus->printer_state_reasons) == 0) {
        PRINT_HILOGD("the prevous jobState is the same as current, ignore");
        return;
    }
    UpdateJobStatus(prevousJobStatus, jobStatus);
    JobStatusCallback(param, jobStatus, false);
}

void PrintCupsClient::MonitorJobState(JobMonitorParam *param, CallbackFunc callback)
{
    if (param == nullptr) {
        return;
    }
    http_t *http = NULL;
    uint32_t fail_connect_times = 0;
    ippSetPort(CUPS_SEVER_PORT);
    http = httpConnect2(cupsServer(), ippPort(), NULL, AF_UNSPEC, HTTP_ENCRYPTION_IF_REQUESTED, 1, LONG_TIME_OUT, NULL);
    if (http == nullptr) {
        return;
    }
    JobStatus *jobStatus = new (std::nothrow) JobStatus { {'\0'}, (ipp_jstate_t)0, {'\0'}};
    if (jobStatus == nullptr) {
        httpClose(http);
        PRINT_HILOGE("new JobStatus returns nullptr");
        return;
    }
    JobStatus *prevousJobStatus = new (std::nothrow) JobStatus { {'\0'}, (ipp_jstate_t)0, {'\0'}};
    if (prevousJobStatus == nullptr) {
        httpClose(http);
        delete jobStatus;
        PRINT_HILOGE("new prevousJobStatus returns nullptr");
        return;
    }
    while (jobStatus != nullptr && jobStatus->job_state < IPP_JSTATE_CANCELED) {
        if (fail_connect_times > OFFLINE_RETRY_TIMES) {
            PRINT_HILOGE("_start(): The maximum number of connection failures has been exceeded");
            JobStatusCallback(param, jobStatus, true);
            break;
        }
        if (httpGetFd(http) < 0) {
            PRINT_HILOGE("http is NULL");
            httpReconnect2(http, LONG_LONG_TIME_OUT, NULL);
        }
        if (httpGetFd(http) < 0 || !CheckPrinterOnline(param)) {
            PRINT_HILOGE("unable connect to printer, retry: %{public}d", fail_connect_times);
            fail_connect_times++;
            sleep(INTERVAL_FOR_QUERY);
            continue;
        }
        fail_connect_times = 0;
        HandleJobState(http, param, jobStatus, prevousJobStatus);
    }
    httpClose(http);
    delete jobStatus;
    delete prevousJobStatus;
    callback();
}

void PrintCupsClient::QueryJobStateAgain(http_t *http, JobMonitorParam *param, JobStatus *jobStatus)
{
    sleep(INTERVAL_FOR_FIRST_QUERY);
    QueryJobState(http, param, jobStatus);
    g_isFirstQueryState = false;
}

void PrintCupsClient::UpdateJobStatus(JobStatus *prevousJobStatus, JobStatus *jobStatus)
{
    if (prevousJobStatus != nullptr && jobStatus != nullptr) {
        prevousJobStatus->job_state = jobStatus->job_state;
        strlcpy(prevousJobStatus->printer_state_reasons,
            jobStatus->printer_state_reasons,
            sizeof(jobStatus->printer_state_reasons));
    }
}

void PrintCupsClient::JobStatusCallback(JobMonitorParam *param, JobStatus *jobStatus, bool isOffline)
{
    if (param == nullptr || jobStatus == nullptr) {
        PRINT_HILOGE("JobStatusCallback param is nullptr");
        return;
    }
    PRINT_HILOGI("JobStatusCallback enter, job_state: %{public}d", jobStatus->job_state);
    PRINT_HILOGI("JobStatusCallback enter, printer_state_reasons: %{public}s", jobStatus->printer_state_reasons);
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
        PrinterStatus printerStatus;
        bool isPrinterStatusAvailable = DelayedSingleton<PrintCupsClient>::GetInstance()->
            QueryPrinterStatusByUri(param->printerUri, printerStatus) == E_PRINT_NONE;
        PRINT_HILOGD("is printer status available: %{public}d", isPrinterStatusAvailable);
        if ((isPrinterStatusAvailable && printerStatus == PRINTER_STATUS_UNAVAILABLE) ||
            (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_ERROR.c_str()) != NULL)) {
            ReportBlockedReason(param, jobStatus);
        } else {
            param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_RUNNING,
                PRINT_JOB_BLOCKED_BUSY);
        }
    } else if (jobStatus->job_state == IPP_JOB_CANCELED || jobStatus->job_state == IPP_JOB_ABORTED ||
        jobStatus->job_state == IPP_JOB_STOPPED) {
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
    if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_OFFLINE.c_str()) != NULL) {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_BLOCKED, PRINT_JOB_BLOCKED_OFFLINE);
        return;
    }
    if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_PAUSED.c_str()) != NULL) {
        param->serviceAbility->UpdatePrintJobState(
            param->serviceJobId, PRINT_JOB_BLOCKED, PRINT_JOB_BLOCKED_SERVICE_REQUEST);
        return;
    }

    uint32_t substate = GetBlockedSubstate(jobStatus);
    if (substate > PRINT_JOB_COMPLETED_SUCCESS) {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_BLOCKED,
            substate);
    } else {
        param->serviceAbility->UpdatePrintJobState(param->serviceJobId, PRINT_JOB_BLOCKED,
            PRINT_JOB_BLOCKED_UNKNOWN);
    }
}

uint32_t PrintCupsClient::GetBlockedSubstate(JobStatus *jobStatus)
{
    if (jobStatus == nullptr) {
        PRINT_HILOGE("GetBlockedSubstate param is nullptr");
        return PRINT_JOB_COMPLETED_FAILED;
    }
    uint32_t substate = PRINT_JOB_COMPLETED_SUCCESS;
    if ((strstr(jobStatus->printer_state_reasons, PRINTER_STATE_MEDIA_EMPTY.c_str()) != NULL) ||
        (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_MEDIA_NEEDED.c_str()) != NULL)) {
        substate = substate * NUMBER_FOR_SPLICING_SUBSTATE + PRINT_JOB_BLOCKED_OUT_OF_PAPER;
    }
    if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_MEDIA_JAM.c_str()) != NULL) {
        substate = substate * NUMBER_FOR_SPLICING_SUBSTATE + PRINT_JOB_BLOCKED_JAMMED;
    }
    if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_TONER_EMPTY.c_str()) != NULL) {
        substate = substate * NUMBER_FOR_SPLICING_SUBSTATE + PRINT_JOB_BLOCKED_OUT_OF_TONER;
    } else if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_TONER_LOW.c_str()) != NULL) {
        substate = substate * NUMBER_FOR_SPLICING_SUBSTATE + PRINT_JOB_BLOCKED_LOW_ON_TONER;
    }
    if ((strstr(jobStatus->printer_state_reasons, PRINTER_STATE_MARKER_EMPTY.c_str()) != NULL) ||
        (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_INK_EMPTY.c_str()) != NULL)) {
        substate = substate * NUMBER_FOR_SPLICING_SUBSTATE + PRINT_JOB_BLOCKED_OUT_OF_INK;
    } else if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_MARKER_LOW.c_str()) != NULL) {
        substate = substate * NUMBER_FOR_SPLICING_SUBSTATE + PRINT_JOB_BLOCKED_LOW_ON_INK;
    }
    if ((strstr(jobStatus->printer_state_reasons, PRINTER_STATE_DOOR_EMPTY.c_str()) != NULL) ||
        (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_COVER_OPEN.c_str()) != NULL)) {
        substate = substate * NUMBER_FOR_SPLICING_SUBSTATE + PRINT_JOB_BLOCKED_DOOR_OPEN;
    }
    if (strstr(jobStatus->printer_state_reasons, PRINTER_STATE_OTHER.c_str()) != NULL) {
        substate = substate * NUMBER_FOR_SPLICING_SUBSTATE + PRINT_JOB_BLOCKED_UNKNOWN;
    }
    return substate;
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
    if (printAbility_ == nullptr) {
        PRINT_HILOGW("printAbility_ is null");
        return;
    }
    if (param == nullptr || jobStatus == nullptr) {
        PRINT_HILOGE("QueryJobState param is null");
        return;
    }
    if (param->cupsJobId > 0) {
        request = ippNewRequest(IPP_OP_GET_JOB_ATTRIBUTES);
        ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri", NULL, param->printerUri.c_str());
        ippAddInteger(request, IPP_TAG_OPERATION, IPP_TAG_INTEGER, "job-id", param->cupsJobId);
        ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name", NULL, DEFAULT_USER.c_str());
        ippAddStrings(request, IPP_TAG_OPERATION, IPP_TAG_KEYWORD, "requested-attributes", jattrsLen, NULL, jattrs);
        PRINT_HILOGD("get job state from cups service: start");
        response = printAbility_->DoRequest(http, request, "/");
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

bool PrintCupsClient::CheckPrinterOnline(JobMonitorParam *param, const uint32_t timeout)
{
    http_t *http;
    char scheme[32] = {0};
    char userpass[BUFFER_LEN] = {0};
    char host[BUFFER_LEN] = {0};
    char resource[BUFFER_LEN] = {0};
    int port;
    if (param == nullptr) {
        PRINT_HILOGE("param is null");
        return false;
    }
    const char* printerUri = param->printerUri.c_str();
    const std::string printerId = param->printerId;
    PRINT_HILOGD("CheckPrinterOnline printerId: %{public}s", printerId.c_str());
    bool isUsbPrinter = param->printerUri.length() > USB_PRINTER.length() &&
                        param->printerUri.substr(INDEX_ZERO, INDEX_THREE) == USB_PRINTER;
    bool isCustomizedExtension = !(PrintUtil::startsWith(printerId, SPOOLER_BUNDLE_NAME) ||
                                   PrintUtil::startsWith(printerId, VENDOR_MANAGER_PREFIX));
    if ((isUsbPrinter || isCustomizedExtension) && param->serviceAbility != nullptr) {
        if (param->serviceAbility->QueryDiscoveredPrinterInfoById(printerId) == nullptr) {
            PRINT_HILOGI("printer offline");
            return false;
        } else {
            PRINT_HILOGI("printer online");
            return true;
        }
    } else {
        httpSeparateURI(HTTP_URI_CODING_ALL, printerUri, scheme, sizeof(scheme),
            userpass, sizeof(userpass), host, sizeof(host), &port, resource, sizeof(resource));
    }
    std::string nic;
    if (IsIpConflict(printerId, nic)) {
        http = httpConnect3(host, port, NULL, AF_UNSPEC, HTTP_ENCRYPTION_IF_REQUESTED, 1, timeout, NULL,
            nic.c_str());
    } else {
        http = httpConnect2(host, port, NULL, AF_UNSPEC, HTTP_ENCRYPTION_IF_REQUESTED, 1, timeout, NULL);
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

void PrintCupsClient::UpdateBorderlessJobParameter(json& optionJson, JobParameters *params)
{
    if (params == nullptr) {
        return;
    }
    if (optionJson.contains("documentCategory") && optionJson["documentCategory"].is_number()) {
        params->borderless = optionJson["documentCategory"];
    } else if (optionJson.contains("borderless") && optionJson["borderless"].is_string()) {
        std::string isBorderless = optionJson["borderless"].get<std::string>();
        if (isBorderless == "true") {
            params->borderless = 1; // 1: borderless
        } else {
            params->borderless = 0;
        }
    } else {
        params->borderless = 0;
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
    if (params == nullptr) {
        PRINT_HILOGE("new JobParameters returns nullptr");
        return params;
    }
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
    if (optionJson.contains("cupsOptions")) {
        params->printerAttrsOption_cupsOption = optionJson["cupsOptions"];
    }
    UpdateBorderlessJobParameter(optionJson, params);
    if (optionJson.contains("printQuality") && optionJson["printQuality"].is_string()) {
        params->printQuality = optionJson["printQuality"].get<std::string>();
    } else {
        params->printQuality = CUPS_PRINT_QUALITY_NORMAL;
    }
    params->jobName = optionJson.contains("jobName") ? optionJson["jobName"].get<std::string>() : DEFAULT_JOB_NAME;
    params->mediaType = optionJson.contains("mediaType") ?
        optionJson["mediaType"].get<std::string>() : CUPS_MEDIA_TYPE_PLAIN;
    params->serviceAbility = PrintServiceAbility::GetInstance();
    return params;
}

void PrintCupsClient::DumpJobParameters(JobParameters* jobParams)
{
    if (jobParams == nullptr) {
        return;
    }
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
    PRINT_HILOGD("jobParams->printerAttrsOption_cupsOption: %{public}s",
        jobParams->printerAttrsOption_cupsOption.c_str());
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
    if (printAbility_ == nullptr) {
        PRINT_HILOGW("printAbility_ is null");
        return printerExist;
    }
    dest = printAbility_->GetNamedDest(CUPS_HTTP_DEFAULT, printerName, NULL);
    if (dest != NULL) {
        const char *deviceUri = cupsGetOption("device-uri", dest->num_options, dest->options);
        if (deviceUri == nullptr) {
            PRINT_HILOGD("deviceUri is null");
            return false;
        }
        PRINT_HILOGD("deviceUri=%{private}s", deviceUri);
        const char *makeModel = cupsGetOption("printer-make-and-model", dest->num_options, dest->options);
        if (makeModel == nullptr) {
            PRINT_HILOGD("makeModel is null");
            return false;
        }
        PRINT_HILOGD("makeModel=%{private}s", makeModel);
        int printerState = cupsGetIntegerOption("printer-state", dest->num_options, dest->options);
        PRINT_HILOGD("printerState=%{private}d", printerState);
        if (printerState == IPP_PRINTER_STOPPED || makeModel == nullptr || strcmp(deviceUri, printerUri) != 0) {
            printAbility_->FreeDests(1, dest);
            PRINT_HILOGI("Printer information needs to be modified");
            return printerExist;
        }
        if (strcmp(ppdName, DEFAULT_PPD_NAME.c_str()) == 0) {
            // 查到everywhere或remote printer驱动
            printerExist = (strstr(makeModel, DEFAULT_MAKE_MODEL.c_str()) != NULL) ||
                           (strstr(makeModel, REMOTE_PRINTER_MAKE_MODEL.c_str()) != NULL);
        } else {
            // 查到驱动
            printerExist = !(strstr(makeModel, DEFAULT_MAKE_MODEL.c_str()) != NULL);
            if (!printerExist) {
                // 私有驱动已卸载，需要先删除打印机再添加，不然下发任务找不到驱动
                DeleteCupsPrinter(printerName);
            }
        }
        printAbility_->FreeDests(1, dest);
    }
    return printerExist;
}

float PrintCupsClient::ConvertInchTo100MM(float num)
{
    return ((num / THOUSAND_INCH) * CONVERSION_UNIT);
}

bool PrintCupsClient::IsIpConflict(const std::string &printerId, std::string &nic) __attribute__((no_sanitize("cfi")))
{
    if (printerId.find(P2P_PRINTER) == std::string::npos) {
        PRINT_HILOGD("The printer is not p2p: %{private}s", printerId.c_str());
        return false;
    }
    bool isWifiConnected = false;
    auto wifiDevice = Wifi::WifiDevice::GetInstance(OHOS::WIFI_DEVICE_SYS_ABILITY_ID);
    if (!wifiDevice) {
        PRINT_HILOGE("wifiDevice GetInstance failed.");
        return false;
    }
    wifiDevice->IsConnected(isWifiConnected);
    PRINT_HILOGD("isWifiConnected: %{public}d", isWifiConnected);
    Wifi::WifiP2pLinkedInfo p2pLinkedInfo;
    Wifi::WifiP2p::GetInstance(OHOS::WIFI_P2P_SYS_ABILITY_ID)->QueryP2pLinkedInfo(p2pLinkedInfo);
    PRINT_HILOGD("P2pConnectedState: %{public}d", p2pLinkedInfo.GetConnectState());
    if (isWifiConnected && p2pLinkedInfo.GetConnectState() == Wifi::P2pConnectedState::P2P_CONNECTED) {
        Wifi::IpInfo info;
        auto wifiDevice = Wifi::WifiDevice::GetInstance(OHOS::WIFI_DEVICE_SYS_ABILITY_ID);
        if (!wifiDevice) {
            PRINT_HILOGE("wifiDevice GetInstance failed.");
            return false;
        }
        wifiDevice->GetIpInfo(info);
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

int32_t PrintCupsClient::DiscoverUsbPrinters(std::vector<PrinterInfo> &printers)
{
    int longStatus = 0;
    const char* include_schemes = CUPS_INCLUDE_ALL;
    const char* exclude_schemes = CUPS_EXCLUDE_NONE;
    int timeout = CUPS_TIMEOUT_DEFAULT;
    PRINT_HILOGD("DiscoverUsbPrinters cupsGetDevices");
    usbPrinters.clear();
    if (cupsGetDevices(CUPS_HTTP_DEFAULT, timeout, include_schemes, exclude_schemes,
        DeviceCb, &longStatus) != IPP_OK) {
        PRINT_HILOGE("lpinfo error : %{public}s", cupsLastErrorString());
        return E_PRINT_SERVER_FAILURE;
    }
    printers = usbPrinters;
    return E_PRINT_NONE;
}

int32_t PrintCupsClient::ResumePrinter(const std::string &printerName)
{
    if (printAbility_ == nullptr) {
        PRINT_HILOGE("printAbility is null");
        return E_PRINT_SERVER_FAILURE;
    }
    ipp_t *request = nullptr;
    char uri[HTTP_MAX_URI] = {0};
    httpAssembleURIf(HTTP_URI_CODING_ALL, uri, sizeof(uri), "ipp", NULL, "localhost", 0, "/printers/%s",
                     printerName.c_str());
    request = ippNewRequest(IPP_OP_RESUME_PRINTER);
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI, "printer-uri", NULL, uri);
    ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME, "requesting-user-name", NULL, cupsUser());
    PRINT_HILOGD("IPP_OP_RESUME_PRINTER cupsDoRequest");
    ippDelete(printAbility_->DoRequest(NULL, request, "/admin/"));
    if (cupsLastError() > IPP_STATUS_OK_EVENTS_COMPLETE) {
        PRINT_HILOGE("resume printer error: %s", cupsLastErrorString());
        return E_PRINT_SERVER_FAILURE;
    }
    PRINT_HILOGI("resume printer success");
    return E_PRINT_NONE;
}
}