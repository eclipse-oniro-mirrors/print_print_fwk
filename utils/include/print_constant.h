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

#ifndef PRINT_CONSTANT_H
#define PRINT_CONSTANT_H

#include <string>
#include <map>

namespace OHOS::Print {
#define PRINT_RET_NONE

#define PRINT_MAX_PRINT_COUNT 1000
#define PRINT_MAX_PPD_COUNT 4096
#define PRINT_CALLBACK_ADAPTER "printCallback_adapter"
#define PRINT_GET_FILE_CALLBACK_ADAPTER "getPrintFileCallback_adapter"

#define PRINT_ASSERT_BASE(env, assertion, message, retVal)  \
    do {                                                    \
        if (!(assertion)) {                                 \
            PRINT_HILOGE(message);                          \
            return retVal;                                  \
        }                                                   \
    } while (0)

#define PRINT_ASSERT(env, assertion, message) PRINT_ASSERT_BASE(env, assertion, message, nullptr)

#define PRINT_ASSERT_RETURN_VOID(env, assertion, message) PRINT_ASSERT_BASE(env, assertion, message, PRINT_RET_NONE)

#define PRINT_CALL_BASE(env, theCall, retVal)   \
    do {                                        \
        if ((theCall) != napi_ok) {             \
            return retVal;                      \
        }                                       \
    } while (0)

#define PRINT_CALL(env, theCall) PRINT_CALL_BASE(env, theCall, nullptr)

#define PRINT_CALL_RETURN_VOID(env, theCall) PRINT_CALL_BASE(env, theCall, PRINT_RET_NONE)

#define CHECK_IS_EXCEED_PRINT_RANGE_BASE(count, retVal)                                             \
    do {                                                                                            \
        if ((count) > PRINT_MAX_PRINT_COUNT) {                                                      \
            PRINT_HILOGW("input val is exceed print max range:%{public}d", PRINT_MAX_PRINT_COUNT);  \
            return retVal;                                                                          \
        }                                                                                           \
    } while (0)

#define CHECK_IS_EXCEED_PRINT_RANGE(count)          CHECK_IS_EXCEED_PRINT_RANGE_BASE(count, nullptr)
#define CHECK_IS_EXCEED_PRINT_RANGE_BOOL(count)     CHECK_IS_EXCEED_PRINT_RANGE_BASE(count, false)
#define CHECK_IS_EXCEED_PRINT_RANGE_VOID(count)     CHECK_IS_EXCEED_PRINT_RANGE_BASE(count, PRINT_RET_NONE)
#define CHECK_IS_EXCEED_PRINT_RANGE_INT(count)      CHECK_IS_EXCEED_PRINT_RANGE_BASE(count, E_PRINT_INVALID_PARAMETER)

#define PRINT_SAFE_DELETE(ptr) \
    if ((ptr) != nullptr) { \
        delete (ptr); \
        (ptr) = nullptr; \
    }

enum PrintErrorCode {
    E_PRINT_NONE = 0,
    E_PRINT_NO_PERMISSION = 201,
    E_PRINT_ILLEGAL_USE_OF_SYSTEM_API = 202,
    E_PRINT_INVALID_PARAMETER = 401,
    E_PRINT_GENERIC_FAILURE = 13100001,
    E_PRINT_RPC_FAILURE = 13100002,
    E_PRINT_SERVER_FAILURE = 13100003,
    E_PRINT_INVALID_EXTENSION = 13100004,
    E_PRINT_INVALID_PRINTER = 13100005,
    E_PRINT_INVALID_PRINTJOB = 13100006,
    E_PRINT_FILE_IO = 13100007,
    E_PRINT_INVALID_TOKEN = 13100008,
    E_PRINT_INVALID_USERID = 13100009,
    E_PRINT_TOO_MANY_FILES = 13100010,
    E_PRINT_UNKNOWN = 13100255,
    E_PRINT_BANNED = 13100011,
};

const uint32_t PRINT_INVALID_ID = 0xFFFFFFFF;   // -1

enum PrinterState {
    PRINTER_ADDED = 0,          // new printers arrival
    PRINTER_REMOVED = 1,        // printers lost
    PRINTER_UPDATE_CAP = 2,     // printers update
    PRINTER_CONNECTED = 3,      // printer has been connected
    PRINTER_DISCONNECTED = 4,   // printer has been disconnected
    PRINTER_RUNNING = 5,        // printer is working
    PRINTER_UNKNOWN = 6,        // unknown printer state
};

enum PrintJobState {
    PRINT_JOB_PREPARED = 0,     // initial state of print job
    PRINT_JOB_QUEUED = 1,       // deliver print job to the printer
    PRINT_JOB_RUNNING = 2,      // executing print job
    PRINT_JOB_BLOCKED = 3,      // print job has been blocked
    PRINT_JOB_COMPLETED = 4,    // print job completed
    PRINT_JOB_UNKNOWN = 100,      // unknown state of print job
    PRINT_JOB_CREATE_FILE_COMPLETED = 101,    // For internal use only: create print file completed
    PRINT_JOB_SPOOLER_CLOSED = 102,    // For internal use only: spooler closed
};

enum PrintJobSubState {
    PRINT_JOB_COMPLETED_SUCCESS = 0,            // print job succeed
    PRINT_JOB_COMPLETED_FAILED = 1,             // print job fail
    PRINT_JOB_COMPLETED_CANCELLED = 2,          // print job has been cancelled
    PRINT_JOB_COMPLETED_FILE_CORRUPT = 3,       // print job has been corrupted
    PRINT_JOB_BLOCKED_OFFLINE = 4,              // printer is offline
    PRINT_JOB_BLOCKED_BUSY = 5,                 // printer is occupied by other process
    PRINT_JOB_BLOCKED_CANCELLED = 6,            // print job has been canncelled
    PRINT_JOB_BLOCKED_OUT_OF_PAPER = 7,         // out of paper
    PRINT_JOB_BLOCKED_OUT_OF_INK = 8,           // out of ink
    PRINT_JOB_BLOCKED_OUT_OF_TONER = 9,         // out of toner
    PRINT_JOB_BLOCKED_JAMMED = 10,              // paper jam
    PRINT_JOB_BLOCKED_DOOR_OPEN = 11,           // cover open
    PRINT_JOB_BLOCKED_SERVICE_REQUEST = 12,     // service request
    PRINT_JOB_BLOCKED_LOW_ON_INK = 13,          // low on ink
    PRINT_JOB_BLOCKED_LOW_ON_TONER = 14,        // low on toner
    PRINT_JOB_BLOCKED_REALLY_LOW_ON_INK = 15,   // really low on ink
    PRINT_JOB_BLOCKED_BAD_CERTIFICATE = 16,     // bad certification
    PRINT_JOB_BLOCKED_DRIVER_EXCEPTION = 17,    // printer driver exception

    PRINT_JOB_BLOCKED_ACCOUNT_ERROR = 18, // An error occurred when printing the account.
    PRINT_JOB_BLOCKED_PRINT_PERMISSION_ERROR = 19, // The printing permission is abnormal.
    PRINT_JOB_BLOCKED_PRINT_COLOR_PERMISSION_ERROR = 20, // Color printing permission exception
    PRINT_JOB_BLOCKED_NETWORK_ERROR = 21, // The device is not connected to the network.
    PRINT_JOB_BLOCKED_SERVER_CONNECTION_ERROR = 22, // Unable to connect to the server
    PRINT_JOB_BLOCKED_LARGE_FILE_ERROR = 23, // Large file exception
    PRINT_JOB_BLOCKED_FILE_PARSING_ERROR = 24, // File parsing exception.
    PRINT_JOB_BLOCKED_SLOW_FILE_CONVERSION = 25, // The file conversion is too slow.
    PRINT_JOB_RUNNING_UPLOADING_FILES = 26, // Uploading file...
    PRINT_JOB_RUNNING_CONVERTING_FILES = 27, // Converting files...
    PRINT_JOB_CREATE_FILE_COMPLETED_SUCCESS = 28, // print job create file succeed
    PRINT_JOB_CREATE_FILE_COMPLETED_FAILED = 29, // print job create file fail
    PRINT_JOB_BLOCK_FILE_UPLOADING_ERROR = 30, // File uploading exception.
    PRINT_JOB_BLOCKED_DRIVER_MISSING = 34, // driver file missing
    PRINT_JOB_BLOCKED_INTERRUPT = 35, // print job interrupt
    PRINT_JOB_BLOCKED_AUTHENTICATION = 36,  // print job need authenticate.
    PRINT_JOB_BLOCKED_BANNED = 37,  // print job has been banned by organization.
    PRINT_JOB_BLOCKED_PRINTER_UNAVAILABLE = 98, // Printer is stopped.
    PRINT_JOB_BLOCKED_UNKNOWN = 99,             // unknown issue
    PRINT_JOB_SPOOLER_CLOSED_FOR_CANCELED = 101, // For internal use only: Click Cancel
    PRINT_JOB_SPOOLER_CLOSED_FOR_STARTED = 102, // For internal use only: Click Start
};

enum PrintFileCreatedInfoCode {
    PRINT_FILE_CREATED_SUCCESS = 0,
    PRINT_FILE_CREATED_FAIL = 1,
    PRINT_FILE_CREATED_SUCCESS_UNRENDERED = 2,
};

enum PrintDocumentAdapterState {
    PREVIEW_ABILITY_DESTROY = 0,
    PRINT_TASK_SUCCEED = 1,
    PRINT_TASK_FAIL = 2,
    PRINT_TASK_CANCEL = 3,
    PRINT_TASK_BLOCK = 4,
    PREVIEW_ABILITY_DESTROY_FOR_CANCELED = 5,
    PREVIEW_ABILITY_DESTROY_FOR_STARTED = 6,
};

enum PrintExtensionState {
    PRINT_EXTENSION_UNLOAD,
    PRINT_EXTENSION_LOADING,
    PRINT_EXTENSION_LOADED,
};

enum PrintParamStatus {
    PRINT_PARAM_NOT_SET,
    PRINT_PARAM_OPT,
    PRINT_PARAM_SET,
};

enum PrintDirectionMode {
    DIRECTION_MODE_AUTO = 0,
    DIRECTION_MODE_PORTRAIT = 1,
    DIRECTION_MODE_LANDSCAPE = 2,
};

enum PrintColorMode {
    PRINT_COLOR_MODE_MONOCHROME = 0,
    PRINT_COLOR_MODE_COLOR = 1,
};

enum PrintDuplexMode {
    DUPLEX_MODE_NONE = 0,
    DUPLEX_MODE_LONG_EDGE = 1,
    DUPLEX_MODE_SHORT_EDGE = 2,
};

enum PrintQualityCode {
    PRINT_QUALITY_DRAFT = 3,
    PRINT_QUALITY_NORMAL = 4,
    PRINT_QUALITY_HIGH = 5
};

enum PrintOrientationMode {
    PRINT_ORIENTATION_MODE_PORTRAIT = 0,
    PRINT_ORIENTATION_MODE_LANDSCAPE = 1,
    PRINT_ORIENTATION_MODE_REVERSE_LANDSCAPE = 2,
    PRINT_ORIENTATION_MODE_REVERSE_PORTRAIT = 3,
    PRINT_ORIENTATION_MODE_NONE = 4
};

enum PrintPageType {
    PAGE_ISO_A3 = 0,
    PAGE_ISO_A4 = 1,
    PAGE_ISO_A5 = 2,
    PAGE_JIS_B5 = 3,
    PAGE_ISO_C5 = 4,
    PAGE_ISO_DL = 5,
    PAGE_LETTER = 6,
    PAGE_LEGAL = 7,
    PAGE_PHOTO_4X6 = 8,
    PAGE_PHOTO_5X7 = 9,
    PAGE_INT_DL_ENVELOPE = 10,
    PAGE_B_TABLOID = 11,
};

enum ApplicationEvent {
    APPLICATION_CREATED = 0,
    APPLICATION_CLOSED_FOR_STARTED = 1,
    APPLICATION_CLOSED_FOR_CANCELED = 2,
};

enum PrinterStatus {
    PRINTER_STATUS_IDLE = 0,
    PRINTER_STATUS_BUSY = 1,
    PRINTER_STATUS_UNAVAILABLE = 2,
};

enum PrinterEvent {
    PRINTER_EVENT_ADDED = 0,
    PRINTER_EVENT_DELETED = 1,
    PRINTER_EVENT_STATE_CHANGED = 2,
    PRINTER_EVENT_INFO_CHANGED = 3,
    PRINTER_EVENT_PREFERENCE_CHANGED = 4,
    PRINTER_EVENT_LAST_USED_PRINTER_CHANGED = 5,
};

enum DefaultPrinterType {
    DEFAULT_PRINTER_TYPE_SETTED_BY_USER = 0,
    DEFAULT_PRINTER_TYPE_LAST_USED_PRINTER = 1,
};

const std::string PRINTER_DISCOVER_EVENT_TYPE = "printerDiscover";
const std::string PRINTER_CHANGE_EVENT_TYPE = "printerChange";
static const std::string PERMISSION_NAME_PRINT = "ohos.permission.PRINT";
static const std::string PERMISSION_NAME_PRINT_JOB = "ohos.permission.MANAGE_PRINT_JOB";
const std::string PRINTER_SERVICE_FILE_PATH = "/data/service/el2/public/print_service";
const std::string PRINTER_SERVICE_PRINTERS_PATH = "/data/service/el2/public/print_service/printers";
const std::string PRINTER_SERVICE_PRINTERS_ENTERPRISE_PATH =
    "/data/service/el2/public/print_service/printers_enterprise";
const std::string PRINTER_LIST_FILE = "printer_list.json";
const std::string PRINTER_LIST_VERSION_FILE = "version.json";
const std::string PRINTER_LIST_VERSION_V1 = "v1";
const std::string PRINTER_LIST_VERSION_V3 = "v3";
const std::string PRINT_USER_DATA_FILE = "print_user_data.json";
const std::string PRINT_USER_DATA_VERSION = "v1";
const std::string PRINTER_PREFERENCE_FILE = "printer_preference.json";
const std::string DEFAULT_PAGESIZE_ID = "ISO_A4";
const std::string DEFAULT_MEDIA_TYPE = "stationery";
const std::string DEFAULT_USER_NAME = "print";
static const std::string P2P_PRINTER = "p2p";
static const std::string EPRINTID = "ePrintID";

const std::string E_PRINT_MSG_NONE = "none";
const std::string E_PRINT_MSG_NO_PERMISSION = "the application does not hace permission";
const std::string E_PRINT_MSG_INVALID_PARAMETER = "parameter error";
static std::map<PrintErrorCode, const std::string> PRINT_ERROR_MSG_MAP {
    {E_PRINT_NONE,                  E_PRINT_MSG_NONE                },
    {E_PRINT_NO_PERMISSION,         E_PRINT_MSG_NO_PERMISSION       },
    {E_PRINT_INVALID_PARAMETER,     E_PRINT_MSG_INVALID_PARAMETER   },
};

const std::string VENDOR_WLAN_GROUP = "driver.wlan.group";
const std::string VENDOR_BSUNI_DRIVER = "driver.bsuni";
const std::string VENDOR_PPD_DRIVER = "driver.ppd";
const std::string VENDOR_IPP_EVERYWHERE = "driver.ipp.everywhere";
const std::string BSUNI_PPD_NAME = "Brocadesoft Universal Driver";
static const std::string DEFAULT_PPD_NAME = "everywhere";
const std::string RAW_PPD_NAME = "raw";
const std::string RAW_PPD_DRIVER = "driver.raw";

const std::string CONNECT_PRINT_EVENT_TYPE = "Event_Connect_Printer";
const int32_t CONNECT_PRINT_EVENT_IPP_UNAVAILABLE = 24300201;

const int32_t INVALID_USER_ID = -1;

const std::string PRINT_PARAM_TYPE_PAGE_SIZE = "defaultPageSizeId";
const std::string PRINT_PARAM_TYPE_QUALITY = "defaultPrintQuality";
const std::string PRINT_PARAM_TYPE_DUPLEX_MODE = "defaultDuplexMode";
const std::string PRINT_PARAM_TYPE_COLOR_MODE = "defaultColorMode";
const std::string PRINT_PARAM_TYPE_MEDIA_TYPE = "defaultMediaType";
const std::string PRINT_PARAM_TYPE_OUTPUT_ORDER = "defaultReverse";
const std::string PRINT_PARAM_TYPE_DELIVERY_ORDER = "defaultCollate";

const std::string PRINT_PARAM_VAL_TRUE = "True";
const std::string PRINT_PARAM_VAL_FALSE = "False";

const std::string PAGE_SIZE_ID_ISO_A0 = "ISO_A0";
const std::string PAGE_SIZE_ID_ISO_A1 = "ISO_A1";
const std::string PAGE_SIZE_ID_ISO_A2 = "ISO_A2";
const std::string PAGE_SIZE_ID_ISO_A3 = "ISO_A3";
const std::string PAGE_SIZE_ID_ISO_A4 = "ISO_A4";
const std::string PAGE_SIZE_ID_ISO_A5 = "ISO_A5";
const std::string PAGE_SIZE_ID_ISO_A6 = "ISO_A6";
const std::string PAGE_SIZE_ID_ISO_A7 = "ISO_A7";
const std::string PAGE_SIZE_ID_ISO_A8 = "ISO_A8";
const std::string PAGE_SIZE_ID_ISO_A9 = "ISO_A9";
const std::string PAGE_SIZE_ID_ISO_A10 = "ISO_A10";
const std::string PAGE_SIZE_ID_ISO_B0 = "ISO_B0";
const std::string PAGE_SIZE_ID_ISO_B1 = "ISO_B1";
const std::string PAGE_SIZE_ID_ISO_B2 = "ISO_B2";
const std::string PAGE_SIZE_ID_ISO_B3 = "ISO_B3";
const std::string PAGE_SIZE_ID_ISO_B4 = "ISO_B4";
const std::string PAGE_SIZE_ID_ISO_B5 = "ISO_B5";
const std::string PAGE_SIZE_ID_ISO_B6 = "ISO_B6";
const std::string PAGE_SIZE_ID_ISO_B7 = "ISO_B7";
const std::string PAGE_SIZE_ID_ISO_B8 = "ISO_B8";
const std::string PAGE_SIZE_ID_ISO_B9 = "ISO_B9";
const std::string PAGE_SIZE_ID_ISO_B10 = "ISO_B10";
const std::string PAGE_SIZE_ID_ISO_C0 = "ISO_C0";
const std::string PAGE_SIZE_ID_ISO_C1 = "ISO_C1";
const std::string PAGE_SIZE_ID_ISO_C2 = "ISO_C2";
const std::string PAGE_SIZE_ID_ISO_C3 = "ISO_C3";
const std::string PAGE_SIZE_ID_ISO_C4 = "ISO_C4";
const std::string PAGE_SIZE_ID_ISO_C5 = "ISO_C5";
const std::string PAGE_SIZE_ID_ISO_C6 = "ISO_C6";
const std::string PAGE_SIZE_ID_ISO_C7 = "ISO_C7";
const std::string PAGE_SIZE_ID_ISO_C8 = "ISO_C8";
const std::string PAGE_SIZE_ID_ISO_C9 = "ISO_C9";
const std::string PAGE_SIZE_ID_ISO_C10 = "ISO_C10";
const std::string PAGE_SIZE_ID_ISO_DL = "ISO_DL";
const std::string PAGE_SIZE_ID_JIS_B0 = "JIS_B0";
const std::string PAGE_SIZE_ID_JIS_B1 = "JIS_B1";
const std::string PAGE_SIZE_ID_JIS_B2 = "JIS_B2";
const std::string PAGE_SIZE_ID_JIS_B3 = "JIS_B3";
const std::string PAGE_SIZE_ID_JIS_B4 = "JIS_B4";
const std::string PAGE_SIZE_ID_JIS_B5 = "JIS_B5";
const std::string PAGE_SIZE_ID_JIS_B6 = "JIS_B6";
const std::string PAGE_SIZE_ID_JIS_B7 = "JIS_B7";
const std::string PAGE_SIZE_ID_JIS_B8 = "JIS_B8";
const std::string PAGE_SIZE_ID_JIS_B9 = "JIS_B9";
const std::string PAGE_SIZE_ID_JIS_B10 = "JIS_B10";
const std::string PAGE_SIZE_ID_JIS_EXEC = "JIS_EXEC";
const std::string PAGE_SIZE_ID_JPN_CHOU2 = "JPN_CHOU2";
const std::string PAGE_SIZE_ID_JPN_CHOU3 = "JPN_CHOU3";
const std::string PAGE_SIZE_ID_JPN_CHOU4 = "JPN_CHOU4";
const std::string PAGE_SIZE_ID_JPN_HAGAKI = "JPN_HAGAKI";
const std::string PAGE_SIZE_ID_NA_ARCH_A = "NA_ARCH_A";
const std::string PAGE_SIZE_ID_NA_ARCH_B = "NA_ARCH_B";
const std::string PAGE_SIZE_ID_NA_ARCH_C = "NA_ARCH_C";
const std::string PAGE_SIZE_ID_NA_ARCH_D = "NA_ARCH_D";
const std::string PAGE_SIZE_ID_NA_ARCH_E = "NA_ARCH_E";
const std::string PAGE_SIZE_ID_NA_FOOLSCAP = "NA_FOOLSCAP";
const std::string PAGE_SIZE_ID_NA_LEGAL = "NA_LEGAL";
const std::string PAGE_SIZE_ID_NA_LETTER = "NA_LETTER";
const std::string PAGE_SIZE_ID_NA_INDEX_3X5 = "NA_INDEX_3X5";
const std::string PAGE_SIZE_ID_NA_INDEX_5X8 = "NA_INDEX_5X8";
const std::string PAGE_SIZE_ID_NA_INDEX_5X7 = "NA_INDEX_5X7";
const std::string PAGE_SIZE_ID_NA_INDEX_4X6 = "NA_INDEX_4X6";
const std::string PAGE_SIZE_ID_NA_GOVT_LETTER = "NA_GOVT_LETTER";
const std::string PAGE_SIZE_ID_NA_LEDGER = "NA_LEDGER";
const std::string PAGE_SIZE_ID_OM_DSC_PHOTO = "OM_DSC_PHOTO";
const std::string PAGE_SIZE_ID_OM_CARD = "OM_CARD";
const std::string PAGE_SIZE_ID_OE_PHOTO_L = "OE_PHOTO_L";
const std::string PAGE_SIZE_ID_NA_TABLOID = "NA_TABLOID";
const std::string PAGE_SIZE_ID_NA_EXECUTIVE = "NA_EXECUTIVE";
const std::string PAGE_SIZE_ID_PRC1 = "PRC1";
const std::string PAGE_SIZE_ID_PRC2 = "PRC2";
const std::string PAGE_SIZE_ID_PRC4 = "PRC4";
const std::string PAGE_SIZE_ID_PRC6 = "PRC6";
const std::string PAGE_SIZE_ID_PRC7 = "PRC7";
const std::string PAGE_SIZE_ID_PRC8 = "PRC8";
const std::string PAGE_SIZE_ID_PRC16 = "PRC16";
const std::string PAGE_SIZE_ID_ROC_16K = "ROC_16K";
const std::string PAGE_SIZE_ID_ROC_8K = "ROC_8K";

} // namespace OHOS::Print
#endif // PRINT_CONSTANT_H
