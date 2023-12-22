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

namespace OHOS::Print {
#define PRINT_RET_NONE

#define PRINT_MAX_PRINT_COUNT 1000
#define PRINT_CALLBACK_ADAPTER "printCallback_adapter"
#define PRINT_GET_FILE_CALLBACK_ADAPTER "getPrintFileCallback_adapter"

#define NEW_PRINT_INTERFACE_SWITCH false

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


enum PrintErrorCode {
    E_PRINT_NONE = 0,
    E_PRINT_NO_PERMISSION = 201,
    E_PRINT_INVALID_PARAMETER = 401,
    E_PRINT_GENERIC_FAILURE = 13100001,
    E_PRINT_RPC_FAILURE = 13100002,
    E_PRINT_SERVER_FAILURE = 13100003,
    E_PRINT_INVALID_EXTENSION = 13100004,
    E_PRINT_INVALID_PRINTER = 13100005,
    E_PRINT_INVALID_PRINTJOB = 13100006,
    E_PRINT_FILE_IO = 13100007,
    E_PRINT_UNKNOWN = 13100255,
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
    PRINT_JOB_COMPLETED = 4,    // print job ocmpleted
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
} // namespace OHOS::Print
#endif // PRINT_CONSTANT_H