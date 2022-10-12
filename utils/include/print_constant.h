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

const std::string INVALID_PRINT_TASK = "invalid_print_task";

enum PrintErrorCode {
  ERROR_NONE = 0,
  ERROR_GENERIC_FAIL = 1,
  ERROR_INVALID_PARAMETER = 2,
  ERROR_NO_PERMISSION = 3,
  ERROR_RPC_FAIL = 4,
  ERROR_SERVER_FAIL = 5,
  ERROR_INVALID_EXTENSION = 6,
  ERROR_INVALID_PRINTER = 7,
  ERROR_INVALID_PRINTJOB = 8,
  ERROR_FILE_IO = 9,
  ERROR_UNKNOWN = 255,
};

const std::string ErrorMessage[] = {
    "ERROR_NONE",
    "ERROR_GENERIC_FAIL",
    "ERROR_INVALID_PARAMETER",
    "ERROR_NO_PERMISSION",
    "ERROR_RPC_FAIL",
    "ERROR_SERVER_FAIL",
    "ERROR_INVALID_EXTENSION",
    "ERROR_INVALID_PRINTER",
    "ERROR_INVALID_PRINTJOB",
    "ERROR_FILE_IO",
    "ERROR_UNKNOWN",
};

enum PrinterState {
  PRINTER_ADDED = 0,        // new printers arrival
  PRINTER_REMOVED = 1,      // printers lost
  PRINTER_UPDATE_CAP = 2,   // printers update
  PRINTER_CONNECTED = 3,    // printer has been connected
  PRINTER_DISCONNECTED = 4, // printer has been disconnected
  PRINTER_RUNNING = 5,      // printer is working
  PRINTER_UNKNOWN = 6,      // unknown printer state
};

enum PrintJobState {
  PRINT_JOB_PREPARED = 0,  // initial state of print job
  PRINT_JOB_QUEUED = 1,    // deliver print job to the printer
  PRINT_JOB_RUNNING = 2,   // executing print job
  PRINT_JOB_BLOCKED = 3,   // print job has been blocked
  PRINT_JOB_COMPLETED = 4, // print job ocmpleted
  PRINT_JOB_UNKNOWN = 5,   // unknown state of print job
};

enum PrintJobSubState {
  PRINT_JOB_COMPLETED_SUCCESS = 0,      // print job succeed
  PRINT_JOB_COMPLETED_FAILED = 1,       // print job fail
  PRINT_JOB_COMPLETED_CANCELLED = 2,    // print job has been cancelled
  PRINT_JOB_COMPLETED_FILE_CORRUPT = 3, // print job has been corrupted
  PRINT_JOB_BLOCKED_OFFLINE = 4,        // printer is offline
  PRINT_JOB_BLOCKED_BUSY = 5,           // printer is occupied by other process
  PRINT_JOB_BLOCKED_CANCELLED = 6,      // print job has been canncelled
  PRINT_JOB_BLOCKED_OUT_OF_PAPER = 7,   // out of paper
  PRINT_JOB_BLOCKED_OUT_OF_INK = 8,     // out of ink
  PRINT_JOB_BLOCKED_OUT_OF_TONER = 9,   // out of toner
  PRINT_JOB_BLOCKED_JAMMED = 10,        // paper jam
  PRINT_JOB_BLOCKED_DOOR_OPEN = 11,     // cover open
  PRINT_JOB_BLOCKED_SERVICE_REQUEST = 12,   // service request
  PRINT_JOB_BLOCKED_LOW_ON_INK = 13,        // low on ink
  PRINT_JOB_BLOCKED_LOW_ON_TONER = 14,      // low on toner
  PRINT_JOB_BLOCKED_REALLY_LOW_ON_INK = 15, // really low on ink
  PRINT_JOB_BLOCKED_BAD_CERTIFICATE = 16,   // bad certification
  PRINT_JOB_BLOCKED_UNKNOWN = 17,           // unknown issue
};

enum PrintExtensionState {
  PRINT_EXTENSION_UNLOAD,
  PRINT_EXTENSION_LOADING,
  PRINT_EXTENSION_LOADED,
  PRINT_EXTENSION_RUNNING,
};
} // namespace OHOS::Print
#endif // PRINT_CONSTANT_H