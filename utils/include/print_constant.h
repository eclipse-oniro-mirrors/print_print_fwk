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

#define PRINT_ASSERT_BASE(env, assertion, message, retVal)                     \
  do {                                                                         \
    if (!(assertion)) {                                                        \
      PRINT_HILOGE(message);                                                   \
      return retVal;                                                           \
    }                                                                          \
  } while (0)

#define PRINT_ASSERT(env, assertion, message)                                  \
  PRINT_ASSERT_BASE(env, assertion, message, nullptr)

#define PRINT_ASSERT_RETURN_VOID(env, assertion, message)                      \
  PRINT_ASSERT_BASE(env, assertion, message, PRINT_RET_NONE)

#define PRINT_CALL_BASE(env, theCall, retVal)                                  \
  do {                                                                         \
    if ((theCall) != napi_ok) {                                                \
      return retVal;                                                           \
    }                                                                          \
  } while (0)

#define PRINT_CALL(env, theCall) PRINT_CALL_BASE(env, theCall, nullptr)

#define PRINT_CALL_RETURN_VOID(env, theCall)                                   \
  PRINT_CALL_BASE(env, theCall, PRINT_RET_NONE)

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
};

enum PrintParamStatus {
  PRINT_PARAM_NOT_SET,
  PRINT_PARAM_OPT,
  PRINT_PARAM_SET,
};
} // namespace OHOS::Print
#endif // PRINT_CONSTANT_H