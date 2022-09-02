/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

namespace OHOS::Print {

enum PrinterState {
    PRINTER_ADD = 1, // new printers arrival
    PRINTER_REMOVED = 2, // printers lost
    PRINTER_IDLE = 3, // printer idle
    PRINTER_PRINTING = 4, // printer is working
    PRINTER_BLOCK = 5, // printer has been blocked
    PRINTER_BUSY = 6, // printer is busy
    PRINTER_FAULT = 7, // printer failure
    PRINTER_UNKNOWN,
};

enum PrintJobState {
    PRINT_JOB_INIT = 1, // initial state of print job
    PRINT_JOB_START = 2, // start print job
    PRINT_JOB_PRINTING = 3, // printing
    PRINT_JOB_BLOCK = 4, // print job has been blocked
    PRINT_JOB_COMPLETE = 5, // print completed
    PRINT_JOB_CANCEL = 6, // print job has been cancelled
};

} // namespace OHOS::Print

#endif // PRINT_CONSTANT_H