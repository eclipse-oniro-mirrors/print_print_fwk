/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef NATIVE_PRINT_HELPER_H
#define NATIVE_PRINT_HELPER_H

#include <string>

#include "ohprint.h"
#include "printer_info.h"
#include "print_job.h"

namespace OHOS::Print {
char *CopyString(const std::string &source);
void ReleasePrinterInfo(Print_PrinterInfo &printerInfo);
Print_PrinterInfo *ConvertToNativePrinterInfo(const PrinterInfo &info);
int32_t ConvertNativeJobToPrintJob(const Print_PrintJob &nativePrintJob, PrintJob &printJob);
Print_ErrorCode ConvertStringVectorToPropertyList(const std::vector<std::string> &valueList,
    Print_PropertyList *propertyList);
}  // namespace OHOS::Print
#endif  // NATIVE_PRINT_HELPER_H