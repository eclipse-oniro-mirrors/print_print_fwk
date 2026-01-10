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
#ifndef PRINT_JOB_HELPER_H
#define PRINT_JOB_HELPER_H

#include <map>
#include "napi/native_api.h"
#include "print_job.h"
#include "print_utils.h"

namespace OHOS::Print {
class PrintJobHelper {
public:
    static napi_value MakeJsObject(napi_env env, const PrintJob &job);
    static napi_value MakeJsSimpleObject(napi_env env, const PrintJob &job);
    static std::shared_ptr<PrintJob> BuildFromJs(napi_env env, napi_value jsValue, bool cvtToPwgSize = true);
    static std::shared_ptr<PrintJob> BuildPrintJobFromJs(napi_env env, napi_value jsValue);
    static std::shared_ptr<PrintJob> BuildJsWorkerIsLegal(napi_env env, napi_value jsValue, std::string jobId,
        uint32_t jobState, uint32_t subState, std::shared_ptr<PrintJob> &nativeObj, bool cvtToPwgSize = true);

private:
    static bool CreateFdList(napi_env env, napi_value &jsPrintJob, const PrintJob &job);
    static bool CreatePageRange(napi_env env, napi_value &jsPrintJob, const PrintJob &job);
    static bool CreatePageSize(napi_env env, napi_value &jsPrintJob, const PrintJob &job);
    static bool CreateMargin(napi_env env, napi_value &jsPrintJob, const PrintJob &job);
    static bool CreatePreview(napi_env env, napi_value &jsPrintJob, const PrintJob &job);

    static bool ValidateProperty(napi_env env, napi_value object);
    static bool ValidatePrintJobProperty(napi_env env, napi_value object);
    static bool FillPrintJobParamsFromJs(napi_env env, napi_value jsValue, PrintJobParams &params);
    static bool FillOptionalParamsFromJs(napi_env env, napi_value jsValue, PrintJobParams &params);
    static bool GetPrintPageRange(napi_env env, napi_value jsValue, PrintJobParams &params);
    static bool GetPrintMargin(napi_env env, napi_value jsValue, PrintJobParams &params);
    static bool GetPrintPreview(napi_env env, napi_value jsValue, PrintJobParams &params);
    static bool GetFileDescriptorList(napi_env env, napi_value jsValue, std::vector<uint32_t> &printFdList);
    static bool ExtractBinaryData(napi_env env, napi_value jsValue, void* &binaryData, size_t &dataLength);
};
}  // namespace OHOS::Print
#endif  // PRINT_JOB_HELPER_H
