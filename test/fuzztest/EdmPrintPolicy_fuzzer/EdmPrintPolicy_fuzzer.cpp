/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "EdmPrintPolicy_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "edm_print_policy_manager.h"
#include "print_job.h"
#include "printer_info.h"

namespace OHOS {
namespace Print {

namespace {

const uint8_t DO_INIT_PRINT_POLICY = 0;
const uint8_t DO_UPDATE_PRINT_POLICY = 1;
const uint8_t DO_IS_PRINT_JOB_ALLOWED_EDM = 2;
const uint8_t DO_IS_PRINTER_ALLOWED_EDM = 3;
const uint8_t DO_ON_USER_SWITCHED = 4;
const uint8_t DO_ON_CURRENT_USER_REMOVED = 5;
const uint8_t TARGET_SIZE = 6;
constexpr size_t MAX_ID_LENGTH = 64;
constexpr size_t MAX_STRING_LENGTH = 256;

void DoInitPrintPolicy(FuzzedDataProvider &fdp)
{
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    EdmPrintPolicyManager::GetInstance().InitPrintPolicyFromEdm(userId);
}

void DoUpdatePrintPolicy(FuzzedDataProvider &fdp)
{
    std::string eventData = fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH);
    EdmPrintPolicyManager::GetInstance().UpdatePrintPolicyFromEdm(eventData);
}

void DoIsPrintJobAllowedEdm(FuzzedDataProvider &fdp)
{
    PrintJob printJob;
    printJob.SetJobId(fdp.ConsumeRandomLengthString(MAX_ID_LENGTH));
    printJob.SetPrinterId(fdp.ConsumeRandomLengthString(MAX_ID_LENGTH));
    printJob.SetOption(fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH));
    EdmPrintPolicyManager::GetInstance().IsPrintJobAllowedEdm(printJob);
}

void DoIsPrinterAllowedEdm(FuzzedDataProvider &fdp)
{
    PrinterInfo printerInfo;
    printerInfo.SetUri(fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH));
    printerInfo.SetOption(fdp.ConsumeRandomLengthString(MAX_STRING_LENGTH));
    EdmPrintPolicyManager::GetInstance().IsPrinterAllowedEdm(printerInfo);
}

void DoOnUserSwitched(FuzzedDataProvider &fdp)
{
    int32_t newUserId = fdp.ConsumeIntegral<int32_t>();
    EdmPrintPolicyManager::GetInstance().OnUserSwitched(newUserId);
}

void DoOnCurrentUserRemoved(FuzzedDataProvider &fdp)
{
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    EdmPrintPolicyManager::GetInstance().OnCurrentUserRemoved(userId);
}

} // namespace

} // namespace Print
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < 1) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    uint8_t tarPos = fdp.ConsumeIntegral<uint8_t>() % OHOS::Print::TARGET_SIZE;
    switch (tarPos) {
        case OHOS::Print::DO_INIT_PRINT_POLICY:
            OHOS::Print::DoInitPrintPolicy(fdp);
            break;
        case OHOS::Print::DO_UPDATE_PRINT_POLICY:
            OHOS::Print::DoUpdatePrintPolicy(fdp);
            break;
        case OHOS::Print::DO_IS_PRINT_JOB_ALLOWED_EDM:
            OHOS::Print::DoIsPrintJobAllowedEdm(fdp);
            break;
        case OHOS::Print::DO_IS_PRINTER_ALLOWED_EDM:
            OHOS::Print::DoIsPrinterAllowedEdm(fdp);
            break;
        case OHOS::Print::DO_ON_USER_SWITCHED:
            OHOS::Print::DoOnUserSwitched(fdp);
            break;
        case OHOS::Print::DO_ON_CURRENT_USER_REMOVED:
            OHOS::Print::DoOnCurrentUserRemoved(fdp);
            break;
        default:
            return 0;
    }
    return 0;
}
