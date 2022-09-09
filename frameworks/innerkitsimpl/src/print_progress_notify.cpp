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

#include "print_progress_notify.h"

#include <uv.h>

#include "napi_print_utils.h"
#include "print_job.h"
#include "print_log.h"
#include "print_page_size.h"
#include "print_resolution.h"
#include "printer_capability.h"
#include "printer_info.h"

namespace OHOS::Print {
PrintProgressNotify::PrintProgressNotify(napi_env env, const std::string &type, napi_ref ref)
    : PrintBaseNotify(env, type, ref)
{}

PrintProgressNotify::~PrintProgressNotify()
{
    PRINT_HILOGD("");
}

void PrintProgressNotify::DataReadInfo(PrinterInfo &info, MessageParcel &data)
{
    PRINT_HILOGD("");
}

void PrintProgressNotify::DataReadJob(PrintJob &job, MessageParcel &data)
{
    PRINT_HILOGD("");
}

void PrintProgressNotify::WriteInfoJsObject(napi_env env, PrinterInfo info, napi_value *result)
{
    PRINT_HILOGD("");
}

void PrintProgressNotify::OnCallBack(MessageParcel &data)
{
    PRINT_HILOGD("");
}
} // namespace OHOS::Print