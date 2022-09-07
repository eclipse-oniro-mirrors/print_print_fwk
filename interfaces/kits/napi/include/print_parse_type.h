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

#ifndef PARSE_TYPE_H
#define PARSE_TYPE_H

#include <string>
#include <vector>

#include "async_call.h"
#include "napi/native_api.h"
#include "noncopyable.h"
#include "print_job.h"
#include "print_page_size.h"
#include "print_resolution.h"
#include "print_task.h"
#include "printer_capability.h"
#include "printer_info.h"

namespace OHOS::Print {
class ParseType {
public:
    static bool ParseInfo(napi_env env, napi_value InfoValue, PrinterInfo &Info);
    static bool ParseCapability(napi_env env, napi_value InfoValue, PrinterCapability &capability);
    static bool ParsePageSize(napi_env env, napi_value capValue, PrintPageSize &PrintPageSize);
    static bool ParseResolution(napi_env env, napi_value reValue, PrintResolution &PrintResolution);
    static bool ParseMargin(napi_env env, napi_value marginValue, PrintMargin &PrintMargin);
    static bool ParseJob(napi_env env, napi_value jobValue, PrintJob &printJob);
    static bool ParsePreviewAttribute(napi_env env, napi_value preAttValue, PreviewAttribute &preAtt);
    static bool ParseRange(napi_env env, napi_value preAttValue, PrintRange &range);

    static bool ParseInfoParam(napi_env env, napi_value InfoValue, PrinterInfo &info);
    static bool ParseCapParam(napi_env env, napi_value InfoValue, PrinterCapability &capability);
    static bool ParsePageSizeParam(napi_env env, napi_value capValue, PrintPageSize &PrintPageSize);
    static bool ParseResolutionParam(napi_env env, napi_value reValue, PrintResolution &PrintResolution);
    static bool ParseMarginParam(napi_env env, napi_value marginValue, PrintMargin &PrintMargin);
    static bool ParseJobParam(napi_env env, napi_value jobValue, PrintJob &printJob);
    static bool ParsePreviewAttributeParam(napi_env env, napi_value preAttValue, PreviewAttribute &preAtt);
    static bool ParseRangeParam(napi_env env, napi_value preAttValue, PrintRange &range);

private:
    struct ParseTypeContext : public AsyncCall::Context {};
};
} // namespace OHOS::Print
#endif // PARSE_TYPE_H