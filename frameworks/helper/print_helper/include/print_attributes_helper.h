/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef PRINT_ATTRIBUTE_HELPER_H
#define PRINT_ATTRIBUTE_HELPER_H

#include <map>
#include "napi/native_api.h"
#include "print_job.h"
#include "napi_print_utils.h"
#include "print_constant.h"
#include "print_margin_helper.h"
#include "print_preview_attribute_helper.h"
#include "print_page_size_helper.h"
#include "print_range_helper.h"

namespace OHOS::Print {
class PrintAttributesHelper {
public:
    static napi_value MakeJsObject(napi_env env, const PrintAttributes &attributes);
    static std::shared_ptr<PrintAttributes> BuildFromJs(napi_env env, napi_value jsValue);
    static void BuildJsWorkerIsLegal(napi_env env, napi_value jsValue, std::shared_ptr<PrintAttributes> &nativeObj);

private:
    static bool CreatePageRange(napi_env env, napi_value &jsPrintAttributes, const PrintAttributes &attributes);
    static bool CreatePageSize(napi_env env, napi_value &jsPrintAttributes, const PrintAttributes &attributes);
    static bool CreateMargin(napi_env env, napi_value &jsPrintAttributes, const PrintAttributes &attributes);

    static bool ValidateProperty(napi_env env, napi_value object);
    static void BuildFromJsPageSize(napi_env env, napi_value jsValue, std::shared_ptr<PrintAttributes> &nativeObj);
};
}  // namespace OHOS::Print
#endif  // PRINT_ATTRIBUTE_HELPER_H