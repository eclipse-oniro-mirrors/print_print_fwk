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

#include "scan_progress_helper.h"
#include "napi_scan_utils.h"
#include "scan_constant.h"
#include "scan_log.h"

namespace OHOS::Scan {

static constexpr const char *PARAM_SCAN_PROGRESS = "progress";
static constexpr const char *PARAM_PICTURE_FD = "pictureFd";
static constexpr const char *PARAM_IS_FINAL = "isFinal";

napi_value ScanProgressHelper::MakeJsObject(napi_env env, const ScanProgress &para)
{
    napi_value jsObj = nullptr;
    SCAN_CALL(env, napi_create_object(env, &jsObj));
    NapiScanUtils::SetInt32Property(env, jsObj, PARAM_SCAN_PROGRESS, para.GetScanProgress());
    NapiScanUtils::SetInt32Property(env, jsObj, PARAM_PICTURE_FD, para.GetScanPictureFd());
    NapiScanUtils::SetBooleanProperty(env, jsObj, PARAM_IS_FINAL, para.GetIsFinal());
    return jsObj;
}

} // namespace OHOS::Scan
