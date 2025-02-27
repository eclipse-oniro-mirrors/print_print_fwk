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

#include "scan_parameters_helper.h"
#include "napi_scan_utils.h"
#include "scan_constant.h"
#include "scan_log.h"

namespace OHOS::Scan {
static constexpr const char *PARAM_SCAN_PARA_FORMAT = "format";
static constexpr const char *PARAM_SCAN_PARA_LAST_FRAME = "lastFrame";
static constexpr const char *PARAM_SCAN_PARA_BYTES = "bytesPerLine";
static constexpr const char *PARAM_SCAN_PARA_PIXELS = "pixelsPerLine";
static constexpr const char *PARAM_SCAN_PARA_LINES = "lines";
static constexpr const char *PARAM_SCAN_PARA_DEPTH = "depth";

napi_value ScanParametersHelper::MakeJsObject(napi_env env, const ScanParameters &para)
{
    napi_value jsObj = nullptr;
    SCAN_CALL(env, napi_create_object(env, &jsObj));
    NapiScanUtils::SetUint32Property(env, jsObj, PARAM_SCAN_PARA_FORMAT, para.GetFormat());
    NapiScanUtils::SetBooleanProperty(env, jsObj, PARAM_SCAN_PARA_LAST_FRAME, para.GetLastFrame());
    NapiScanUtils::SetInt32Property(env, jsObj, PARAM_SCAN_PARA_BYTES, para.GetBytesPerLine());
    NapiScanUtils::SetInt32Property(env, jsObj, PARAM_SCAN_PARA_PIXELS, para.GetPixelsPerLine());
    NapiScanUtils::SetInt32Property(env, jsObj, PARAM_SCAN_PARA_LINES, para.GetLines());
    NapiScanUtils::SetInt32Property(env, jsObj, PARAM_SCAN_PARA_DEPTH, para.GetDepth());
    return jsObj;
}

std::shared_ptr<ScanParameters> ScanParametersHelper::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<ScanParameters>();

    if (!ValidateProperty(env, jsValue)) {
        SCAN_HILOGE("Invalid property of scan parameters");
        return nullptr;
    }

    ScanFrame format = (ScanFrame)NapiScanUtils::GetUint32Property(env, jsValue, PARAM_SCAN_PARA_FORMAT);
    nativeObj->SetFormat(format);
    bool lastFrame = NapiScanUtils::GetBooleanProperty(env, jsValue, PARAM_SCAN_PARA_LAST_FRAME);
    nativeObj->SetLastFrame(lastFrame);
    int32_t bytesPerLine = NapiScanUtils::GetInt32Property(env, jsValue, PARAM_SCAN_PARA_BYTES);
    nativeObj->SetBytesPerLine(bytesPerLine);
    int32_t pixelsPerLine = NapiScanUtils::GetInt32Property(env, jsValue, PARAM_SCAN_PARA_PIXELS);
    nativeObj->SetPixelsPerLine(pixelsPerLine);
    int32_t lines = NapiScanUtils::GetInt32Property(env, jsValue, PARAM_SCAN_PARA_LINES);
    nativeObj->SetLines(lines);
    int32_t depth = NapiScanUtils::GetInt32Property(env, jsValue, PARAM_SCAN_PARA_DEPTH);
    nativeObj->SetDepth(depth);

    SCAN_HILOGD("Build Scan Parameters succeed");
    return nativeObj;
}

bool ScanParametersHelper::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, ScanParamStatus> propertyList = {
        {PARAM_SCAN_PARA_FORMAT, SCAN_PARAM_OPT},
        {PARAM_SCAN_PARA_LAST_FRAME, SCAN_PARAM_OPT},
        {PARAM_SCAN_PARA_BYTES, SCAN_PARAM_OPT},
        {PARAM_SCAN_PARA_PIXELS, SCAN_PARAM_OPT},
        {PARAM_SCAN_PARA_LINES, SCAN_PARAM_OPT},
        {PARAM_SCAN_PARA_DEPTH, SCAN_PARAM_OPT},
    };

    auto names = NapiScanUtils::GetPropertyNames(env, object);
    for (auto name : names) {
        if (propertyList.find(name) == propertyList.end()) {
            SCAN_HILOGE("Invalid property: %{public}s", name.c_str());
            return false;
        }
        propertyList[name] = SCAN_PARAM_SET;
    }
    bool hasFormat = propertyList[PARAM_SCAN_PARA_FORMAT] == SCAN_PARAM_SET;
    bool hasFrame = propertyList[PARAM_SCAN_PARA_LAST_FRAME] == SCAN_PARAM_SET;
    bool hasBytes = propertyList[PARAM_SCAN_PARA_BYTES] == SCAN_PARAM_SET;
    bool hasPixels = propertyList[PARAM_SCAN_PARA_PIXELS] == SCAN_PARAM_SET;
    bool hasLines = propertyList[PARAM_SCAN_PARA_LINES] == SCAN_PARAM_SET;
    bool hasDepth = propertyList[PARAM_SCAN_PARA_DEPTH] == SCAN_PARAM_SET;
    
    if (!hasFormat || !hasFrame || !hasBytes || !hasPixels || !hasLines || !hasDepth) {
        return false;
    }
    return true;
}
} // namespace OHOS::Scan
