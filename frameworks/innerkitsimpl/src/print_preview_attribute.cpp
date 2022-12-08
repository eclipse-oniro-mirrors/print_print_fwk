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

#include "print_preview_attribute.h"
#include "napi_print_utils.h"
#include "print_log.h"
namespace OHOS::Print {
static constexpr const char *PARAM_PREATTRIBUTE_RANGE = "previewRange";
static constexpr const char *PARAM_PREATTRIBUTE_RESULT = "result";

PrintPreviewAttribute::PrintPreviewAttribute() : result_(PRINT_INVALID_ID) {
}

PrintPreviewAttribute::PrintPreviewAttribute(const PrintPreviewAttribute &right)
{
    hasResult_ = right.hasResult_;
    result_ = right.result_;
    previewRange_ = right.previewRange_;
}

PrintPreviewAttribute &PrintPreviewAttribute::operator=(const PrintPreviewAttribute &right)
{
    if (this != &right) {
        hasResult_ = right.hasResult_;
        result_ = right.result_;
        previewRange_ = right.previewRange_;
    }
    return *this;
}

PrintPreviewAttribute::~PrintPreviewAttribute()
{
}

void PrintPreviewAttribute::Reset()
{
    hasResult_ = false;
    result_ = PRINT_INVALID_ID;
    previewRange_.Reset();
}

void PrintPreviewAttribute::SetResult(uint32_t result)
{
    hasResult_ = true;
    result_ = result;
}

void PrintPreviewAttribute::SetPreviewRange(const PrintRange &previewRange)
{
    previewRange_ = previewRange;
}

uint32_t  PrintPreviewAttribute::GetResult() const
{
    return result_;
}

void PrintPreviewAttribute::GetPreviewRange(PrintRange &previewRange) const
{
    previewRange = previewRange_;
}

bool PrintPreviewAttribute::ReadFromParcel(Parcel &parcel)
{
    hasResult_ = parcel.ReadBool();
    if (hasResult_) {
        SetResult(parcel.ReadUint32());
    }
    auto rangePtr = PrintRange::Unmarshalling(parcel);
    if (rangePtr == nullptr) {
        return false;
    }
    SetPreviewRange(*rangePtr);
    return true;
}

bool PrintPreviewAttribute::Marshalling(Parcel &parcel) const
{
    parcel.WriteBool(hasResult_);
    if (hasResult_) {
        parcel.WriteUint32(GetResult());
    }
    if (!previewRange_.Marshalling(parcel)) {
        PRINT_HILOGE("Failed to marshalling preview attribute object");
        return false;
    }
    return true;
}

std::shared_ptr<PrintPreviewAttribute> PrintPreviewAttribute::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintPreviewAttribute>();
    if (nativeObj == nullptr) {
        PRINT_HILOGE("Failed to create print preview attribute object");
        return nullptr;
    }
    if (!nativeObj->ReadFromParcel(parcel)) {
        PRINT_HILOGE("Failed to unmarshalling print preview attribute");
        return nullptr;
    }
    return nativeObj;
}

napi_value PrintPreviewAttribute::ToJsObject(napi_env env) const
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));

    if (hasResult_) {
        NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_PREATTRIBUTE_RESULT, GetResult());
    }

    napi_value jsPreviewRange = previewRange_.ToJsObject(env);
    PRINT_CALL(env, napi_set_named_property(env, jsObj, PARAM_PREATTRIBUTE_RANGE, jsPreviewRange));
    return jsObj;
}

std::shared_ptr<PrintPreviewAttribute> PrintPreviewAttribute::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PrintPreviewAttribute>();
    if (nativeObj == nullptr) {
        PRINT_HILOGE("Failed to create print preview attribute object");
        return nullptr;
    }

    if (!ValidateProperty(env, jsValue)) {
        PRINT_HILOGE("Invalid property of print preview attribute");
        return nullptr;
    }
    
    napi_value jsPreviewRange = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_PREATTRIBUTE_RANGE);
    auto previewRangePtr = PrintRange::BuildFromJs(env, jsPreviewRange);
    if (previewRangePtr == nullptr) {
        PRINT_HILOGE("Failed to build print preview attribute object from js");
        return nullptr;
    }
    nativeObj->SetPreviewRange(*previewRangePtr);

    napi_value jsResult = NapiPrintUtils::GetNamedProperty(env, jsValue, PARAM_PREATTRIBUTE_RANGE);
    if (jsResult != nullptr) {
        auto result = NapiPrintUtils::GetUint32FromValue(env, jsResult);
        nativeObj->SetResult(result);
    }
    PRINT_HILOGE("Build Print Preview Attribute succeed");
    return nativeObj;
}

bool PrintPreviewAttribute::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_PREATTRIBUTE_RANGE, PRINT_PARAM_NOT_SET},
        {PARAM_PREATTRIBUTE_RESULT, PRINT_PARAM_OPT},
    };
    
    auto names = NapiPrintUtils::GetPropertyNames(env, object);
    for (auto name : names) {
        if (propertyList.find(name) == propertyList.end()) {
            PRINT_HILOGE("Invalid property: %{public}s", name.c_str());
            return false;
        }
        propertyList[name] = PRINT_PARAM_SET;
    }

    for (auto propertypItem : propertyList) {
        if (propertypItem.second == PRINT_PARAM_NOT_SET) {
            PRINT_HILOGE("Missing Property: %{public}s", propertypItem.first.c_str());
            return false;
        }
    }

    return true;
}

void PrintPreviewAttribute::Dump()
{
    if (hasResult_) {
        PRINT_HILOGD("result_: %{public}d", result_);
    }

    previewRange_.Dump();
}
} // namespace OHOS::Print
