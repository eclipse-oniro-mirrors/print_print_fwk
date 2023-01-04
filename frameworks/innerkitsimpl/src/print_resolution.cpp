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

#include "print_resolution.h"
#include "napi_print_utils.h"
#include "print_log.h"

namespace OHOS::Print {
static constexpr const char *PARAM_RESOLUTION_ID = "id";
static constexpr const char *PARAM_RESOLUTION_HORIZONTALDPI = "horizontalDpi";
static constexpr const char *PARAM_RESOLUTION_VERTICALDPI = "verticalDpi";

PrintResolution::PrintResolution() : id_(""), horizontalDpi_(0), verticalDpi_(0) {
}

PrintResolution::PrintResolution(const PrintResolution &right)
{
    SetId(right.id_);
    SetHorizontalDpi(right.horizontalDpi_);
    SetVerticalDpi(right.verticalDpi_);
}

PrintResolution &PrintResolution::operator=(const PrintResolution &right)
{
    if (this != &right) {
        SetId(right.id_);
        SetHorizontalDpi(right.horizontalDpi_);
        SetVerticalDpi(right.verticalDpi_);
    }
    return *this;
}

PrintResolution::~PrintResolution()
{
}

void PrintResolution::Reset()
{
    SetId("");
    SetHorizontalDpi(0);
    SetVerticalDpi(0);
}

void PrintResolution::SetId(const std::string &id)
{
    id_ = id;
}

void PrintResolution::SetHorizontalDpi(uint32_t horizontalDpi)
{
    horizontalDpi_ = horizontalDpi;
}

void PrintResolution::SetVerticalDpi(uint32_t verticalDpi)
{
    verticalDpi_ = verticalDpi;
}

const std::string &PrintResolution::GetId() const
{
    return id_;
}

uint32_t PrintResolution::GetHorizontalDpi() const
{
    return horizontalDpi_;
}

uint32_t PrintResolution::GetVerticalDpi() const
{
    return verticalDpi_;
}

bool PrintResolution::ReadFromParcel(Parcel &parcel)
{
    SetId(parcel.ReadString());
    SetHorizontalDpi(parcel.ReadUint32());
    SetVerticalDpi(parcel.ReadUint32());
    return true;
}

bool PrintResolution::Marshalling(Parcel &parcel) const
{
    parcel.WriteString(GetId());
    parcel.WriteUint32(GetHorizontalDpi());
    parcel.WriteUint32(GetVerticalDpi());
    return true;
}

std::shared_ptr<PrintResolution> PrintResolution::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintResolution>();
    if (nativeObj == nullptr) {
        PRINT_HILOGE("Failed to create print resolution object");
        return nullptr;
    }
    if (!nativeObj->ReadFromParcel(parcel)) {
        PRINT_HILOGE("Failed to unmarshalling print resolution");
        return nullptr;
    }
    return nativeObj;
}

napi_value PrintResolution::ToJsObject(napi_env env) const
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));
    NapiPrintUtils::SetStringPropertyUtf8(env, jsObj, PARAM_RESOLUTION_ID, GetId());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_RESOLUTION_HORIZONTALDPI, GetHorizontalDpi());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_RESOLUTION_VERTICALDPI, GetVerticalDpi());
    return jsObj;
}

std::shared_ptr<PrintResolution> PrintResolution::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PrintResolution>();
    if (nativeObj == nullptr) {
        PRINT_HILOGE("Failed to create print range object");
        return nullptr;
    }

    if (!ValidateProperty(env, jsValue)) {
        PRINT_HILOGE("Invalid property of print resolution");
        return nullptr;
    }

    std::string id = NapiPrintUtils::GetStringPropertyUtf8(env, jsValue, PARAM_RESOLUTION_ID);
    uint32_t horizontalDpi = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_RESOLUTION_HORIZONTALDPI);
    uint32_t verticalDpi = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_RESOLUTION_VERTICALDPI);

    if (id == "") {
        PRINT_HILOGE("Invalid resolution id");
        return nullptr;
    }

    nativeObj->SetId(id);
    nativeObj->SetHorizontalDpi(horizontalDpi);
    nativeObj->SetVerticalDpi(verticalDpi);
    return nativeObj;
}

bool PrintResolution::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_RESOLUTION_ID, PRINT_PARAM_NOT_SET},
        {PARAM_RESOLUTION_HORIZONTALDPI, PRINT_PARAM_NOT_SET},
        {PARAM_RESOLUTION_VERTICALDPI, PRINT_PARAM_NOT_SET},
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

void PrintResolution::Dump()
{
    PRINT_HILOGD("id_ = %{public}s", id_.c_str());
    PRINT_HILOGD("horizontalDpi_ = %{public}d", horizontalDpi_);
    PRINT_HILOGD("verticalDpi_ = %{public}d", verticalDpi_);
}
} // namespace OHOS::Print
