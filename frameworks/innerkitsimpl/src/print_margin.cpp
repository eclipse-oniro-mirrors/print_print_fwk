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

#include "print_margin.h"
#include "napi_print_utils.h"
#include "print_log.h"

namespace OHOS::Print {
static constexpr const char *PARAM_MARGIN_TOP = "top";
static constexpr const char *PARAM_MARGIN_BOTTOM = "bottom";
static constexpr const char *PARAM_MARGIN_LEFT = "left";
static constexpr const char *PARAM_MARGIN_RIGHT = "right";

PrintMargin::PrintMargin() : top_(0), bottom_(0), left_(0), right_(0) {}

PrintMargin::PrintMargin(const PrintMargin &right)
{
    top_ = right.top_;
    bottom_ = right.bottom_;
    left_ = right.left_;
    right_ = right.right_;
}

PrintMargin &PrintMargin::operator=(const PrintMargin &right)
{
    if (this != &right) {
        top_ = right.top_;
        bottom_ = right.bottom_;
        left_ = right.left_;
        right_ = right.right_;
    }
    return *this;
}

PrintMargin::~PrintMargin()
{
}

void PrintMargin::Reset()
{
    SetTop(0);
    SetBottom(0);
    SetLeft(0);
    SetRight(0);
}

void PrintMargin::SetTop(uint32_t top)
{
    top_ = top;
}

void PrintMargin::SetBottom(uint32_t bottom)
{
    bottom_ = bottom;
}

void PrintMargin::SetLeft(uint32_t left)
{
    left_ = left;
}

void PrintMargin::SetRight(uint32_t right)
{
    right_ = right;
}

uint32_t PrintMargin::GetTop() const
{
    return top_;
}

uint32_t PrintMargin::GetBottom() const
{
    return bottom_;
}

uint32_t PrintMargin::GetLeft() const
{
    return left_;
}

uint32_t PrintMargin::GetRight() const
{
    return right_;
}

bool PrintMargin::ReadFromParcel(Parcel &parcel)
{
    SetTop(parcel.ReadUint32());
    SetBottom(parcel.ReadUint32());
    SetLeft(parcel.ReadUint32());
    SetRight(parcel.ReadUint32());
    return true;
}

bool PrintMargin::Marshalling(Parcel &parcel) const
{
    parcel.WriteUint32(GetTop());
    parcel.WriteUint32(GetBottom());
    parcel.WriteUint32(GetLeft());
    parcel.WriteUint32(GetRight());
    return true;
}

std::shared_ptr<PrintMargin> PrintMargin::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintMargin>();
    if (nativeObj == nullptr) {
        PRINT_HILOGE("Failed to create print margin object");
        return nullptr;
    }
    if (!nativeObj->ReadFromParcel(parcel)) {
        PRINT_HILOGE("Failed to unmarshalling print margin");
        return nullptr;
    }
    return nativeObj;
}

napi_value PrintMargin::ToJsObject(napi_env env) const
{
    napi_value jsObj = nullptr;
    PRINT_CALL(env, napi_create_object(env, &jsObj));
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_MARGIN_TOP, GetTop());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_MARGIN_BOTTOM, GetBottom());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_MARGIN_LEFT, GetLeft());
    NapiPrintUtils::SetUint32Property(env, jsObj, PARAM_MARGIN_RIGHT, GetRight());
    return jsObj;    
}

std::shared_ptr<PrintMargin> PrintMargin::BuildFromJs(napi_env env, napi_value jsValue)
{
    auto nativeObj = std::make_shared<PrintMargin>();
    if (nativeObj == nullptr) {
        PRINT_HILOGE("Failed to create print margin object");
        return nullptr;
    }

    if (!ValidateProperty(env, jsValue)) {
        PRINT_HILOGE("Invalid property of print margin");
        return nullptr;
    }

    uint32_t top = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_MARGIN_TOP);
    uint32_t bottom = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_MARGIN_BOTTOM);
    uint32_t left = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_MARGIN_LEFT);
    uint32_t right = NapiPrintUtils::GetUint32Property(env, jsValue, PARAM_MARGIN_RIGHT);
    
    nativeObj->SetTop(top);
    nativeObj->SetBottom(bottom);
    nativeObj->SetLeft(left);
    nativeObj->SetRight(right);
    PRINT_HILOGE("Build Print Margin succeed");    
    return nativeObj;
}

bool PrintMargin::ValidateProperty(napi_env env, napi_value object)
{
    std::map<std::string, PrintParamStatus> propertyList = {
        {PARAM_MARGIN_TOP, PRINT_PARAM_OPT},
        {PARAM_MARGIN_BOTTOM, PRINT_PARAM_OPT},
        {PARAM_MARGIN_LEFT, PRINT_PARAM_OPT},
        {PARAM_MARGIN_RIGHT, PRINT_PARAM_OPT},
    };

    auto names = NapiPrintUtils::GetPropertyNames(env, object);
    for (auto name : names) {
        if (propertyList.find(name) == propertyList.end()) {
            PRINT_HILOGE("Invalid property: %{public}s", name.c_str());
            return false;
        }
        propertyList[name] = PRINT_PARAM_SET;
    }

    return true;
}

void PrintMargin::Dump()
{
    PRINT_HILOGD("top_ = %{public}d", top_);
    PRINT_HILOGD("bottom_ = %{public}d", bottom_);
    PRINT_HILOGD("left_ = %{public}d", left_);
    PRINT_HILOGD("right_ = %{public}d", right_);
}
} // namespace OHOS::Print
