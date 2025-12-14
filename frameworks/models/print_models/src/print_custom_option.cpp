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

#include "print_custom_option.h"
#include "print_log.h"
#include "print_utils.h"

namespace OHOS::Print {
PrintCustomOption::PrintCustomOption() : optionName_(""), type_(0), bundleName_(""), optionResourceName_(""),
    hasValue_(false), isSelect_(false), hasErrorResourceName_(false), errorResourceName_("") {
    menuOption_.clear();
}

PrintCustomOption::PrintCustomOption(const PrintCustomOption &right)
{
    Set(right);
}

void PrintCustomOption::Set(const PrintCustomOption &right)
{
    optionName_ = right.optionName_;
    type_ = right.type_;
    bundleName_ = right.bundleName_;
    optionResourceName_ = right.optionResourceName_;
    hasValue_ = right.hasValue_;
    menuOption_.assign(right.menuOption_.begin(), right.menuOption_.end());
    isSelect_ = right.isSelect_;
    hasErrorResourceName_ = right.hasErrorResourceName_;
    errorResourceName_ = right.errorResourceName_;
}

PrintCustomOption &PrintCustomOption::operator=(const PrintCustomOption &right)
{
    if (this != &right) {
        Set(right);
    }
    return *this;
}

PrintCustomOption::~PrintCustomOption()
{
}

void PrintCustomOption::Reset()
{
    optionName_ = "";
    type_ = 0;
    bundleName_ = "";
    optionResourceName_ = "";
    hasValue_ = false;
    menuOption_.clear();
    isSelect_ = false;
    hasErrorResourceName_ = false;
    errorResourceName_ = "";
}

void PrintCustomOption::SetOptionName(const std::string &optionName)
{
    optionName_ = optionName;
}

void PrintCustomOption::SetType(const uint32_t &type)
{
    type_ = type;
}

void PrintCustomOption::SetBundleName(const std::string &bundleName)
{
    bundleName_ = bundleName;
}

void PrintCustomOption::SetOptionResourceName(const std::string &optionResourceName)
{
    optionResourceName_ = optionResourceName;
}

void PrintCustomOption::SetMenuOption(const std::vector<PrintMenuOption> &menuOption)
{
    hasValue_ = true;
    menuOption_.assign(menuOption.begin(), menuOption.end());
}

void PrintCustomOption::SetIsSelect(const bool isSelect)
{
    hasValue_ = true;
    isSelect_ = isSelect;
}

void PrintCustomOption::SetErrorResourceName(const std::string &errorResourceName)
{
    hasErrorResourceName_ = true;
    errorResourceName_ = errorResourceName;
}

const std::string &PrintCustomOption::GetOptionName() const
{
    return optionName_;
}

const uint32_t &PrintCustomOption::GetType() const
{
    return type_;
}

const std::string &PrintCustomOption::GetBundleName() const
{
    return bundleName_;
}

const std::string &PrintCustomOption::GetOptionResourceName() const
{
    return optionResourceName_;
}

bool PrintCustomOption::HasValue() const
{
    return hasValue_;
}

void PrintCustomOption::GetMenuOption(std::vector<PrintMenuOption> &menuOption) const
{
    menuOption.assign(menuOption_.begin(), menuOption_.end());
}

bool PrintCustomOption::GetIsSelect() const
{
    return isSelect_;
}

bool PrintCustomOption::HasErrorResourceName() const
{
    return hasErrorResourceName_;
}

const std::string &PrintCustomOption::GetErrorResourceName() const
{
    return errorResourceName_;
}

void PrintCustomOption::ReadFromParcel(Parcel &parcel)
{
    if (parcel.GetReadableBytes() == 0) {
        PRINT_HILOGE("no data in parcel");
        return;
    }
    SetOptionName(parcel.ReadString());
    SetType(parcel.ReadUint32());
    SetBundleName(parcel.ReadString());
    SetOptionResourceName(parcel.ReadString());
    hasValue_ = parcel.ReadBool();
    if (hasValue_) {
        ReadValueFromParcel(parcel);
    }
    hasErrorResourceName_ = parcel.ReadBool();
    if (hasErrorResourceName_) {
        SetErrorResourceName(parcel.ReadString());
    }
}

void PrintCustomOption::ReadValueFromParcel(Parcel &parcel) {
    if (static_cast<ComponentType>(type_) == ComponentType::SWITCH) {
        SetIsSelect(parcel.ReadBool());
    } else if (static_cast<ComponentType>(type_) == ComponentType::MENU) {
        PrintUtils::readListFromParcel<PrintMenuOption>(parcel, menuOption_,
            [](Parcel& p) -> std::optional<PrintMenuOption> {
                auto ptr = PrintMenuOption::Unmarshalling(p);
                if (ptr) {
                    return std::optional<PrintMenuOption>(*ptr);
                }
                return std::nullopt;
            });
    }
}

bool PrintCustomOption::Marshalling(Parcel &parcel) const
{
    parcel.WriteString(GetOptionName());
    parcel.WriteUint32(GetType());
    parcel.WriteString(GetBundleName());
    parcel.WriteString(GetOptionResourceName());
    parcel.WriteBool(hasValue_);
    if (hasValue_) {
        if (static_cast<ComponentType>(type_) == ComponentType::SWITCH) {
            parcel.WriteBool(GetIsSelect());
        } else if (static_cast<ComponentType>(type_) == ComponentType::MENU) {
            PrintUtils::WriteListToParcel(
                parcel, menuOption_, [](Parcel &p, const PrintMenuOption &item) { item.Marshalling(p); });
        }
    }
    parcel.WriteBool(hasErrorResourceName_);
    if (hasErrorResourceName_) {
        parcel.WriteString(GetErrorResourceName());
    }
    return true;
}

std::shared_ptr<PrintCustomOption> PrintCustomOption::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintCustomOption>();
    nativeObj->ReadFromParcel(parcel);
    return nativeObj;
}

void PrintCustomOption::Dump()
{
    PRINT_HILOGD("optionName_ = %{public}s", optionName_.c_str());
    PRINT_HILOGD("type_ = %{public}d", type_);
    PRINT_HILOGD("bundleName_ = %{public}s", bundleName_.c_str());
    PRINT_HILOGD("optionResourceName_ = %{public}s", optionResourceName_.c_str());
    if (hasValue_) {
        if (static_cast<ComponentType>(type_) == ComponentType::SWITCH) {
            PRINT_HILOGD("isSelect_ = %{public}d", isSelect_);
        } else if (static_cast<ComponentType>(type_) == ComponentType::MENU) {
            for (auto menuOptionItem : menuOption_) {
                menuOptionItem.Dump();
            }
        }
    }
    if (hasErrorResourceName_) {
        PRINT_HILOGD("errorResourceName_ = %{public}s", errorResourceName_.c_str());
    }
}

Json::Value PrintCustomOption::ConvertToJsonObject() const
{
    Json::Value jsonObject;
    jsonObject["optionName"] = optionName_;
    jsonObject["type"] = type_;
    jsonObject["bundleName"] = bundleName_;
    jsonObject["optionResourceName"] = optionResourceName_;
    if (hasValue_) {
        if (static_cast<ComponentType>(type_) == ComponentType::SWITCH) {
            jsonObject["value"] = isSelect_;
        } else if (static_cast<ComponentType>(type_) == ComponentType::MENU) {
            Json::Value jsonArray;
            for (const auto& item : menuOption_) {
                jsonArray.append(item.ConvertToJsonObject());
            }
            jsonObject["value"] = jsonArray;
        }
    }
    if (hasErrorResourceName_) {
        jsonObject["errorResourceName"] = errorResourceName_;
    }
    return jsonObject;
}
} // namespace OHOS::Print
