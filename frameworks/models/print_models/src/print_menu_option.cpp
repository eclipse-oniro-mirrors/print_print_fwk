/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "print_menu_option.h"
#include "print_log.h"

namespace OHOS::Print {
PrintMenuOption::PrintMenuOption() : menuItemResourceName_(""), isSelect_(false) {
}

PrintMenuOption::PrintMenuOption(const PrintMenuOption &right)
{
    SetMenuItemResourceName(right.menuItemResourceName_);
    SetIsSelect(right.isSelect_);
}

PrintMenuOption &PrintMenuOption::operator=(const PrintMenuOption &right)
{
    if (this != &right) {
        SetMenuItemResourceName(right.menuItemResourceName_);
        SetIsSelect(right.isSelect_);
    }
    return *this;
}

PrintMenuOption::~PrintMenuOption()
{
}

void PrintMenuOption::Reset()
{
    SetMenuItemResourceName("");
    SetIsSelect(false);
}

const std::string &PrintMenuOption::GetMenuItemResourceName() const
{
    return menuItemResourceName_;
}

bool PrintMenuOption::GetIsSelect() const
{
    return isSelect_;
}

void PrintMenuOption::SetMenuItemResourceName(const std::string &menuItemResourceName)
{
    menuItemResourceName_ = menuItemResourceName;
}

void PrintMenuOption::SetIsSelect(const bool isSelect)
{
    isSelect_ = isSelect;
}

void PrintMenuOption::ReadFromParcel(Parcel &parcel)
{
    SetMenuItemResourceName(parcel.ReadString());
    SetIsSelect(parcel.ReadBool());
}

bool PrintMenuOption::Marshalling(Parcel &parcel) const
{
    parcel.WriteString(GetMenuItemResourceName());
    parcel.WriteBool(GetIsSelect());
    return true;
}

std::shared_ptr<PrintMenuOption> PrintMenuOption::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintMenuOption>();
    nativeObj->ReadFromParcel(parcel);
    return nativeObj;
}

void PrintMenuOption::Dump() const
{
    PRINT_HILOGD("menuItemResourceName_ = %{public}s", menuItemResourceName_.c_str());
    PRINT_HILOGD("isSelect_ = %{public}d", isSelect_);
}

Json::Value PrintMenuOption::ConvertToJsonObject() const
{
    Json::Value jsonObject;
    jsonObject["menuItemResourceName"] = menuItemResourceName_;
    jsonObject["isSelect"] = isSelect_;
    return jsonObject;
}
} // namespace OHOS::Print
