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

#ifndef PRINT_CUSTOM_OPTION_H
#define PRINT_CUSTOM_OPTION_H

#include "parcel.h"
#include <json/json.h>
#include <string>
#include <vector>
#include "print_menu_option.h"

namespace OHOS::Print {
enum class ComponentType {
    SWITCH = 0,
    MENU = 1
};
class PrintCustomOption final : public Parcelable {
public:
    explicit PrintCustomOption();

    PrintCustomOption(const PrintCustomOption &right);

    void Set(const PrintCustomOption &right);

    PrintCustomOption &operator=(const PrintCustomOption &right);

    virtual ~PrintCustomOption();

    void Reset();

    [[nodiscard]] const std::string &GetOptionName() const;
    
    [[nodiscard]] const uint32_t &GetType() const;
    
    [[nodiscard]] const std::string &GetBundleName() const;
    
    [[nodiscard]] const std::string &GetOptionResourceName() const;
    
    [[nodiscard]] bool HasValue() const;

    void GetMenuOption(std::vector<PrintMenuOption> &menuOption) const;

    [[nodiscard]] bool GetIsSelect() const;

    [[nodiscard]] bool HasErrorResourceName() const;

    [[nodiscard]] const std::string &GetErrorResourceName() const;
    
    void SetOptionName(const std::string &optionName);
    
    void SetType(const uint32_t &type);
    
    void SetBundleName(const std::string &bundleName);
    
    void SetOptionResourceName(const std::string &optionResourceName);
    
    void SetMenuOption(const std::vector<PrintMenuOption>& menuOption);
    
    void SetIsSelect(const bool isSelect);
    
    void SetErrorResourceName(const std::string &errorResourceName);

    virtual bool Marshalling(Parcel &parcel) const override;

    static std::shared_ptr<PrintCustomOption> Unmarshalling(Parcel &parcel);

    void Dump();

    Json::Value ConvertToJsonObject() const;

private:
    void ReadFromParcel(Parcel &parcel);

private:
    std::string optionName_;
    uint32_t type_;
    std::string bundleName_;
    std::string optionResourceName_;
    bool hasValue_;
    std::vector<PrintMenuOption> menuOption_;
    bool isSelect_;
    bool hasErrorResourceName_;
    std::string errorResourceName_;
};
}  // namespace OHOS::Print
#endif  // PRINT_CUSTOM_OPTION_H
