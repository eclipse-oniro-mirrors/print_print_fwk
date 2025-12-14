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

#ifndef PRINT_MENU_OPTION_H
#define PRINT_MENU_OPTION_H

#include <string>
#include <json/json.h>
#include "parcel.h"

namespace OHOS::Print {
class PrintMenuOption final : public Parcelable {
public:
    explicit PrintMenuOption();

    PrintMenuOption(const PrintMenuOption &right);

    PrintMenuOption &operator=(const PrintMenuOption &right);

    virtual ~PrintMenuOption();

    void Reset();

    [[nodiscard]] const std::string &GetMenuItemResourceName() const;

    [[nodiscard]] bool GetIsSelect() const;

    void SetMenuItemResourceName(const std::string &menuItemResourceName);

    void SetIsSelect(const bool isSelect);

    virtual bool Marshalling(Parcel &parcel) const override;

    static std::shared_ptr<PrintMenuOption> Unmarshalling(Parcel &parcel);

    void Dump() const;

    Json::Value ConvertToJsonObject() const;

private:
    void ReadFromParcel(Parcel &parcel);

private:
    std::string menuItemResourceName_;
    bool isSelect_;
};
}  // namespace OHOS::Print
#endif  // PRINT_MENU_OPTION_H
