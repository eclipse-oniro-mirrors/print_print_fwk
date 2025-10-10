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

#ifndef PRINT_FWK_PPD_INFO_H
#define PRINT_FWK_PPD_INFO_H
#define TDD_ENABLE 1

#include "parcel.h"
#include "printer_capability.h"
#include "printer_preferences.h"

namespace OHOS::Print {
class PpdInfo final : public Parcelable {
public:
    void SetManufacturer(const std::string &manufacturer);

    void SetNickName(const std::string &nickName);

    void SetPpdName(const std::string &ppdName);

    void SetPpdInfo(const std::string &manufacturer, const std::string &nickName, const std::string &ppdName);

    std::string GetManufacturer() const;

    std::string GetNickName() const;

    std::string GetPpdName() const;

    bool ReadFromParcel(Parcel &parcel);

    virtual bool Marshalling(Parcel &parcel) const override;

    static std::shared_ptr<PpdInfo> Unmarshalling(Parcel &parcel);

private:

    std::string manufacturer_;
    std::string nickName_;
    std::string ppdName_;
   
};
}  // namespace OHOS::Print
#endif  // PRINTER_INFO_H
