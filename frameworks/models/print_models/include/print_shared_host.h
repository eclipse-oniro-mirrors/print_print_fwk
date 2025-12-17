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

#ifndef PRINT_SHARED_HOST_H
#define PRINT_SHARED_HOST_H

#include "parcel.h"

namespace OHOS::Print {
class PrintSharedHost final : public Parcelable {
public:
    PrintSharedHost() = default;

    ~PrintSharedHost() = default;

    PrintSharedHost& operator=(const PrintSharedHost &right) = default;

    void SetIp(const std::string &ip);

    void SetShareName(const std::string &shareName);

    void SetWorkgroupName(const std::string &workgroupName);

    std::string GetIp() const;

    std::string GetShareName() const;

    std::string GetWorkgroupName() const;

    bool ReadFromParcel(Parcel &parcel);

    virtual bool Marshalling(Parcel &parcel) const override;

    static std::shared_ptr<PrintSharedHost> Unmarshalling(Parcel &parcel);

    void Dump() const;

private:
    std::string ip_;
    std::string shareName_;
    std::string workgroupName_;
};
}  // namespace OHOS::Print
#endif  // PRINT_SHARED_HOST_H
