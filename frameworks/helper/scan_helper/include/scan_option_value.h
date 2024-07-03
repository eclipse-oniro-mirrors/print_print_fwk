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

#ifndef SCAN_OPTION_VALUE_H
#define SCAN_OPTION_VALUE_H

#include <vector>
#include "parcel.h"
#include "scan_constant.h"

namespace OHOS::Scan {
class ScanOptionValue final : public Parcelable {
public:
    explicit ScanOptionValue();

    ScanOptionValue(const ScanOptionValue &right);

    ScanOptionValue &operator=(const ScanOptionValue &right);

    virtual ~ScanOptionValue();

    void Reset();
    void Dump();

    void SetScanOptionValueType(const ScanOptionValueType &valueType);
    void SetValueSize(const int32_t &valueSize);
    void SetNumValue(const int32_t &numValue);
    void SetNumListValue(const std::vector<int32_t> &numListValue);
    void SetStrValue(const std::string &strValue);
    void SetBoolValue(const bool &boolValue);

    [[nodiscard]] ScanOptionValueType GetScanOptionValueType() const;
    [[nodiscard]] int32_t GetValueSize() const;
    [[nodiscard]] int32_t GetNumValue() const;
    void GetNumListValue(std::vector<int32_t> &numListValue) const;
    [[nodiscard]] std::string GetStrValue() const;
    [[nodiscard]] bool GetBoolValue() const;

    virtual bool Marshalling(Parcel &parcel) const override;
    static std::shared_ptr<ScanOptionValue> Unmarshalling(Parcel &parcel);
private:
    void ReadFromParcel(Parcel &parcel);

private:
    ScanOptionValueType valueType_;
    int32_t valueSize_;
    int32_t numValue_;
    std::vector<int32_t> numListValue_;
    std::string strValue_;
    bool boolValue_;
};
}  // namespace OHOS::Scan
#endif  // SCAN_OPTION_VALUE_H
