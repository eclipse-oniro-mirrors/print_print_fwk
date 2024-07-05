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

#ifndef SCAN_OPTION_DESCRIPTOR_H
#define SCAN_OPTION_DESCRIPTOR_H

#include "parcel.h"
#include "scan_range.h"

namespace OHOS::Scan {
class ScanOptionDescriptor final : public Parcelable {
public:
    explicit ScanOptionDescriptor();
    ScanOptionDescriptor(const ScanOptionDescriptor &right);
    ~ScanOptionDescriptor() = default;

    ScanOptionDescriptor &operator=(const ScanOptionDescriptor &right);

    void SetOptionName(const std::string &optionName);
    void SetOptionTitle(const std::string &optionTitle);
    void SetOptionDesc(const std::string &optionDesc);
    void SetOptionType(const uint32_t &optionType);
    void SetOptionUnit(const uint32_t &optionUnit);

    void SetOptionSize(const int32_t &optionSize);
    void SetOptionCap(const int32_t &optionCap);

    void SetOptionConstraintType(const uint32_t &optionConstraintType);
    void SetOptionConstraintString(const std::vector<std::string> &optionConstraintString);
    void SetOptionConstraintNumber(const std::vector<int32_t> &optionConstraintNumber);
    void SetOptionConstraintRange(const ScanRange& optionConstraintRange);

    [[nodiscard]] std::string GetOptionName() const;
    [[nodiscard]] std::string GetOptionTitle() const;
    [[nodiscard]] std::string GetOptionDesc() const;
    [[nodiscard]] uint32_t GetOptionType() const;
    [[nodiscard]] uint32_t GetOptionUnit() const;

    [[nodiscard]] int32_t GetOptionSize() const;
    [[nodiscard]] int32_t GetOptionCap() const;

    [[nodiscard]] uint32_t GetOptionConstraintType() const;
    void GetOptionConstraintString(std::vector<std::string> &optionConstraintString) const;
    void GetOptionConstraintNumber(std::vector<int32_t> &optionConstraintNumber) const;
    void GetOptionConstraintRange(ScanRange &optionConstraintRange) const;

    virtual bool Marshalling(Parcel &parcel) const override;

    static std::shared_ptr<ScanOptionDescriptor> Unmarshalling(Parcel &parcel);

    void Dump();

private:
    void ReadFromParcel(Parcel &parcel);

private:
    std::string optionName_;
    std::string optionTitle_;
    std::string optionDesc_;
    uint32_t optionType_;
    uint32_t optionUnit_;

    int32_t optionSize_;
    int32_t optionCap_;

    uint32_t optionConstraintType_;
    std::vector<std::string> optionConstraintString_;
    std::vector<std::int32_t> optionConstraintNumber_;
    ScanRange optionConstraintRange_;
};
}  // namespace OHOS::Scan
#endif  // SCAN_OPTION_DESCRIPTOR_H
