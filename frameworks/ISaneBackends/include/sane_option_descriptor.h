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

#ifndef SANE_OPTION_DESCRIPTOR_H
#define SANE_OPTION_DESCRIPTOR_H

#include <vector>
#include "scan_constant.h"
#include "sane_info.h"
#include "parcel.h"
#include "message_parcel.h"

namespace OHOS::Scan {
class SaneOptionDescriptor final:public Parcelable {
public:
    SaneOptionDescriptor();
    ~SaneOptionDescriptor() = default;

    virtual bool Marshalling(Parcel &parcel) const override;
    static SaneOptionDescriptor* Unmarshalling(Parcel &parcel);
    void Dump();

public:
    std::string optionName_;
    std::string optionTitle_;
    std::string optionDesc_;
    int32_t optionType_;
    int32_t optionUnit_;
    int32_t optionSize_;
    int32_t optionCap_;
    int32_t optionConstraintType_;
    std::vector<std::string> optionConstraintString_;
    std::vector<int32_t> optionConstraintNumber_;
    int32_t minValue_;
    int32_t maxValue_;
    int32_t quantValue_;
};

} // namespace OHOS::Scan

#endif // SANE_OPTION_DESCRIPTOR_H