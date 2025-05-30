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

#ifndef SCAN_RANGE_H
#define SCAN_RANGE_H

#include <vector>
#include "parcel.h"

namespace OHOS::Scan {
class ScanRange final : public Parcelable {
public:
    explicit ScanRange();

    ScanRange(const ScanRange &right);

    ScanRange &operator=(const ScanRange &right);

    virtual ~ScanRange();

    void Reset();

    void SetMinValue(const int32_t &minValue);

    void SetMaxValue(const int32_t &maxValue);

    void SetQuantValue(const int32_t &quantValue);

    [[nodiscard]] int32_t GetMinValue() const;

    [[nodiscard]] int32_t GetMaxValue() const;

    [[nodiscard]] int32_t GetQuantValue() const;

    virtual bool Marshalling(Parcel &parcel) const override;

    static std::shared_ptr<ScanRange> Unmarshalling(Parcel &parcel);

    void Dump() const;

private:
    void ReadFromParcel(Parcel &parcel);

private:
    int32_t minValue_;

    int32_t maxValue_;

    int32_t quantValue_;
};
}  // namespace OHOS::Scan
#endif  // SCAN_RANGE_H
