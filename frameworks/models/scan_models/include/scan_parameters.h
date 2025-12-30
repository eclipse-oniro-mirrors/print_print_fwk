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

#ifndef SCAN_PARAMETERS_H
#define SCAN_PARAMETERS_H

#include <vector>
#include "parcel.h"
#include "scan_constant.h"

namespace OHOS::Scan {
class ScanParameters final : public Parcelable {
public:
    explicit ScanParameters();
    ScanParameters(const ScanParameters &right);
    ScanParameters &operator=(const ScanParameters &right);
    virtual ~ScanParameters();

    void Reset();
    void Dump();

    void SetFormat(const ScanFrame &format);
    void SetLastFrame(const bool &lastFrame);
    void SetBytesPerLine(const int32_t &bytesPerLine);
    void SetPixelsPerLine(const int32_t &pixelsPerLine);
    void SetLines(const int32_t &lines);
    void SetDepth(const int32_t &depth);

    [[nodiscard]] ScanFrame GetFormat() const;
    [[nodiscard]] bool GetLastFrame() const;
    [[nodiscard]] int32_t GetBytesPerLine() const;
    [[nodiscard]] int32_t GetPixelsPerLine() const;
    [[nodiscard]] int32_t GetLines() const;
    [[nodiscard]] int32_t GetDepth() const;

    virtual bool Marshalling(Parcel &parcel) const override;
    static std::shared_ptr<ScanParameters> Unmarshalling(Parcel &parcel);
private:
    void ReadFromParcel(Parcel &parcel);
    bool Validate() const;

private:
    ScanFrame format_;
    bool lastFrame_;
    int32_t bytesPerLine_;
    int32_t pixelsPerLine_;
    int32_t lines_;
    int32_t depth_;
};
}  // namespace OHOS::Scan
#endif  // SCAN_PARAMETERS_H
