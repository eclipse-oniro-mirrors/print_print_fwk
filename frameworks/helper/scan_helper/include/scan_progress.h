/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef SCAN_PROGRESS_H
#define SCAN_PROGRESS_H

#include <vector>
#include <chrono>
#include "parcel.h"
#include "scan_constant.h"


namespace OHOS::Scan {
using SteadyTimePoint = std::chrono::steady_clock::time_point;
class ScanProgress final : public Parcelable {
public:
    explicit ScanProgress();
    ScanProgress(const ScanProgress &right);
    ScanProgress &operator=(const ScanProgress &right);
    virtual ~ScanProgress();

    void SetScanProgress(const int32_t progress);
    void SetScanPictureFd(const int32_t fd);
    void SetIsFinal(const bool isFinal);
    void SetPictureId(const int32_t pictureId);
    void SetScanTime(SteadyTimePoint nowTime);
    void SetTaskCode(ScanErrorCode taskCode);
    void Dump() const;

    [[nodiscard]] int32_t GetScanProgress() const;
    [[nodiscard]] int32_t GetScanPictureFd() const;
    [[nodiscard]] bool GetIsFinal() const;
    [[nodiscard]] int32_t GetPictureId() const;
    [[nodiscard]] SteadyTimePoint GetScanTime() const;
    [[nodiscard]] ScanErrorCode GetTaskCode() const;

    virtual bool Marshalling(Parcel &parcel) const override;
    static std::shared_ptr<ScanProgress> Unmarshalling(Parcel &parcel);
private:
    void ReadFromParcel(Parcel &parcel);

private:
    int32_t progress; // 0~100
    int32_t fd;
    bool isFinal;
    int32_t pictureId;
    SteadyTimePoint timePoint;
    ScanErrorCode taskCode;
};
}  // namespace OHOS::Scan
#endif  // SCAN_PROGRESS_H
