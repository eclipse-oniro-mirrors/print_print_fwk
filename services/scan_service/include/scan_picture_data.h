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

#ifndef SCAN_PICTURE_DATA
#define SCAN_PICTURE_DATA

#include <string>
#include <map>
#include <mutex>
#include <chrono>
#include <queue>
#include "scan_progress.h"
namespace OHOS::Scan {
class ScanPictureData {
public:
    static ScanPictureData& GetInstance();
    ~ScanPictureData();
    void SetScanProgr(int64_t &totalBytes, const int64_t &hundredPercent, const int32_t &curReadSize);
    void SetScanTaskCode(int32_t taskCode);
    void SetNowScanProgressFinished(bool isFinal);
    void SetLastScanProgressFinished();
    bool SetImageRealPath(const std::string& filePath);
    int32_t GetPictureProgressInQueue(ScanProgress& scanProgress);
    void CleanPictureData();
    void PushScanPictureProgress();

private:
    ScanPictureData() = default;
    int32_t GetRandomNumber(const int32_t &lowerBoundary, const int32_t &upperBoundary);
    int32_t GetElapsedSeconds(const SteadyTimePoint &preTime);
    mutable std::mutex mutex_;
    std::queue<int32_t> scanQueue_;
    std::map<std::string, int32_t> imageFdMap_;
    std::map<int32_t, ScanProgress> scanTaskMap_;
    int32_t picId_ = 0;
};

} // namespace OHOS::Scan
#endif // SCAN_PICTURE_DATA