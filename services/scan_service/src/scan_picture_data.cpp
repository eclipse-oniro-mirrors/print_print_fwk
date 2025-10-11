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
#include <unistd.h>
#include <fcntl.h>
#include <random>
#include "scan_picture_data.h"
#include "scan_constant.h"
#include "scan_log.h"
#include "file_ex.h"
#include "scan_system_data.h"

namespace OHOS::Scan {
constexpr int SCAN_PROGRESS_10 = 10;
constexpr int SCAN_PROGRESS_19 = 19;
constexpr int SCAN_PROGRESS_80 = 80;
constexpr int SCAN_PROGRESS_100 = 100;
ScanPictureData& ScanPictureData::GetInstance()
{
    static ScanPictureData instance;
    return instance;
}

ScanPictureData::~ScanPictureData()
{
    CleanPictureData();
}

void ScanPictureData::CleanPictureData()
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &[imagePath, fd] : imageFdMap_) {
        constexpr int32_t INVALID_FILE_DESCRIPTOR = -1;
        if (fd != INVALID_FILE_DESCRIPTOR) {
            fdsan_close_with_tag(fd, SCAN_LOG_DOMAIN);
        }
        if (FileExists(imagePath)) {
            unlink(imagePath.c_str());
        }
    }
    imageFdMap_.clear();
    std::queue<int32_t> empty;
    scanQueue_.swap(empty);
    scanTaskMap_.clear();
    callerPid_ = 0;
}

int32_t ScanPictureData::GetPictureProgressInQueue(ScanProgress& scanProgress, int32_t callerPid)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (callerPid_ != callerPid) {
        SCAN_HILOGE("No permission to access scanned images");
        return E_SCAN_NO_PERMISSION;
    }
    if (scanQueue_.empty()) {
        SCAN_HILOGE("scanQueue is empty");
        return E_SCAN_GENERIC_FAILURE;
    }
    int32_t frontPicId = scanQueue_.front();
    auto frontPicIt = scanTaskMap_.find(frontPicId);
    if (frontPicIt == scanTaskMap_.end()) {
        SCAN_HILOGE("cannot find frontPicId [%{public}d]", frontPicId);
        return E_SCAN_GENERIC_FAILURE;
    }
    auto& prog = frontPicIt->second;
    auto taskCode = prog.GetTaskCode();
    if (taskCode != E_SCAN_NONE) {
        SCAN_HILOGE("scan task failed, taskCode = [%{public}u]", taskCode);
        scanQueue_.pop();
        return taskCode;
    }
    auto progress = prog.GetScanProgress();
    if (progress == SCAN_PROGRESS_100) {
        SCAN_HILOGD("get scan picture successfully!");
        scanProgress = prog;
        int32_t fd = open(scanProgress.GetImageRealPath().c_str(), O_RDONLY);
        fdsan_exchange_owner_tag(fd, 0, SCAN_LOG_DOMAIN);
        scanProgress.SetScanPictureFd(fd);
        imageFdMap_[scanProgress.GetImageRealPath()] = fd;
        scanProgress.Dump();
        scanQueue_.pop();
        return E_SCAN_NONE;
    }
    int32_t randomNumber = GetRandomNumber(SCAN_PROGRESS_10, SCAN_PROGRESS_19);
    auto preTime = prog.GetScanTime();
    if (GetElapsedSeconds(preTime) >= 1 && progress < SCAN_PROGRESS_80) {
        prog.SetScanProgress(progress + randomNumber);
        prog.SetScanTime(std::chrono::steady_clock::now());
    }
    scanProgress = prog;
    scanProgress.Dump();
    return E_SCAN_NONE;
}

int32_t ScanPictureData::GetRandomNumber(const int32_t &lowerBoundary, const int32_t &upperBoundary)
{
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(lowerBoundary, upperBoundary);
    return dis(gen);
}

int32_t ScanPictureData::GetElapsedSeconds(const SteadyTimePoint &preTime)
{
    auto nowTime = std::chrono::steady_clock::now();
    auto elapsedTime = std::chrono::duration_cast<std::chrono::seconds>(nowTime - preTime);
    return elapsedTime.count();
}

void ScanPictureData::PushScanPictureProgress()
{
    std::lock_guard<std::mutex> lock(mutex_);
    ScanProgress prog;
    picId_++;
    prog.SetPictureId(picId_);
    prog.SetScanTime(std::chrono::steady_clock::now());
    scanTaskMap_[picId_] = std::move(prog);
    scanQueue_.push(picId_);
}

bool ScanPictureData::SetImageRealPath(const std::string& filePath)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = scanTaskMap_.find(picId_);
    if (it == scanTaskMap_.end()) {
        SCAN_HILOGE("cannot find picId_ %{private}d", picId_);
        return false;
    }
    it->second.SetImageRealPath(filePath);
    return true;
}

void ScanPictureData::SetCallerPid(int32_t callerPid)
{
    std::lock_guard<std::mutex> lock(mutex_);
    callerPid_ = callerPid;
}

void ScanPictureData::SetScanProgr(int64_t &totalBytes, const int64_t &hundredPercent, const int32_t &curReadSize)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (hundredPercent == 0) {
        SCAN_HILOGE("hundredPercent equals zero.");
        return;
    }
    auto it = scanTaskMap_.find(picId_);
    if (it == scanTaskMap_.end()) {
        SCAN_HILOGW("cannot find picId [%{public}d]", picId_);
        return;
    }
    totalBytes += static_cast<int64_t>(curReadSize);
    int64_t progr = ((totalBytes * SCAN_PROGRESS_100) / hundredPercent);
    if (progr >= SCAN_PROGRESS_100) {
        progr = SCAN_PROGRESS_100 - 1;
    }
    if (progr > (it->second.GetScanProgress())) {
        it->second.SetScanProgress(static_cast<int32_t>(progr));
    }
}

void ScanPictureData::SetScanTaskCode(int32_t taskCode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = scanTaskMap_.find(picId_);
    if (it != scanTaskMap_.end()) {
        it->second.SetTaskCode(static_cast<ScanErrorCode>(taskCode));
    } else {
        SCAN_HILOGE("SetScanTaskCode cannot find picId_ = [%{public}d]", picId_);
    }
}

void ScanPictureData::SetNowScanProgressFinished(bool isFinal)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = scanTaskMap_.find(picId_);
    if (it != scanTaskMap_.end()) {
        it->second.SetIsFinal(isFinal);
        it->second.SetScanProgress(SCAN_PROGRESS_100);
    } else {
        SCAN_HILOGE("SetNowScanProgressFinished cannot find picId_ = [%{public}d]", picId_);
    }
}
void ScanPictureData::SetLastScanProgressFinished()
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = scanTaskMap_.find(picId_ - 1);
    if (it != scanTaskMap_.end()) {
        it->second.SetIsFinal(false);
    } else {
        SCAN_HILOGE("SetLastScanProgressFinished cannot find picId_ = [%{public}d]", picId_);
    }
}
} // namespace OHOS::Scan
