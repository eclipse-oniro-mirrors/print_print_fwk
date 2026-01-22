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

#include "scan_progress.h"
#include "scan_log.h"
#include "message_parcel.h"

namespace OHOS::Scan {
using SteadyTimePoint = std::chrono::steady_clock::time_point;
ScanProgress::ScanProgress() : progress_(0),
    fd_(0), isFinal_(true), pictureId_(0), taskCode_(E_SCAN_NONE), imageRealPath_("")
{}

ScanProgress::ScanProgress(const ScanProgress &right)
{
    progress_ = right.progress_;
    fd_ = right.fd_;
    isFinal_ = right.isFinal_;
    pictureId_ = right.pictureId_;
    timePoint_ = right.timePoint_;
    taskCode_ = right.taskCode_;
    imageRealPath_ = right.imageRealPath_;
}

ScanProgress &ScanProgress::operator=(const ScanProgress &right)
{
    if (this != &right) {
        progress_ = right.progress_;
        fd_ = right.fd_;
        isFinal_ = right.isFinal_;
        pictureId_ = right.pictureId_;
        timePoint_ = right.timePoint_;
        taskCode_ = right.taskCode_;
        imageRealPath_ = right.imageRealPath_;
    }
    return *this;
}

ScanProgress::~ScanProgress()
{}

void ScanProgress::SetScanProgress(const int32_t progress)
{
    this->progress_ = progress;
}

void ScanProgress::SetScanPictureFd(const int32_t fd)
{
    this->fd_ = fd;
}

void ScanProgress::SetIsFinal(const bool isFinal)
{
    this->isFinal_ = isFinal;
}

void ScanProgress::SetPictureId(const int32_t pictureId)
{
    this->pictureId_ = pictureId;
}

void ScanProgress::SetScanTime(SteadyTimePoint nowTime)
{
    this->timePoint_ = nowTime;
}

void ScanProgress::SetTaskCode(ScanErrorCode taskCode)
{
    this->taskCode_ = taskCode;
}

void ScanProgress::SetImageRealPath(const std::string &imageRealPath)
{
    this->imageRealPath_ = imageRealPath;
}


int32_t ScanProgress::GetScanProgress() const
{
    return progress_;
}

int32_t ScanProgress::GetScanPictureFd() const
{
    return fd_;
}

bool ScanProgress::GetIsFinal() const
{
    return isFinal_;
}

int32_t ScanProgress::GetPictureId() const
{
    return pictureId_;
}

SteadyTimePoint ScanProgress::GetScanTime() const
{
    return timePoint_;
}

ScanErrorCode ScanProgress::GetTaskCode() const
{
    return taskCode_;
}

std::string ScanProgress::GetImageRealPath() const
{
    return imageRealPath_;
}

void ScanProgress::ReadFromParcel(Parcel &parcel)
{
    auto mesgParcel = static_cast<MessageParcel*>(&parcel);
    SetScanProgress(parcel.ReadInt32());
    SetScanPictureFd(mesgParcel->ReadFileDescriptor());
    SetIsFinal(parcel.ReadBool());
}

bool ScanProgress::Marshalling(Parcel &parcel) const
{
    auto mesgParcel = static_cast<MessageParcel*>(&parcel);
    parcel.WriteInt32(progress_);
    mesgParcel->WriteFileDescriptor(fd_);
    parcel.WriteBool(isFinal_);
    return true;
}

std::shared_ptr<ScanProgress> ScanProgress::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<ScanProgress>();
    nativeObj->ReadFromParcel(parcel);
    return nativeObj;
}

void ScanProgress::Dump() const
{
    SCAN_HILOGI("ScanProgress Dump");
    SCAN_HILOGI("ScanProgress: progress = %{public}d", progress_);
    SCAN_HILOGI("ScanProgress: fd = %{public}d", fd_);
    SCAN_HILOGI("ScanProgress: isFinal = %{public}d", isFinal_);
    SCAN_HILOGI("ScanProgress: pictureId = %{public}d", pictureId_);
    SCAN_HILOGI("ScanProgress: taskCode = %{public}d", taskCode_);
}

} // namespace OHOS::Scan
