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
ScanProgress::ScanProgress() : progress(0),
    fd(0), isFinal(true), pictureId(0), taskCode(E_SCAN_GOOD)
{}

ScanProgress::ScanProgress(const ScanProgress &right)
{
    progress = right.progress;
    fd = right.fd;
    isFinal = right.isFinal;
    pictureId = right.pictureId;
    timePoint = right.timePoint;
    taskCode = right.taskCode;
}

ScanProgress &ScanProgress::operator=(const ScanProgress &right)
{
    if (this != &right) {
        progress = right.progress;
        fd = right.fd;
        isFinal = right.isFinal;
        pictureId = right.pictureId;
        timePoint = right.timePoint;
        taskCode = right.taskCode;
    }
    return *this;
}

ScanProgress::~ScanProgress()
{}

void ScanProgress::SetScanProgress(const int32_t progress)
{
    this->progress = progress;
}

void ScanProgress::SetScanPictureFd(const int32_t fd)
{
    this->fd = fd;
}

void ScanProgress::SetIsFinal(const bool isFinal)
{
    this->isFinal = isFinal;
}

void ScanProgress::SetPictureId(const int32_t pictureId)
{
    this->pictureId = pictureId;
}

void ScanProgress::SetScanTime(SteadyTimePoint nowTime)
{
    this->timePoint = nowTime;
}

void ScanProgress::SetTaskCode(ScanErrorCode taskCode)
{
    this->taskCode = taskCode;
}

int32_t ScanProgress::GetScanProgress() const
{
    return progress;
}

int32_t ScanProgress::GetScanPictureFd() const
{
    return fd;
}

bool ScanProgress::GetIsFinal() const
{
    return isFinal;
}

int32_t ScanProgress::GetPictureId() const
{
    return pictureId;
}

SteadyTimePoint ScanProgress::GetScanTime() const
{
    return timePoint;
}

ScanErrorCode ScanProgress::GetTaskCode() const
{
    return taskCode;
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
    parcel.WriteInt32(progress);
    mesgParcel->WriteFileDescriptor(fd);
    parcel.WriteBool(isFinal);
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
    SCAN_HILOGI("ScanProgress: progress = %{public}d", progress);
    SCAN_HILOGI("ScanProgress: fd = %{public}d", fd);
    SCAN_HILOGI("ScanProgress: isFinal = %{public}d", isFinal);
    SCAN_HILOGI("ScanProgress: pictureId = %{public}d", pictureId);
    SCAN_HILOGI("ScanProgress: taskCode = %{public}d", taskCode);
}

} // namespace OHOS::Scan
