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

#include "scan_parameters.h"
#include "scan_log.h"

namespace OHOS::Scan {
ScanParameters::ScanParameters() : format_(SCAN_FRAME_GRAY),
    lastFrame_(false), bytesPerLine_(0), pixelsPerLine_(0), lines_(0), depth_(0)
{}

ScanParameters::ScanParameters(const ScanParameters &right)
{
    format_ = right.format_;
    lastFrame_ = right.lastFrame_;
    bytesPerLine_ = right.bytesPerLine_;
    pixelsPerLine_ = right.pixelsPerLine_;
    lines_ = right.lines_;
    depth_ = right.depth_;
}

ScanParameters &ScanParameters::operator=(const ScanParameters &right)
{
    if (this != &right) {
        format_ = right.format_;
        lastFrame_ = right.lastFrame_;
        bytesPerLine_ = right.bytesPerLine_;
        pixelsPerLine_ = right.pixelsPerLine_;
        lines_ = right.lines_;
        depth_ = right.depth_;
    }
    return *this;
}

ScanParameters::~ScanParameters()
{}

void ScanParameters::Reset()
{
    format_ = SCAN_FRAME_GRAY;
    lastFrame_ = false;
    bytesPerLine_ = 0;
    pixelsPerLine_ = 0;
    lines_ = 0;
    depth_ = 0;
}

void ScanParameters::SetFormat(const ScanFrame &format)
{
    format_ = format;
}

void ScanParameters::SetLastFrame(const bool &lastFrame)
{
    lastFrame_ = lastFrame;
}

void ScanParameters::SetBytesPerLine(const int32_t &bytesPerLine)
{
    bytesPerLine_ = bytesPerLine;
}

void ScanParameters::SetPixelsPerLine(const int32_t &pixelsPerLine)
{
    pixelsPerLine_ = pixelsPerLine;
}

void ScanParameters::SetLines(const int32_t &lines)
{
    lines_ = lines;
}

void ScanParameters::SetDepth(const int32_t &depth)
{
    depth_ = depth;
}

ScanFrame ScanParameters::GetFormat() const
{
    return format_;
}

bool ScanParameters::GetLastFrame() const
{
    return lastFrame_;
}

int32_t ScanParameters::GetBytesPerLine() const
{
    return bytesPerLine_;
}

int32_t ScanParameters::GetPixelsPerLine() const
{
    return pixelsPerLine_;
}

int32_t ScanParameters::GetLines() const
{
    return lines_;
}

int32_t ScanParameters::GetDepth() const
{
    return depth_;
}


void ScanParameters::ReadFromParcel(Parcel &parcel)
{
    SetFormat((ScanFrame)parcel.ReadUint32());
    SetLastFrame(parcel.ReadBool());
    SetBytesPerLine(parcel.ReadInt32());
    SetPixelsPerLine(parcel.ReadInt32());
    SetLines(parcel.ReadInt32());
    SetDepth(parcel.ReadInt32());
}

bool ScanParameters::Marshalling(Parcel &parcel) const
{
    parcel.WriteUint32((uint32_t)format_);
    parcel.WriteBool(lastFrame_);
    parcel.WriteInt32(bytesPerLine_);
    parcel.WriteInt32(pixelsPerLine_);
    parcel.WriteInt32(lines_);
    parcel.WriteInt32(depth_);
    return true;
}

std::shared_ptr<ScanParameters> ScanParameters::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<ScanParameters>();
    nativeObj->ReadFromParcel(parcel);
    return nativeObj;
}

void ScanParameters::Dump()
{
    SCAN_HILOGI("Format = %{public}u", format_);
    SCAN_HILOGI("LastFrame = %{public}d", lastFrame_);
    SCAN_HILOGI("BytesPerLine = %{public}d", bytesPerLine_);
    SCAN_HILOGI("PixelsPerLine = %{public}d", pixelsPerLine_);
    SCAN_HILOGI("Lines = %{public}d", lines_);
    SCAN_HILOGI("Depth = %{public}d", depth_);
}
} // namespace OHOS::Scan
