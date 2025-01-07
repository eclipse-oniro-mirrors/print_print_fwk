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

#include "sane_parameters.h"
#include "scan_log.h"
#include "message_parcel.h"

namespace OHOS::Scan {
SaneParameters::SaneParameters() : format_(SANE_FRAME_GRAY), lastFrame_(0),
    bytesPerLine_(0), pixelsPerLine_(0), lines_(0), depth_(0) {}
bool SaneParameters::Marshalling(Parcel &parcel) const
{
    bool status = true;
    status &= parcel.WriteInt32(static_cast<int32_t>(format_));
    status &= parcel.WriteInt32(static_cast<int32_t>(lastFrame_));
    status &= parcel.WriteInt32(bytesPerLine_);
    status &= parcel.WriteInt32(pixelsPerLine_);
    status &= parcel.WriteInt32(lines_);
    status &= parcel.WriteInt32(depth_);
    return status;
}

SaneParameters* SaneParameters::Unmarshalling(Parcel &parcel)
{
    SaneParameters* obj = new SaneParameters();
    obj->format_ = static_cast<SaneFrame>(parcel.ReadInt32());
    obj->lastFrame_ = parcel.ReadInt32();
    obj->bytesPerLine_ = parcel.ReadInt32();
    obj->pixelsPerLine_ = parcel.ReadInt32();
    obj->lines_ = parcel.ReadInt32();
    obj->depth_ = parcel.ReadInt32();
    return obj;
}
}   // namespace OHOS::Scan