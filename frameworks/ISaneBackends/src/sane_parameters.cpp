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
#include "scan_constant.h"

namespace OHOS::Scan {
SaneParameters::SaneParameters() : format_(SANE_FRAME_GRAY), lastFrame_(0),
    bytesPerLine_(0), pixelsPerLine_(0), lines_(0), depth_(0) {}
bool SaneParameters::Marshalling(Parcel &parcel) const
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteInt32(static_cast<int32_t>(format_)), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteInt32(static_cast<int32_t>(lastFrame_)), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteInt32(bytesPerLine_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteInt32(pixelsPerLine_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteInt32(lines_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteInt32(depth_), false);
    return true;
}

SaneParameters* SaneParameters::Unmarshalling(Parcel &parcel)
{
    auto obj = std::make_unique<SaneParameters>();
    if (obj == nullptr) {
        SCAN_HILOGE("obj is a nullptr.");
        return nullptr;
    }
    int32_t format = 0;
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadInt32(format), nullptr);
    if (format < SANE_FRAME_GRAY || format >= SANE_FRAME_MAX) {
        SCAN_HILOGE("invalid format %{public}d", format);
        return nullptr;
    }
    obj->format_ = static_cast<SaneFrame>(format);
    int32_t lastFrame = 0;
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadInt32(lastFrame), nullptr);
    obj->lastFrame_ = lastFrame;
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadInt32(obj->bytesPerLine_), nullptr);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadInt32(obj->pixelsPerLine_), nullptr);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadInt32(obj->lines_), nullptr);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadInt32(obj->depth_), nullptr);
    if (obj->bytesPerLine_ < 0 || obj->bytesPerLine_ > MAX_IMAGE_DIMENSION ||
        obj->pixelsPerLine_ < 0 || obj->pixelsPerLine_ > MAX_IMAGE_DIMENSION ||
        obj->lines_ < 0 || obj->lines_ > MAX_IMAGE_DIMENSION ||
        obj->depth_ < 0 || obj->depth_ > MAX_IMAGE_DIMENSION) {
        SCAN_HILOGE("invalid parameters: bytesPerLine=%{public}d, pixelsPerLine=%{public}d, "
            "lines=%{public}d, depth=%{public}d",
            obj->bytesPerLine_, obj->pixelsPerLine_, obj->lines_, obj->depth_);
        return nullptr;
    }
    return obj.release();
}
}   // namespace OHOS::Scan