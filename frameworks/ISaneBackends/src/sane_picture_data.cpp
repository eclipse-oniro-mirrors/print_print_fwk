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

#include "sane_picture_data.h"
#include "sane_info.h"
#include "scan_log.h"
#include "securec.h"
#include "message_parcel.h"
#include "parcel.h"

namespace OHOS::Scan {
SanePictureData::SanePictureData() : ret_(SANE_READ_OK) {}
SanePictureData::~SanePictureData() {}

bool SanePictureData::Marshalling(Parcel &parcel) const
{
    bool status = true;
    status &= parcel.WriteUint32(ret_);
    if (ret_ == SANE_READ_OK) {
        status &= parcel.WriteUint32(dataBuffer_.size());
        status &= parcel.WriteBuffer((void*) dataBuffer_.data(), dataBuffer_.size());
    }
    return status;
}

SanePictureData* SanePictureData::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<SanePictureData> obj = std::make_unique<SanePictureData>();
    if (obj == nullptr) {
        SCAN_HILOGE("obj is a nullptr");
        return nullptr;
    }
    obj->ret_ = parcel.ReadUint32();
    if (obj->ret_ == SANE_READ_OK) {
        uint32_t bufferSize = parcel.ReadUint32();
        const uint8_t* data = parcel.ReadUnpadBuffer(bufferSize);
        if (data == nullptr) {
            SCAN_HILOGE("data is a nullptr");
            return nullptr;
        }
        if (bufferSize > MAX_BUFLEN) {
            SCAN_HILOGE("data exceeds MAX_BUFLEN");
            return nullptr;
        }
        obj->dataBuffer_.resize(bufferSize, 0);
        auto ret = memcpy_s(obj->dataBuffer_.data(), bufferSize, data, bufferSize);
        if (ret != SANE_STATUS_GOOD) {
            SCAN_HILOGE("memcpy_s failed, errorCode: %{public}d", ret);
            return nullptr;
        }
    }
    return obj.release();
}
}   // namespace OHOS::Scan