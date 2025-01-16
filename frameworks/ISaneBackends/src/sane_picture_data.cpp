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
SanePictureData::SanePictureData() : data_(nullptr), size_(0) {}
SanePictureData::~SanePictureData()
{
    DELETE_ARRAY_AND_NULLIFY(data_);
}

bool SanePictureData::Marshalling(Parcel &parcel) const
{
    bool status = true;
    if (size_ == INVALID_DATA) {
        status &= parcel.WriteInt32(size_);
        return status;
    }
    if (data_ == nullptr) {
        SCAN_HILOGE("data_ is a nullptr");
        return false;
    }
    status &= parcel.WriteInt32(size_);
    status &= parcel.WriteBuffer((void*) data_, size_);
    return status;
}

SanePictureData* SanePictureData::Unmarshalling(Parcel &parcel)
{
    SanePictureData* obj = new (std::nothrow) SanePictureData();
    if (obj == nullptr) {
        SCAN_HILOGE("obj is a nullptr.");
        return nullptr;
    }
    int32_t dataSize = parcel.ReadInt32();
    obj->size_ = dataSize;
    if (dataSize == INVALID_DATA) {
        SCAN_HILOGW("No data was read because of the failure");
        return obj;
    }
    if (dataSize > MAX_BUFLEN) {
        SCAN_HILOGE("dataSize [%{public}d] exceeded the maximum value.", dataSize);
        delete obj;
        return nullptr;
    }
    const uint8_t* data = parcel.ReadBuffer(static_cast<size_t>(obj->size_));
    if (data == nullptr) {
        SCAN_HILOGE("data is a nullptr");
        delete obj;
        return nullptr;
    }
    constexpr int32_t zero = 0;
    obj->valueBuffer_.resize(dataSize, zero);
    auto ret = memcpy_s(obj->valueBuffer_.data(), dataSize, data, dataSize);
    if (ret != SANE_STATUS_GOOD) {
        SCAN_HILOGE("memcpy_s failed, errorCode: %{public}d", ret);
        delete obj;
        return nullptr;
    }
    return obj;
}
}   // namespace OHOS::Scan