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

#include "message_parcel.h"
#include "sane_out_param.h"
#include "scan_log.h"
#include "scan_constant.h"

namespace OHOS::Scan {
SaneOutParam::SaneOutParam() : info_(0), valueNumber_(0), valueBool_(true) {}
bool SaneOutParam::Marshalling(Parcel &parcel) const
{
    bool status = true;
    status &= parcel.WriteInt32(info_);
    status &= parcel.WriteInt32(valueNumber_);
    status &= parcel.WriteInt32Vector(valueNumList_);
    status &= parcel.WriteString(valueStr_);
    status &= parcel.WriteBool(valueBool_);
    return status;
}

SaneOutParam* SaneOutParam::Unmarshalling(Parcel &parcel)
{
    SaneOutParam* obj = new (std::nothrow) SaneOutParam();
    if (obj == nullptr) {
        SCAN_HILOGE("obj is a nullptr.");
        return nullptr;
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadInt32(obj->info_), nullptr);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadInt32(obj->valueNumber_), nullptr);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadInt32Vector(&obj->valueNumList_), nullptr);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(obj->valueStr_), nullptr);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadBool(obj->valueBool_), nullptr);
    return obj;
}
}   // namespace OHOS::Scan