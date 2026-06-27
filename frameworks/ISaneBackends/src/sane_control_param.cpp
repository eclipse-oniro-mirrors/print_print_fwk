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

#include "sane_control_param.h"
#include "scan_log.h"
#include "message_parcel.h"
#include "scan_constant.h"

namespace OHOS::Scan {
SaneControlParam::SaneControlParam() : option_(0), action_(SANE_ACTION_GET_VALUE),
    valueType_(0), valueSize_(0), valueNumber_(0) {}
bool SaneControlParam::Marshalling(Parcel &parcel) const
{
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteInt32(option_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteInt32(static_cast<int32_t>(action_)), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteInt32(valueType_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteInt32(valueSize_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteInt32(valueNumber_), false);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.WriteString(valueStr_), false);
    return true;
}

SaneControlParam* SaneControlParam::Unmarshalling(Parcel &parcel)
{
    auto obj = std::make_unique<SaneControlParam>();
    if (obj == nullptr) {
        SCAN_HILOGE("obj is a nullptr.");
        return nullptr;
    }
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadInt32(obj->option_), nullptr);
    int32_t action = 0;
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadInt32(action), nullptr);
    obj->action_ = static_cast<SaneAction>(action);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadInt32(obj->valueType_), nullptr);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadInt32(obj->valueSize_), nullptr);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadInt32(obj->valueNumber_), nullptr);
    CHECK_PARCEL_OP_AND_RETURN_VAL(parcel.ReadString(obj->valueStr_), nullptr);
    return obj.release();
}
}   // namespace OHOS::Scan