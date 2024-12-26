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
#include "message_parcel.h"

namespace OHOS::Scan {
SaneControlParam::SaneControlParam() : option_(0), action_(SANE_ACTION_GET_VALUE),
    valueType_(0), valueSize_(0), valueNumber_(0) {}
bool SaneControlParam::Marshalling(Parcel &parcel) const
{
    bool status = true;
    status &= parcel.WriteInt32(option_);
    status &= parcel.WriteInt32(static_cast<int32_t>(action_));
    status &= parcel.WriteInt32(valueType_);
    status &= parcel.WriteInt32(valueSize_);
    status &= parcel.WriteInt32(valueNumber_);
    status &= parcel.WriteString(valueStr_);
    return status;
}

SaneControlParam* SaneControlParam::Unmarshalling(Parcel &parcel)
{
    SaneControlParam* obj = new SaneControlParam();
    obj->option_ = parcel.ReadInt32();
    obj->action_ = static_cast<SaneAction>(parcel.ReadInt32());
    obj->valueType_ = parcel.ReadInt32();
    obj->valueSize_ = parcel.ReadInt32();
    obj->valueNumber_ = parcel.ReadInt32();
    obj->valueStr_ = parcel.ReadString();
    return obj;
}
}   // namespace OHOS::Scan