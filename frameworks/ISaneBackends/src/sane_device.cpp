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
#include "sane_device.h"

namespace OHOS::Scan {
bool SaneDevice::Marshalling(Parcel &parcel) const
{
    bool status = true;
    status &= parcel.WriteString(name_);
    status &= parcel.WriteString(vendor_);
    status &= parcel.WriteString(model_);
    status &= parcel.WriteString(type_);
    return status;
}

SaneDevice* SaneDevice::Unmarshalling(Parcel &parcel)
{
    SaneDevice* obj = new SaneDevice();
    obj->name_ = parcel.ReadString();
    obj->vendor_ = parcel.ReadString();
    obj->model_ = parcel.ReadString();
    obj->type_ = parcel.ReadString();
    return obj;
}
}   // namespace OHOS::Scan