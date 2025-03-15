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

#ifndef SANE_DEVICE_H
#define SANE_DEVICE_H

#include <vector>
#include "scan_constant.h"
#include "sane_info.h"
#include "parcel.h"
#include "message_parcel.h"

namespace OHOS::Scan {
class SaneDevice final:public Parcelable {
public:
    SaneDevice() = default;
    ~SaneDevice() = default;

    virtual bool Marshalling(Parcel &parcel) const override;
    static SaneDevice* Unmarshalling(Parcel &parcel);
    void Dump();
public:
    std::string name_;
    std::string vendor_;
    std::string model_;
    std::string type_;
};

} // namespace OHOS::Scan

#endif // SANE_DEVICE_H