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

#ifndef SCAN_SA_DEATH_RECIPIENT_H
#define SCAN_SA_DEATH_RECIPIENT_H
#define TDD_ENABLE 1

#include "iremote_object.h"
#include "refbase.h"

namespace OHOS::Scan {
class ScanSaDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit ScanSaDeathRecipient();
    ~ScanSaDeathRecipient() = default;
    void OnRemoteDied(const wptr<IRemoteObject> &object) override;
};
} // namespace OHOS::Scan
#endif // SCAN_SA_DEATH_RECIPIENT_H