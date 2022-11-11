/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "print_bms_death_recipient.h"
#include "print_bms_helper.h"
#include "print_log.h"

namespace OHOS::Print {
void PrintBMSDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &wptrDeath)
{
    PRINT_HILOGD("bundle manager service died, remove the proxy object");

    if (wptrDeath == nullptr) {
        PRINT_HILOGE("wptrDeath is null");
        return;
    }

    sptr<IRemoteObject> object = wptrDeath.promote();
    if (!object) {
        PRINT_HILOGE("object is null");
        return;
    }

    DelayedSingleton<PrintBMSHelper>::GetInstance()->ResetProxy();
}
}  // namespace OHOS