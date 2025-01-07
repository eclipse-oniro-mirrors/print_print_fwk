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

#include "sane_manager_client.h"
#include "scan_log.h"
#include "sane_sa_death_recipient.h"

namespace OHOS::Scan {
SaneSaDeathRecipient::SaneSaDeathRecipient() {}

void SaneSaDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &object)
{
    SCAN_HILOGE("SaneSaDeathRecipient on remote systemAbility died.");
    SaneManagerClient::GetInstance()->OnRemoteSaDied(object);
}
} // namespace OHOS::Scan
