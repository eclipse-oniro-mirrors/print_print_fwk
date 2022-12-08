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

#include "print_sync_load_callback.h"

#include "iservice_registry.h"
#include "isystem_ability_load_callback.h"
#include "print_log.h"
#include "print_manager_client.h"
#include "system_ability_definition.h"

namespace OHOS::Print {
void PrintSyncLoadCallback::OnLoadSystemAbilitySuccess(int32_t systemAbilityId, const sptr<IRemoteObject> &remoteObject)
{
    if (systemAbilityId != PRINT_SERVICE_ID) {
        PRINT_HILOGE("start systemAbilityId is not print server");
        return;
    }
    PrintManagerClient::GetInstance()->LoadServerSuccess();
}

void PrintSyncLoadCallback::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    if (systemAbilityId != PRINT_SERVICE_ID) {
        PRINT_HILOGE("start systemAbilityId is not print server");
        return;
    }
    PrintManagerClient::GetInstance()->LoadServerFail();
}
} // namespace OHOS::Print