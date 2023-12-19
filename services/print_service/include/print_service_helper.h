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

#ifndef PRINT_SERVICE_HELPER_H
#define PRINT_SERVICE_HELPER_H

#include <string>
#include "ability_manager_client.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_client.h"
#include "system_ability.h"

namespace OHOS::Print {
class PrintServiceHelper {
public:
    virtual ~PrintServiceHelper();
    virtual bool CheckPermission(const std::string &name);
    virtual bool StartAbility(const AAFwk::Want &want);
    virtual bool KillAbility(const std::string &bundleName);
    virtual bool StartPrintServiceExtension(const AAFwk::Want &want, int32_t requestCode_);
    virtual sptr<IRemoteObject> GetBundleMgr();
    virtual bool QueryAccounts(std::vector<int> &accountList);
    virtual bool QueryExtension(sptr<AppExecFwk::IBundleMgr> mgr, int userId,
                                    std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfos);
    virtual bool QueryNameForUid(sptr<AppExecFwk::IBundleMgr> mgr, int32_t userId, std::string& name);
    virtual bool IsSyncMode();
};
}  // namespace OHOS
#endif  // PRINT_SERVICE_HELPER_H
