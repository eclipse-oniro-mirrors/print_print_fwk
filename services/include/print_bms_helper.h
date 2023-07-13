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

#ifndef PRINT_BMS_HELPER_H
#define PRINT_BMS_HELPER_H

#include <string>
#include <vector>

#include "bundle_mgr_interface.h"
#include "extension_ability_info.h"
#include "print_bms_death_recipient.h"
#include "print_service_helper.h"
#include "singleton.h"

namespace OHOS::Print {
class PrintBMSHelper : public DelayedSingleton<PrintBMSHelper> {
public:
    PrintBMSHelper();

    virtual ~PrintBMSHelper();

    void SetHelper(const std::shared_ptr<PrintServiceHelper> &helper);

    bool QueryExtensionInfos(std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfo);

    std::string QueryCallerBundleName();

    void ResetProxy(const wptr<IRemoteObject> &remote);

private:
    bool GetProxy();

private:
    sptr<AppExecFwk::IBundleMgr> sptrBundleMgr_;
    std::mutex mutex_;
    sptr<PrintBMSDeathRecipient> printBMSDeath_;
    std::shared_ptr<PrintServiceHelper> helper_;
};
}  // namespace OHOS
#endif  // PRINT_BMS_HELPER_H
