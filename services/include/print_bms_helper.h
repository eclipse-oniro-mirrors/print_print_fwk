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

#include "print_bms_death_recipient.h"
#include "bundle_mgr_interface.h"
#include "extension_ability_info.h"
#include "iremote_object.h"
#include "refbase.h"
#include "singleton.h"
#include "want.h"

namespace OHOS::Print {

class PrintBMSHelper : public DelayedSingleton<PrintBMSHelper> {
public:
    using IBundleMgr = OHOS::AppExecFwk::IBundleMgr;

    explicit PrintBMSHelper();

    virtual ~PrintBMSHelper();

    bool QueryExtensionInfos(std::vector<AppExecFwk::ExtensionAbilityInfo> &extensionInfo);

    void ResetProxy();

private:
    bool GetProxy();

private:
    sptr<IBundleMgr> sptrBundleMgr_;
    std::mutex mutex_;
    sptr<PrintBMSDeathRecipient> printBMSDeath_;
};
}  // namespace OHOS

#endif  // PRINT_BMS_HELPER_H