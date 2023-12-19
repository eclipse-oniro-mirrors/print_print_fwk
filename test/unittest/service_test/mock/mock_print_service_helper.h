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

#ifndef MOCK_PRINT_SERVICE_HELPER_H
#define MOCK_PRINT_SERVICE_HELPER_H

#include <gmock/gmock.h>
#include "print_service_helper.h"

namespace OHOS {
namespace Print {
class MockPrintServiceHelper final : public PrintServiceHelper {
public:
    MOCK_METHOD1(CheckPermission, bool(const std::string&));
    MOCK_METHOD1(StartAbility, bool(const AAFwk::Want&));
    MOCK_METHOD1(KillAbility, bool(const std::string&));
    MOCK_METHOD2(StartPrintServiceExtension, bool(const AAFwk::Want&, int32_t));
    MOCK_METHOD0(GetBundleMgr, sptr<IRemoteObject>());
    MOCK_METHOD1(QueryAccounts, bool(std::vector<int>&));
    MOCK_METHOD3(QueryExtension, bool(sptr<AppExecFwk::IBundleMgr>, int,
                                            std::vector<AppExecFwk::ExtensionAbilityInfo>&));
    MOCK_METHOD3(QueryNameForUid, bool(sptr<AppExecFwk::IBundleMgr>, int32_t, std::string&));
    MOCK_METHOD0(IsSyncMode, bool());
};
}  // namespace Print
}  // namespace OHOS
#endif  // MOCK_PRINT_SERVICE_HELPER_H
