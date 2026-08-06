/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_CLIENT_H
#define OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_CLIENT_H

#include <memory>
#include "errors.h"
#include "start_options.h"
#include "want.h"

namespace OHOS {
namespace AAFwk {

class AbilityManagerClient {
public:
    static std::shared_ptr<AbilityManagerClient> GetInstance()
    {
        return instance_;
    }

    static void SetInstance(std::shared_ptr<AbilityManagerClient> instance)
    {
        instance_ = instance;
    }

    static void ResetInstance()
    {
        instance_.reset();
    }

    virtual ~AbilityManagerClient() = default;

    ErrCode StartAbility(const Want &want, int requestCode = -1, int32_t userId = -1,
        uint64_t specifiedFullTokenId = 0)
    {
        return startAbilityResult_;
    }

    ErrCode StartAbility(const Want &want, sptr<IRemoteObject> callerToken,
        int requestCode = -1, int32_t userId = -1, uint64_t specifiedFullTokenId = 0)
    {
        return startAbilityResult_;
    }

    ErrCode StartAbility(const Want &want, const StartOptions &startOptions,
        sptr<IRemoteObject> callerToken, int requestCode = -1, int32_t userId = -1)
    {
        return startAbilityResult_;
    }

    ErrCode TerminateAbility(sptr<IRemoteObject> token, int resultCode, const Want *resultWant)
    {
        return terminateAbilityResult_;
    }

    // Configurable return values for testing
    ErrCode startAbilityResult_{ERR_OK};
    ErrCode terminateAbilityResult_{ERR_OK};

private:
    static std::shared_ptr<AbilityManagerClient> instance_;
};

}  // namespace AAFwk
}  // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_CLIENT_H
