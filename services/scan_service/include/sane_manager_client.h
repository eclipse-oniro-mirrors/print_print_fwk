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

#ifndef BACKENDS_MANAGER_CLIENT_H
#define BACKENDS_MANAGER_CLIENT_H

#include <condition_variable>
#include <map>
#include <mutex>
#include <shared_mutex>
#include "isane_backends.h"
#include "iremote_object.h"
#include "refbase.h"
#include "sane_backends_proxy.h"
#include "sane_sa_death_recipient.h"
#include "scan_log.h"
#include "scan_constant.h"
namespace OHOS::Scan {
class SaneManagerClient : public RefBase {
public:
    SaneManagerClient();
    ~SaneManagerClient();
    static sptr<SaneManagerClient> GetInstance();
    SaneStatus SaneInit();
    SaneStatus SaneExit();
    SaneStatus SaneOpen(const std::string& scannerId);
    SaneStatus SaneClose(const std::string& scannerId);
    SaneStatus SaneStart(const std::string& scannerId);
    SaneStatus SaneCancel(const std::string& scannerId);
    SaneStatus SaneGetOptionDescriptor(const std::string& scannerId, const int32_t& option, SaneOptionDescriptor& desc);
    SaneStatus SaneGetParameters(const std::string& scannerId, SaneParameters& params);
    SaneStatus SaneGetDevices(std::vector<SaneDevice>& deviceInfos);
    SaneStatus SaneControlOption(const std::string& scannerId, SaneControlParam& controlParam, SaneOutParam& outParam);
    SaneStatus SaneRead(const std::string& scannerId, const int32_t buflen, SanePictureData& pictureData);
    SaneStatus UnloadSystemAbility();
    void LoadSystemAbilitysuccess(const sptr<IRemoteObject> &remoteObject);
    void LoadSystemAbilityFail();
    void OnRemoteSaDied(const wptr<IRemoteObject>& object);

private:
    bool LoadSaneService();
    sptr<ISaneBackends> GetSaneServiceProxy();
    sptr<OHOS::Scan::ISaneBackends> proxy_;
    sptr<SaneSaDeathRecipient> deathRecipient_;
    static sptr<SaneManagerClient> instance_;
    static std::mutex instanceLock_;
    static std::shared_mutex serviceLock_;
    std::condition_variable_any syncCon_;
};
} // namespage OHOS::Scan
#endif // BACKENDS_MANAGER_CLIENT_H