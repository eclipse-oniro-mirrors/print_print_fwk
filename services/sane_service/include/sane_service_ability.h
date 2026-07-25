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

#ifndef SANE_SERVER_MANAGER_H
#define SANE_SERVER_MANAGER_H

#include <mutex>
#include <map>
#include "system_ability.h"
#include "sane_backends_stub.h"
#include "scan_log.h"
#include "scan_constant.h"
#include "sane_control_param.h"

namespace OHOS::Scan {
class SaneServerManager : public SystemAbility, public SaneBackendsStub {
    DECLARE_SYSTEM_ABILITY(SaneServerManager);

public:
    SaneServerManager(int32_t saId, bool runOnCreate);
    SaneServerManager();
    ~SaneServerManager() override = default;

    void OnStart() override;

    ErrCode SaneInit(int32_t& status) override;
    ErrCode SaneExit() override;
    ErrCode SaneOpen(const std::string &scannerId, int32_t& status) override;
    ErrCode SaneClose(const std::string &scannerId) override;
    ErrCode SaneStart(const std::string &scannerId, int32_t& status) override;
    ErrCode SaneCancel(const std::string &scannerId) override;
    ErrCode SaneGetOptionDescriptor(const std::string &scannerId, int32_t saneOption,
        SaneOptionDescriptor& saneOptDes, int32_t& status) override;
    ErrCode SaneGetParameters(const std::string &scannerId, SaneParameters& spm, int32_t& status) override;
    ErrCode SaneGetDevices(std::vector<SaneDevice>& deviceInfos, int32_t& status) override;
    ErrCode SaneControlOption(const std::string& scannerId, const SaneControlParam& controlParam,
        SaneOutParam& outParam, int32_t& status) override;
    ErrCode SaneRead(const std::string& scannerId, const int32_t buflen,
        SanePictureData& pictureData, int32_t& status) override;
    ErrCode UnloadSystemAbility() override;
private:
    bool CheckPermission();
    SANE_Handle GetScanHandle(const std::string &scannerId);
    SaneStatus GetControlOption(SANE_Handle& handle, const SaneControlParam& controlParam, SaneOutParam& outParam);
    SaneStatus SetControlOption(SANE_Handle& handle, const SaneControlParam& controlParam, SaneOutParam& outParam);
    void ConvertSaneDescriptor(const SANE_Option_Descriptor* saneDesc, SaneOptionDescriptor& saneOptDes);
    std::map<std::string, SANE_Handle> scannerHandleList_;
    std::mutex scannerHandleListlock_;
};

} // namespace  OHOS::Scan
#endif