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
#ifndef OHOS_SCAN_ANI_CALLBACK_H
#define OHOS_SCAN_ANI_CALLBACK_H

#include <ani.h>
#include "scan_callback.h"

namespace OHOS::Scan {
class ScanAniCallback : public ScanCallbackStub {
public:
    explicit ScanAniCallback(ani_env *env, ani_object callback);
    ~ScanAniCallback() override = default;

    bool OnCallback(uint32_t state, const ScanDeviceInfo &info) override;
    bool OnCallbackSync(uint32_t state, const ScanDeviceInfoSync &info) override;
    bool OnGetDevicesList(std::vector<ScanDeviceInfo> &info) override;

private:
    ani_env *env_;
    ani_object callback_;
};
}
#endif
