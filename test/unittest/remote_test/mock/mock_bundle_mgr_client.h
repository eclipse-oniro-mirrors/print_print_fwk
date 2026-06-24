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

#ifndef MOCK_BUNDLE_MGR_CLIENT_H
#define MOCK_BUNDLE_MGR_CLIENT_H

#include <gmock/gmock.h>
#include "bundle_mgr_client.h"
#include "bundle_info.h"

namespace OHOS::AppExecFwk {

class MockBundleMgrClient : public BundleMgrClient {
public:
    MockBundleMgrClient() = default;
    virtual ~MockBundleMgrClient() = default;

    MOCK_METHOD4(GetBundleInfo, bool(const std::string &bundleName, const int32_t flags, 
                                      BundleInfo &bundleInfo, int32_t userId));
};

} // namespace OHOS::AppExecFwk

#endif // MOCK_BUNDLE_MGR_CLIENT_H