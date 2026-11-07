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

#ifndef I_PRINT_FEATURE_H
#define I_PRINT_FEATURE_H

#include <cstdint>

namespace OHOS::Print {

enum class PrintFeatureIid : uint32_t {
    IID_UNKNOWN = 0,
    IID_REMOTE_PRINTER_MANAGER = 0x1001,
    IID_PRINT_FAILURE_AI_NOTIFIER = 0x2001,
};

class IPrintFeature {
public:
    virtual ~IPrintFeature() = default;

    virtual void *QueryInterface(PrintFeatureIid iid) = 0;
};

} // namespace OHOS::Print
#endif // I_PRINT_FEATURE_H
