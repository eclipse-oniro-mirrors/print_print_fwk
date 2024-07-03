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

#ifndef SCAN_OPTION_DESCRIPTOR_HELPER
#define SCAN_OPTION_DESCRIPTOR_HELPER

#include <map>
#include "napi/native_api.h"
#include "scan_option_descriptor.h"

namespace OHOS::Scan {
class ScanOptionDescriptorHelper {
public:
    static napi_value MakeJsObject(napi_env env, const ScanOptionDescriptor &info);
    static std::shared_ptr<ScanOptionDescriptor> BuildFromJs(napi_env env, napi_value jsValue);
private:
    static napi_value GetValueFromJs(napi_env env, napi_value jsValue,
                                     std::shared_ptr<ScanOptionDescriptor> &nativeObj);
    static napi_value ObjSetOptionConstraintString(napi_env env, napi_value jsValue,
                                            std::shared_ptr<ScanOptionDescriptor> &nativeObj);
    static napi_value ObjSetOptionConstraintNumber(napi_env env, napi_value jsValue,
                                            std::shared_ptr<ScanOptionDescriptor> &nativeObj);
    static napi_value ObjSetOptionConstraintRange(napi_env env, napi_value jsValue,
                                        std::shared_ptr<ScanOptionDescriptor> &nativeObj);
};
}  // namespace OHOS::Scan
#endif  // SCAN_OPTION_DESCRIPTOR_HELPER
