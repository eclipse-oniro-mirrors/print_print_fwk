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
#ifndef PPD_INFO_HELPER_H
#define PPD_INFO_HELPER_H

#include <map>
#include "napi/native_api.h"
#include "ppd_info.h"

namespace OHOS::Print {
class PodInfoHelper {
public:
    static napi_value MakeJsSimpleObject(napi_env env, const PpdInfo &info);
    static std::shared_ptr<PpdInfo> BuildFromJs(napi_env env, napi_value jsValue);

private:

};
}  // namespace OHOS::Print
#endif  // PRINT_JOB_HELPER_H
