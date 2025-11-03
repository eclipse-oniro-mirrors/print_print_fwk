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
#ifndef OHOS_PRINT_CALLBACK_ANI_UTIL_H
#define OHOS_PRINT_CALLBACK_ANI_UTIL_H

#include <ani.h>
#include <string>
namespace OHOS::Print {
    bool AsyncCallback(ani_env *env, ani_object call, ani_object stsErrCode, ani_object retObj);
    bool StsCallback(ani_env *env, ani_object call, ani_object retObj);
    bool AsyncCallbackArray(ani_env *env, ani_object call, ani_object error, ani_object result);
    ani_object CreateStsError(ani_env *env, ani_int code, const std::string& msg = "");
}  // namespace OHOS::Print
#endif  // OHOS_PRINT_CALLBACK_ANI_UTIL_H