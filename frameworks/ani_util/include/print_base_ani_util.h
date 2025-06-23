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
#ifndef OHOS_COMMON_PRINT_ANI_UTIL_H
#define OHOS_COMMON_PRINT_ANI_UTIL_H

#include <ani.h>
#include <string>
#include <vector>
namespace OHOS::Print {
ani_object CreateDouble(ani_env *env, ani_double value);
ani_object CreateBoolean(ani_env *env, ani_boolean value);
ani_string CreateAniString(ani_env *env, const std::string &str);
ani_object CreateAniStringArray(ani_env *env, const std::vector<std::string>& strs);
ani_enum_item CreateEnumByIndex(ani_env *env, const std::string &enumDescriptor, ani_size enumIndex);
ani_object CreateEnumArray(ani_env *env, const std::string &enumDescriptor, std::vector<uint32_t> enumIndexArray);
ani_object CreateObject(ani_env *env, const char *signature, const char* className);

bool GetStdString(ani_env *env, ani_string str, std::string &res);
bool GetStdStringArray(ani_env *env, ani_object param, std::vector<std::string> &res);
bool GetEnumValueInt(ani_env *env, ani_enum_item enumObj, uint32_t& enumValue);
}  // namespace OHOS::Print
#endif  // OHOS_COMMON_PRINT_ANI_UTIL_H