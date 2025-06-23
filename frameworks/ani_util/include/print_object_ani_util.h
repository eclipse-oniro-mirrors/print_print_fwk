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
#ifndef OHOS_PRINT_OBJECT_FIELD_ANI_UTIL_H
#define OHOS_PRINT_OBJECT_FIELD_ANI_UTIL_H

#include <ani.h>
#include <string>
#include <vector>
namespace OHOS::Print {
    // get property
    bool GetDoubleProperty(ani_env *env, ani_object param, const char *name, double &value);
    bool GetDoubleArrayProperty(ani_env *env, ani_object param, const char *name, std::vector<double> &value);
    bool GetStringProperty(ani_env *env, ani_object param, const char *name, std::string &value);
    bool GetStringArrayProperty(ani_env *env, ani_object param, const char *name, std::vector<std::string> &value);
    bool GetEnumArrayProperty(ani_env *env, ani_object param, const char *name, std::vector<uint32_t> &res);
    bool GetRefProperty(ani_env *env, ani_object param, const char *name, ani_ref &value);
    bool GetBoolProperty(ani_env *env, ani_object param, const char *name, bool value);

    // set property
    bool SetEnumProperty(ani_env *env, ani_object object, const std::string &fieldName, const std::string &signature,
        ani_enum_item item);
    bool SetDoubleArrayProperty(ani_env *env, ani_object param, const char *name, const std::vector<double> &values);
    bool SetStringProperty(ani_env *env, ani_object param, const char *name, const std::string &value);
    bool SetStringArrayProperty(ani_env *env, ani_object param, const char *name,
        const std::vector<std::string> &values);
    bool SetRefProperty(ani_env *env, ani_object param, const char *name, ani_ref value);
    bool SetDoubleProperty(ani_env *env, ani_object param, const char *name, double value);
    bool SetBoolProperty(ani_env *env, ani_object param, const char *name, bool value);
}  // namespace OHOS::Print
#endif  // OHOS_PRINT_OBJECT_FIELD_ANI_UTIL_H