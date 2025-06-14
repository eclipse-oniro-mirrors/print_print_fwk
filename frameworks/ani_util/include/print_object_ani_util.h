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
namespace OHOS::Print {
    bool GetIntByName(ani_env *env, ani_ref param, const char *name, int32_t &value);
    bool GetDoubleArrayOrUndefined(ani_env *env, ani_object param, const char *name, std::vector<ani_double> &res);
    bool GetStringArrayOrUndefined(ani_env *env, ani_object param, const char *name, std::vector<std::string> &res);
    bool GetEnumArrayOrUndefined(ani_env *env, ani_object param, const char *name, std::vector<uint32_t> &res);
    bool GetDoubleOrUndefined(ani_env *env, ani_object param, const char *name, ani_double &value);
    bool GetBoolOrUndefined(ani_env *env, ani_object param, const char *name);
    bool GetStringOrUndefined(ani_env *env, ani_ref param, const char *name, std::string &res);
    bool GetRefFieldByName(ani_env *env, ani_ref param, const char *name, ani_ref &ref);

    bool SetFieldDouble(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, double value);
    bool SetFieldDoubleArray(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName,
        const std::vector<double> &values);
    bool SetFieldBoolean(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, bool value);
    bool SetFieldInt(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, int32_t value);
    bool SetFieldEnum(ani_env *env, ani_object object, const std::string &fieldName, const std::string &signature,
                      ani_enum_item item);
    bool SetFieldEnumArray(ani_env *env, ani_class cls,
                           ani_object object, const std::string &fieldName, ani_object items);
    bool SetFieldRef(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, ani_ref value);
    bool SetFieldString(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName,
        const std::string &value);
    bool SetFieldStringArray(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName,
        const std::vector<std::string> &values);
}  // namespace OHOS::Print
#endif  // OHOS_PRINT_OBJECT_FIELD_ANI_UTIL_H