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
#include "print_object_ani_util.h"
#include "print_base_ani_util.h"
#include "print_log.h"

namespace OHOS::Print {
bool GetIntArrayProperty(ani_env *env, ani_object param, const char *name, std::vector<int32_t> &res)
{
    ani_ref arrayObj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;
    ani_double length = 0.0;
    std::string str;

    if ((status = env->Object_GetPropertyByName_Ref(param, name, &arrayObj)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d, name : %{public}s", status, name);
        return false;
    }
    if ((status = env->Reference_IsUndefined(arrayObj, &isUndefined)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d, name : %{public}s", status, name);
        return false;
    }
    if (isUndefined) {
        PRINT_HILOGD("%{public}s is undefined: undefined", name);
        return false;
    }

    status = env->Object_GetPropertyByName_Double(reinterpret_cast<ani_object>(arrayObj), "length", &length);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d, name : %{public}s", status, name);
        return false;
    }
    for (int32_t i = 0; i < static_cast<int32_t>(length); i++) {
        ani_int value;
        if ((status = env->Object_CallMethodByName_Int(
            reinterpret_cast<ani_object>(arrayObj), "intValue", nullptr, &value)) != ANI_OK) {
            PRINT_HILOGE("status : %{public}d, name : %{public}s", status, name);
            return false;
        }
        res.push_back(value);
    }
    return true;
}

bool GetStringArrayProperty(ani_env *env, ani_object param, const char *name, std::vector<std::string> &value)
{
    if (env == nullptr) {
        PRINT_HILOGE("null env");
        return false;
    }

    ani_ref arrayObj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;
    ani_double length = 0.0;
    std::string str;

    if ((status = env->Object_GetPropertyByName_Ref(param, name, &arrayObj)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
        return false;
    }
    if ((status = env->Reference_IsUndefined(arrayObj, &isUndefined)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
        return false;
    }
    if (isUndefined) {
        PRINT_HILOGD("%{public}s is undefined", name);
        return false;
    }

    status = env->Object_GetPropertyByName_Double(reinterpret_cast<ani_object>(arrayObj), "length", &length);
    if (status != ANI_OK) {
        PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
        return false;
    }

    for (int i = 0; i < static_cast<int>(length); i++) {
        ani_ref stringEntryRef;
        status = env->Object_CallMethodByName_Ref(reinterpret_cast<ani_object>(arrayObj),
            "$_get", "i:C{std.core.Object}", &stringEntryRef, (ani_int)i);
        if (status != ANI_OK) {
            PRINT_HILOGE("status: %{public}d, index: %{public}d, name : %{public}s", status, i, name);
            return false;
        }

        str = "";
        if (!GetStdString(env, reinterpret_cast<ani_string>(stringEntryRef), str)) {
            PRINT_HILOGE("GetStdString failed, index: %{public}d, name : %{public}s", i, name);
            return false;
        }

        value.push_back(str);
    }

    return true;
}

bool GetEnumArrayProperty(ani_env *env, ani_object param, const char *name, std::vector<uint32_t> &res)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;
    ani_size size = 0;
    ani_size i = 0;
    ani_ref ref = nullptr;
    std::string str;

    if ((status = env->Object_GetPropertyByName_Ref(param, name, &obj)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d, name : %{public}s", status, name);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d, name : %{public}s", status, name);
        return false;
    }
    if (isUndefined) {
        PRINT_HILOGD("%{public}s is undefined", name);
        return false;
    }

    if ((status = env->Array_GetLength(reinterpret_cast<ani_array>(obj), &size)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }

    for (i = 0; i < size; i++) {
        if ((status = env->Array_Get(reinterpret_cast<ani_array>(obj), i, &ref)) != ANI_OK) {
            PRINT_HILOGE("status : %{public}d, index: %{public}zu", status, i);
            return false;
        }
        ani_int enumValue;
        env->EnumItem_GetValue_Int(reinterpret_cast<ani_enum_item>(ref), &enumValue);
        res.push_back(enumValue);
    }
    return true;
}

bool GetBoolProperty(ani_env *env, ani_object param, const char *name, bool value)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;
    ani_boolean res = 0.0;

    if ((status = env->Object_GetFieldByName_Ref(param, name, &obj)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d, name : %{public}s", status, name);
        return res;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d, name : %{public}s", status, name);
        return res;
    }
    if (isUndefined) {
        PRINT_HILOGD("%{public}s : undefined", name);
        return res;
    }
    if ((status = env->Object_CallMethodByName_Boolean(
        reinterpret_cast<ani_object>(obj), "booleanValue", nullptr, &res)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d, name : %{public}s", status, name);
        return res;
    }
    return res;
}

bool GetStringProperty(ani_env *env, ani_object param, const char *name, std::string &value)
{
    if (env == nullptr) {
        PRINT_HILOGE("null env");
        return false;
    }

    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;

    if ((status = env->Object_GetPropertyByName_Ref(param, name, &obj)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
        return false;
    }
    if (isUndefined) {
        PRINT_HILOGD("%{public}s : undefined", name);
        return false;
    }
    if (!GetStdString(env, reinterpret_cast<ani_string>(obj), value)) {
        PRINT_HILOGE("GetStdString failed, name : %{public}s", name);
        return false;
    }
    return true;
}

bool GetRefProperty(ani_env *env, ani_object param, const char *name, ani_ref &value)
{
    if (env == nullptr) {
        PRINT_HILOGE("null env");
        return false;
    }

    ani_status status;
    ani_boolean isUndefined = true;

    if ((status = env->Object_GetPropertyByName_Ref(param, name, &value)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
        return false;
    }
    if ((status = env->Reference_IsUndefined(value, &isUndefined)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
        return false;
    }
    if (isUndefined) {
        return false;
    }
    return true;
}

bool GetIntProperty(ani_env *env, ani_object param, const char *name, int32_t &value)
{
    if (env == nullptr) {
        PRINT_HILOGE("null env");
        return false;
    }

    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetPropertyByName_Int(param, name, &value)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
        return false;
    }
    return true;
}

bool SetIntArrayProperty(ani_env *env, ani_object param, const char *name,
    const std::vector<int32_t> &values)
{
    if (env == nullptr) {
        PRINT_HILOGE("null env");
        return false;
    }

    ani_class arrayCls = nullptr;
    ani_method arrayCtor;
    ani_object arrayObj;

    ani_status status = env->FindClass("escompat.Array", &arrayCls);
    if (status != ANI_OK) {
        PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
        return false;
    }

    status = env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor);
    if (status != ANI_OK) {
        PRINT_HILOGE("status: %{public}d", status);
        return false;
    }

    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, values.size());
    if (status != ANI_OK) {
        PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
        return false;
    }

    for (size_t i = 0; i < values.size(); i++) {
        status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "ii:V", i, values[i]);
        if (status != ANI_OK) {
            PRINT_HILOGE("status : %{public}d, name : %{public}s", status, name);
            return false;
        }
    }
    status = env->Object_SetPropertyByName_Ref(param, name, arrayObj);
    if (status != ANI_OK) {
        PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
        return false;
    }

    return true;
}

bool SetEnumProperty(ani_env *env, ani_object object, const std::string &fieldName,
    const std::string &signature, ani_enum_item item)
{
    if (ANI_OK != env->Object_CallMethodByName_Void(object, fieldName.c_str(), signature.c_str(), item)) {
        PRINT_HILOGE("SetEnumProperty failed");
        return false;
    }
    return true;
}

bool SetStringProperty(ani_env *env, ani_object param, const char *name, const std::string &value)
{
    if (env == nullptr) {
        PRINT_HILOGE("null env");
        return false;
    }
    ani_status status;
    ani_string aniString = nullptr;
    if (value.empty()) {
        ani_ref nullRef = nullptr;
        if ((status = env->GetNull(&nullRef)) != ANI_OK) {
            PRINT_HILOGE("status : %{public}d, name : %{public}s", status, name);
            return false;
        }
        if ((status = env->Object_SetPropertyByName_Ref(param, name, nullRef)) != ANI_OK) {
            PRINT_HILOGE("status : %{public}d, name : %{public}s", status, name);
            return false;
        }
        return true;
    }
    if ((status = env->String_NewUTF8(value.c_str(), value.size(), &aniString)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d, name : %{public}s", status, name);
        return false;
    }
    if ((status = env->Object_SetPropertyByName_Ref(param, name, aniString)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d, name : %{public}s", status, name);
        return false;
    }
    return true;
}

bool SetStringArrayProperty(ani_env *env, ani_object param, const char *name, const std::vector<std::string> &values)
{
    if (env == nullptr) {
        PRINT_HILOGE("null env");
        return false;
    }

    ani_class arrayCls = nullptr;
    ani_method arrayCtor;
    ani_object arrayObj;

    ani_status status = env->FindClass("escompat.Array", &arrayCls);
    if (status != ANI_OK) {
        PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
        return false;
    }

    status = env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor);
    if (status != ANI_OK) {
        PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
        return false;
    }

    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, values.size());
    if (status != ANI_OK) {
        PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
        return false;
    }
    ani_string aniString = nullptr;
    for (size_t i = 0; i < values.size(); i++) {
        aniString = nullptr;
        status = env->String_NewUTF8(values[i].c_str(), values[i].size(), &aniString);
        if (status != ANI_OK) {
            PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
            return false;
        }

        status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "iC{std.core.Object}:", i, aniString);
        if (status != ANI_OK) {
            PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
            return false;
        }
    }
    status = env->Object_SetPropertyByName_Ref(param, name, arrayObj);
    if (status != ANI_OK) {
        PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
        return false;
    }

    return true;
}

bool SetRefProperty(ani_env *env, ani_object param, const char *name, ani_ref value)
{
    if (env == nullptr) {
        PRINT_HILOGE("null env");
        return false;
    }

    ani_status status;
    if ((status = env->Object_SetPropertyByName_Ref(param, name, value)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
        return false;
    }
    return true;
}

bool SetIntProperty(ani_env *env, ani_object param, const char *name, int32_t value)
{
    if (env == nullptr) {
        PRINT_HILOGE("null env");
        return false;
    }

    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Int(param, name, value)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
        return false;
    }
    return true;
}

bool SetBoolProperty(ani_env *env, ani_object param, const char *name, bool value)
{
    if (env == nullptr) {
        PRINT_HILOGE("null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Boolean(param, name, value)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d, name : %{public}s", status, name);
        return false;
    }
    return true;
}

}  // namespace OHOS::Print