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
bool GetIntByName(ani_env *env, ani_ref param, const char *name, int32_t &value)
{
    ani_int res;
    ani_status status;

    status = env->Object_GetFieldByName_Int(static_cast<ani_object>(param), name, &res);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }

    value = static_cast<int32_t>(res);
    return true;
}

bool GetDoubleArrayOrUndefined(ani_env *env, ani_object param, const char *name, std::vector<ani_double> &res)
{
    ani_ref arrayObj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status;
    ani_double length;
    std::string str;

    if ((status = env->Object_GetFieldByName_Ref(param, name, &arrayObj)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(arrayObj, &isUndefined)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        PRINT_HILOGE("%{public}s : undefined", name);
        return false;
    }

    status = env->Object_GetPropertyByName_Double(reinterpret_cast<ani_object>(arrayObj), "length", &length);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }
    for (int32_t i = 0; i < static_cast<int32_t>(length); i++) {
        ani_double value;
        if ((status = env->Object_CallMethodByName_Double(
            reinterpret_cast<ani_object>(arrayObj), "doubleValue", nullptr, &value)) != ANI_OK) {
            PRINT_HILOGE("status : %{public}d", status);
            return false;
        }
        res.push_back(value);
    }
    return true;
}

bool GetStringArrayOrUndefined(ani_env *env, ani_object param, const char *name, std::vector<std::string> &res)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status;
    ani_size size = 0;
    ani_size i;
    ani_ref ref;
    std::string str;

    if ((status = env->Object_GetFieldByName_Ref(param, name, &obj)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        PRINT_HILOGE("%{public}s : undefined", name);
        return false;
    }

    if ((status = env->Array_GetLength(reinterpret_cast<ani_array>(obj), &size)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }

    for (i = 0; i < size; i++) {
        if ((status = env->Array_Get_Ref(reinterpret_cast<ani_array_ref>(obj), i, &ref)) != ANI_OK) {
            PRINT_HILOGE("status : %{public}d, index: %{public}zu", status, i);
            return false;
        }

        str = "";
        if (!GetStdString(env, reinterpret_cast<ani_string>(ref), str)) {
            PRINT_HILOGE("GetStdString failed, index: %{public}zu", i);
            return false;
        }

        res.push_back(str);
    }

    return true;
}

bool GetEnumArrayOrUndefined(ani_env *env, ani_object param, const char *name, std::vector<uint32_t> &res)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status;
    ani_size size = 0;
    ani_size i;
    ani_ref ref;
    std::string str;

    if ((status = env->Object_GetFieldByName_Ref(param, name, &obj)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        PRINT_HILOGE("%{public}s : undefined", name);
        return false;
    }

    if ((status = env->Array_GetLength(reinterpret_cast<ani_array>(obj), &size)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }

    for (i = 0; i < size; i++) {
        if ((status = env->Array_Get_Ref(reinterpret_cast<ani_array_ref>(obj), i, &ref)) != ANI_OK) {
            PRINT_HILOGE("status : %{public}d, index: %{public}zu", status, i);
            return false;
        }
        ani_int enumValue;
        env->EnumItem_GetValue_Int(reinterpret_cast<ani_enum_item>(ref), &enumValue);
        res.push_back(enumValue);
    }
    return true;
}

bool GetDoubleOrUndefined(ani_env *env, ani_object param, const char *name, ani_double &value)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;

    if ((status = env->Object_GetFieldByName_Ref(param, name, &obj)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        PRINT_HILOGE("%{public}s : undefined", name);
        return false;
    }
    if ((status = env->Object_CallMethodByName_Double(
        reinterpret_cast<ani_object>(obj), "doubleValue", nullptr, &value)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }
    return true;
}

bool GetBoolOrUndefined(ani_env *env, ani_object param, const char *name)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;
    ani_boolean res = 0.0;

    if ((status = env->Object_GetFieldByName_Ref(param, name, &obj)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return res;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return res;
    }
    if (isUndefined) {
        PRINT_HILOGE("%{public}s : undefined", name);
        return res;
    }
    if ((status = env->Object_CallMethodByName_Boolean(
        reinterpret_cast<ani_object>(obj), "booleanValue", nullptr, &res)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return res;
    }
    return res;
}

bool GetStringOrUndefined(ani_env *env, ani_ref param, const char *name, std::string &res)
{
    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;

    if ((status = env->Object_GetFieldByName_Ref(static_cast<ani_object>(param), name, &obj)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        PRINT_HILOGE("%{public}s : undefined", name);
        return false;
    }
    if (!GetStdString(env, reinterpret_cast<ani_string>(obj), res)) {
        PRINT_HILOGE("GetStdString failed");
        return false;
    }
    return true;
}

bool GetRefFieldByName(ani_env *env, ani_ref param, const char *name, ani_ref &ref)
{
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetFieldByName_Ref(static_cast<ani_object>(param), name, &ref)) != ANI_OK) {
        PRINT_HILOGE("Object_GetFieldByName_Ref failed, status : %{public}d", status);
        return false;
    }

    ani_boolean isUndefined = true;
    if ((status = env->Reference_IsUndefined(ref, &isUndefined)) != ANI_OK) {
        PRINT_HILOGE("Reference_IsUndefined failed, status : %{public}d", status);
        return false;
    }
    if (isUndefined) {
        PRINT_HILOGE("wantParams is undefined");
        return false;
    }
    return true;
}

// SET
bool SetFieldDouble(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, double value)
{
    ani_field field = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK) {
        PRINT_HILOGE("find status : %{public}d", status);
        return false;
    }
    status = env->Object_SetField_Double(object, field, value);
    if (status != ANI_OK) {
        PRINT_HILOGE("set field status : %{public}d", status);
        return false;
    }
    return true;
}

bool SetFieldDoubleArray(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName,
    const std::vector<double> &values)
{
    ani_field field = nullptr;
    ani_class arrayCls = nullptr;
    ani_method arrayCtor;
    ani_object arrayObj;
    
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }

    status = env->FindClass("Lescompat/Array;", &arrayCls);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }

    status = env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }

    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, values.size());
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }

    for (size_t i = 0; i < values.size(); i++) {
        status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "ID:V", i, values[i]);
        if (status != ANI_OK) {
            PRINT_HILOGE("status : %{public}d", status);
            return false;
        }
    }

    status = env->Object_SetField_Ref(object, field, arrayObj);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }

    return true;
}

bool SetFieldBoolean(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, bool value)
{
    ani_field field = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }
    status = env->Object_SetField_Boolean(object, field, value);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }
    return true;
}

bool SetFieldInt(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, int32_t value)
{
    ani_field field = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        PRINT_HILOGE("status : %{public}s", fieldName.c_str());
        return false;
    }
    status = env->Object_SetField_Int(object, field, value);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        PRINT_HILOGE("status : %{public}s", fieldName.c_str());
        return false;
    }
    return true;
}

bool SetFieldEnum(ani_env *env, ani_object object, const std::string &fieldName,
    const std::string &signature, ani_enum_item item)
{
    if (ANI_OK != env->Object_CallMethodByName_Void(object, fieldName.c_str(), signature.c_str(), item)) {
        PRINT_HILOGE("SetFieldEnum failed");
        return false;
    }
    return true;
}

bool SetFieldEnumArray(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, ani_object items)
{
    ani_field field = nullptr;

    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }

    status = env->Object_SetField_Ref(object, field, items);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }
    return true;
}

bool SetFieldRef(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName, ani_ref value)
{
    ani_field field = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK) {
        PRINT_HILOGE("FindField %{public}s failed, status: %{public}d", fieldName.c_str(), status);
        return false;
    }
    status = env->Object_SetField_Ref(object, field, value);
    if (status != ANI_OK) {
        PRINT_HILOGE("SetField_Ref %{public}s failed, status: %{public}d", fieldName.c_str(), status);
        return false;
    }
    return true;
}

bool SetFieldString(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName,
    const std::string &value)
{
    ani_field field = nullptr;
    ani_string string = nullptr;
    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);

    PRINT_HILOGI("fieldName : %{public}s", fieldName.c_str());

    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }

    if (value.empty()) {
        ani_ref nullRef = nullptr;
        if ((status = env->GetNull(&nullRef)) != ANI_OK) {
            PRINT_HILOGE("status : %{public}d", status);
            return false;
        }
        if ((status = env->Object_SetField_Ref(object, field, nullRef)) != ANI_OK) {
            PRINT_HILOGE("status : %{public}d", status);
            return false;
        }
        return true;
    }

    if ((status = env->String_NewUTF8(value.c_str(), value.size(), &string)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }

    if ((status = env->Object_SetField_Ref(object, field, string)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }
    return true;
}

bool SetFieldStringArray(ani_env *env, ani_class cls, ani_object object, const std::string &fieldName,
    const std::vector<std::string> &values)
{
    ani_field field = nullptr;
    ani_class arrayCls = nullptr;
    ani_method arrayCtor;
    ani_object arrayObj;
    ani_string string = nullptr;

    ani_status status = env->Class_FindField(cls, fieldName.c_str(), &field);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }

    status = env->FindClass("Lescompat/Array;", &arrayCls);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }

    status = env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }

    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, values.size());
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }

    for (size_t i = 0; i < values.size(); i++) {
        string = nullptr;
        status = env->String_NewUTF8(values[i].c_str(), values[i].size(), &string);
        if (status != ANI_OK) {
            PRINT_HILOGE("status : %{public}d", status);
            return false;
        }

        status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", i, string);
        if (status != ANI_OK) {
            PRINT_HILOGE("status : %{public}d", status);
            return false;
        }
    }
    status = env->Object_SetField_Ref(object, field, arrayObj);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }

    return true;
}

}  // namespace OHOS::Print