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
#include "print_base_ani_util.h"
#include "print_log.h"

namespace OHOS::Print {

ani_object CreateInt(ani_env *env, ani_int value)
{
    ani_class cls;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass("std.core.Int", &cls)) != ANI_OK) {
        PRINT_HILOGE("FindClass status : %{public}d", status);
        return nullptr;
    }
    ani_method ctor;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "i:", &ctor)) != ANI_OK) {
        PRINT_HILOGE("Class_FindMethod status : %{public}d", status);
        return nullptr;
    }
    ani_object object;
    if ((status = env->Object_New(cls, ctor, &object, value)) != ANI_OK) {
        PRINT_HILOGE("Object_New status : %{public}d", status);
        return nullptr;
    }
    return object;
}

ani_object CreateBoolean(ani_env *env, ani_boolean value)
{
    if (env == nullptr) {
        PRINT_HILOGE("null env");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass("std.core.Boolean", &cls)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d", status);
        return nullptr;
    }
    ani_method ctor = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "z:", &ctor)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d", status);
        return nullptr;
    }
    ani_object obj = nullptr;
    if ((status = env->Object_New(cls, ctor, &obj, value)) != ANI_OK) {
        PRINT_HILOGE("status: %{public}d", status);
        return nullptr;
    }
    return obj;
}

ani_string CreateAniString(ani_env *env, const std::string &str)
{
    if (env == nullptr) {
        PRINT_HILOGE("env is nullptr");
        return nullptr;
    }
    ani_string aniStr = nullptr;
    ani_status status = env->String_NewUTF8(str.c_str(), str.size(), &aniStr);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return nullptr;
    }
    return aniStr;
}

ani_object CreateAniStringArray(ani_env *env, const std::vector<std::string>& strs)
{
    if (env == nullptr) {
        PRINT_HILOGE("env is nullptr");
        return nullptr;
    }
    ani_object arrayObj = nullptr;
    ani_class arrayCls = nullptr;
    ani_method arrayCtor;
    ani_string aniStr = nullptr;
    ani_status status = ANI_ERROR;
    constexpr const char *classArray = "escompat.Array";
    status = env->FindClass(classArray, &arrayCls);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return nullptr;
    }
    status = env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor);
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return nullptr;
    }
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, strs.size());
    if (status != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return nullptr;
    }
    for (size_t i = 0; i < strs.size(); i++) {
        aniStr = nullptr;
        status = env->String_NewUTF8(strs[i].c_str(), strs[i].size(), &aniStr);
        if (aniStr == nullptr) {
            PRINT_HILOGE("null aniStr");
            return nullptr;
        }
        if (status != ANI_OK) {
            PRINT_HILOGE("status : %{public}d", status);
            return nullptr;
        }
        constexpr const char *SET_OBJECT_VOID_SIGNATURE = "iC{std.core.Object}:";
        status = env->Object_CallMethodByName_Void(arrayObj, "$_set", SET_OBJECT_VOID_SIGNATURE, i, aniStr);
        if (status != ANI_OK) {
            PRINT_HILOGE("status : %{public}d", status);
            return nullptr;
        }
    }
    return arrayObj;
}


ani_enum_item CreateEnumByIndex(ani_env *env, const std::string &enumDescriptor, ani_size enumIndex)
{
    if (env == nullptr) {
        PRINT_HILOGE("env is nullptr");
        return nullptr;
    }
    ani_enum enumType;
    if (ANI_OK != env->FindEnum(enumDescriptor.c_str(), &enumType)) {
        PRINT_HILOGE("Find Enum Faild");
        return nullptr;
    }

    ani_enum_item enumItem;
    if (ANI_OK != env->Enum_GetEnumItemByIndex(enumType, enumIndex, &enumItem)) {
        PRINT_HILOGE("Enum_GetEnumItemByIndex FAILD");
        return nullptr;
    }
    return enumItem;
}

ani_object CreateEnumArray(ani_env *env, const std::string &enumDescriptor, std::vector<uint32_t> enumIndexArray)
{
    if (env == nullptr) {
        PRINT_HILOGE("env is nullptr");
        return nullptr;
    }
    ani_class arrayCls = nullptr;
    ani_status status = env->FindClass("escompat.Array", &arrayCls);
    if (status != ANI_OK) {
        PRINT_HILOGE("[ANI] find class fail");
        return nullptr;
    }
    ani_method arrayCtor = nullptr;
    status = env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor);
    if (status != ANI_OK) {
        PRINT_HILOGE("[ANI] Class_FindMethod Failed");
        return nullptr;
    }
    ani_size length = enumIndexArray.size();
    ani_object arrayObj = nullptr;
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, length);
    if (status != ANI_OK) {
        PRINT_HILOGE("Object_New failed %{public}d", status);
        return nullptr;
    }

    for (size_t i = 0; i < enumIndexArray.size(); i++) {
        ani_enum_item item = CreateEnumByIndex(env, enumDescriptor, enumIndexArray[i]);
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "iC{std.core.Object}:", i, item)) {
            PRINT_HILOGE("Set Array item Failed");
            return nullptr;
        }
    }
    return arrayObj;
}

ani_object CreateObject(ani_env *env, const char *signature, const char* className)
{
    if (env == nullptr) {
        PRINT_HILOGE("env is nullptr");
        return nullptr;
    }
    ani_object obj = {};
    ani_class cls {};
    if (ANI_OK != env->FindClass(className, &cls)) {
        PRINT_HILOGE("[ANI] find class fail");
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", signature, &ctor)) {
        PRINT_HILOGE("[ANI] find method fail");
        return nullptr;
    }

    if (ANI_OK != env->Object_New(cls, ctor, &obj)) {
        PRINT_HILOGE("Create Object Failed");
        return nullptr;
    }
    return obj;
}

bool GetStdString(ani_env *env, ani_string str, std::string &res)
{
    if (env == nullptr) {
        PRINT_HILOGE("env is nullptr");
        return false;
    }
    ani_size sz {};
    ani_status status = ANI_ERROR;
    if ((status = env->String_GetUTF8Size(str, &sz)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }
    res.resize(sz + 1);
    if ((status = env->String_GetUTF8SubString(str, 0, sz, res.data(), res.size(), &sz)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return false;
    }
    res.resize(sz);
    return true;
}

bool GetStdStringArray(ani_env *env, ani_object param, std::vector<std::string> &res)
{
    if (env == nullptr) {
        PRINT_HILOGE("env is nullptr");
        return false;
    }
    ani_double length = 0.0;
    ani_status status = ANI_ERROR;
    status = env->Object_GetPropertyByName_Double(param, "length", &length);
    if (status != ANI_OK) {
        PRINT_HILOGE("Object_GetPropertyByName_Double fail, status = %{public}u", status);
        return false;
    }
    for (int32_t i = 0; i < static_cast<int32_t>(length); i++) {
        ani_ref stringEntryRef = nullptr;
        status = env->Object_CallMethodByName_Ref(param, "$_get",
            "I:Lstd/core/Object;", &stringEntryRef, i);
        if (status != ANI_OK) {
            PRINT_HILOGE("Object_CallMethodByName_Ref fail, status = %{public}u", status);
            return false;
        }
        std::string file;
        if (!GetStdString(env, static_cast<ani_string>(stringEntryRef), file)) {
            PRINT_HILOGE("GetStdString fail");
            return false;
        }
        res.emplace_back(file);
    }
    return true;
}

bool GetEnumValueInt(ani_env *env, ani_enum_item enumObj, uint32_t& enumValue)
{
    if (env == nullptr) {
        PRINT_HILOGE("env is nullptr");
        return false;
    }
    ani_int result = 0;
    env->EnumItem_GetValue_Int(enumObj, &result);
    enumValue = result;
    return true;
}
}  // namespace OHOS::Print