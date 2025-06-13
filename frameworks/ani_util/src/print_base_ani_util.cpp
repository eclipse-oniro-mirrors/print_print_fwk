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

ani_object CreateInt(ani_env *env, ani_double value)
{
    ani_class cls;
    ani_status status = ANI_ERROR;
    constexpr const char* classNameDouble = "Lstd/core/Int;";
    if ((status = env->FindClass(classNameDouble, &cls)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return nullptr;
    }
    ani_method ctor;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "I:V", &ctor)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return nullptr;
    }
    ani_object ojb;
    if ((status = env->Object_New(cls, ctor, &ojb, value)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return nullptr;
    }
    return ojb;
}

ani_object CreateDouble(ani_env *env, ani_double value)
{
    ani_class persion_cls;
    ani_status status = ANI_ERROR;
    constexpr const char* classNameDouble = "Lstd/core/Double;";
    if ((status = env->FindClass(classNameDouble, &persion_cls)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return nullptr;
    }
    ani_method personInfoCtor;
    if ((status = env->Class_FindMethod(persion_cls, "<ctor>", "D:V", &personInfoCtor)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return nullptr;
    }
    ani_object personInfoObj;
    if ((status = env->Object_New(persion_cls, personInfoCtor, &personInfoObj, value)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return nullptr;
    }
    return personInfoObj;
}

ani_object CreateBoolean(ani_env *env, ani_boolean value)
{
    ani_class persion_cls;
    ani_status status = ANI_ERROR;
    constexpr const char* classNameBoolean = "Lstd/core/Boolean;";
    if ((status = env->FindClass(classNameBoolean, &persion_cls)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return nullptr;
    }
    ani_method personInfoCtor;
    if ((status = env->Class_FindMethod(persion_cls, "<ctor>", "Z:V", &personInfoCtor)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return nullptr;
    }
    ani_object personInfoObj;
    if ((status = env->Object_New(persion_cls, personInfoCtor, &personInfoObj, value)) != ANI_OK) {
        PRINT_HILOGE("status : %{public}d", status);
        return nullptr;
    }
    return personInfoObj;
}

ani_string CreateAniString(ani_env *env, const std::string &str)
{
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
    PRINT_HILOGI("enter CreateAniStringArray");

    ani_object arrayObj = {};
    ani_ref undefinedRef = nullptr;
    if (ANI_OK != env->GetUndefined(&undefinedRef)) {
        PRINT_HILOGE("GetUndefined Failed");
        return arrayObj;
    }
    ani_array_ref arrayRef;
    if (ANI_OK != env->Array_New_Ref(nullptr, strs.size(), undefinedRef, &arrayRef)) {
        PRINT_HILOGE("Create String Array Failed");
        return arrayObj;
    }
    arrayObj = arrayRef;

    for (size_t i = 0; i < strs.size(); i++) {
        ani_string strObj;
        if (ANI_OK != env->String_NewUTF8(strs[i].c_str(), strs[i].size(), &strObj)) {
            PRINT_HILOGE("Create String Failed");
            return arrayObj;
        }
        if (ANI_OK != env->Array_Set_Ref(arrayRef, i, strObj)) {
            PRINT_HILOGE("Set Array Element Failed");
            return arrayObj;
        }
    }

    return arrayObj;
}

ani_enum_item CreateEnumByIndex(ani_env *env, const std::string &enum_descriptor, ani_int enumIndex)
{
    ani_enum enumType;
    if (ANI_OK != env->FindEnum(enum_descriptor.c_str(), &enumType)) {
        PRINT_HILOGE("Find Enum Faild");
    }

    ani_enum_item enumItem;
    if (ANI_OK != env->Enum_GetEnumItemByIndex(enumType, enumIndex, &enumItem)) {
        PRINT_HILOGE("Enum_GetEnumItemByIndex FAILD");
    }
    return enumItem;
}

ani_object CreateEnumArray(ani_env *env, const std::string &enum_descriptor, std::vector<uint32_t> enumArray)
{
    ani_class arrayCls = nullptr;
    ani_status status = env->FindClass("Lescompat/Array;", &arrayCls);
    if (status != ANI_OK) {
        PRINT_HILOGE("[ANI] find class fail");
        return nullptr;
    }
    ani_method arrayCtor;
    status = env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor);
    if (status != ANI_OK) {
        PRINT_HILOGE("[ANI] Class_FindMethod Failed");
        return nullptr;
    }
    ani_size length = enumArray.size();
    ani_object arrayObj;
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, length);
    if (status != ANI_OK) {
        PRINT_HILOGE("Object_New failed %{public}d", status);
        return nullptr;
    }

    for (size_t i = 0; i < enumArray.size(); i++) {
        ani_enum_item item = CreateEnumByIndex(env, enum_descriptor, static_cast<int32_t>(enumArray[i]));
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", i, item)) {
            PRINT_HILOGE("Set Array item Failed");
            return arrayObj;
        }
    }
    return arrayObj;
}

ani_object CreateObject(ani_env *env, const char* className, ani_class& cls)
{
    ani_object obj = {};
    if (ANI_OK != env->FindClass(className, &cls)) {
        PRINT_HILOGE("[ANI] find class fail");
        return obj;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
        PRINT_HILOGE("[ANI] find method fail");
        return obj;
    }

    if (ANI_OK != env->Object_New(cls, ctor, &obj)) {
        PRINT_HILOGE("Create Object Failed");
        return obj;
    }
    return obj;
}

bool GetStdString(ani_env *env, ani_string str, std::string &res)
{
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
    ani_double length;
    ani_status status = ANI_ERROR;
    status = env->Object_GetPropertyByName_Double(param, "length", &length);
    if (status != ANI_OK) {
        PRINT_HILOGE("Object_GetPropertyByName_Double fail, status = %{public}u", status);
        return false;
    }
    for (int32_t i = 0; i < static_cast<int32_t>(length); i++) {
        ani_ref stringEntryRef;
        status = env->Object_CallMethodByName_Ref(param, "$_get",
            "I:Lstd/core/Object;", &stringEntryRef, static_cast<ani_int>(i));
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

uint32_t GetEnumValueInt(ani_env *env, const char *enumName, ani_int enumIndex)
{
    ani_enum enumType;
    if (ANI_OK != env->FindEnum(enumName, &enumType)) {
        PRINT_HILOGE("Find Enum Faild");
    }

    ani_enum_item enumItem;
    if (ANI_OK != env->Enum_GetEnumItemByIndex(enumType, enumIndex, &enumItem)) {
        PRINT_HILOGE("Enum_GetEnumItemByIndex FAILD");
    }

    ani_int intValue;
    if (ANI_OK != env->EnumItem_GetValue_Int(enumItem, &intValue)) {
        PRINT_HILOGE("Enum_GetEnumItemByIndex FAILD");
    }
    return static_cast<uint32_t>(intValue);
}
}  // namespace OHOS::Print