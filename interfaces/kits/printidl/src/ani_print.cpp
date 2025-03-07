/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ani.h>
#include <array>
#include <iostream>
#include <vector>
#include "print_log.h"
#include "print_constant.h"
#include "print_entry.h"
#include "print_callback.h"

using namespace OHOS::Print;
std::string ANIUtils_ANIStringToStdString(ani_env *env, ani_string aniStr)
{
    ani_size  strSize;
    env->String_GetUTF8Size(aniStr, &strSize);
   
    std::vector<char> buffer(strSize + 1);
    char* utf8Buffer = buffer.data();

    ani_size bytesWritten = 0;
    env->String_GetUTF8(aniStr, utf8Buffer, strSize + 1, &bytesWritten);
    
    utf8Buffer[bytesWritten] = '\0';
    std::string content = std::string(utf8Buffer);
    return content;
}

static ani_int PrintAsyncCallback([[maybe_unused]] ani_env *env,
    [[maybe_unused]] ani_object object, ani_object arrayObj)
{
    PRINT_HILOGI("enter PrintAsyncCallback");
    ani_double length;
    ani_status status = ANI_ERROR;
    status = env->Object_GetPropertyByName_Double(arrayObj, "length", &length);
    if (status != ANI_OK) {
        PRINT_HILOGE("Object_GetPropertyByName_Double fail, status = %{public}u", status);
        return status;
    }
    std::vector<std::string> files;
    for (int i = 0; i < int(length); i++) {
        ani_ref stringEntryRef;
        status = env->Object_CallMethodByName_Ref(arrayObj, "$_get",
            "I:Lstd/core/Object;", &stringEntryRef, (ani_int)i);
        if (status != ANI_OK) {
            PRINT_HILOGE("Object_CallMethodByName_Ref fail, status = %{public}u", status);
            return status;
        }
        files.emplace_back(ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(stringEntryRef)));
    }
    for (const auto &file : files) {
        PRINT_HILOGD("Array String Content: = %{private}s", file.c_str());
    }

    int32_t ret = PrintEntry::GetInstance()->StartPrint(files);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("StartPrint error, ret = %{public}d", ret);
        status = ANI_ERROR;
    }
    return status;
}

static ani_int On([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_string string_object)
{
    PRINT_HILOGI("enter On");
    ani_size  strSize;
    env->String_GetUTF8Size(string_object, &strSize);
   
    std::vector<char> buffer(strSize + 1); // +1 for null terminator
    char* utf8Buffer = buffer.data();

    ani_size bytesWritten = 0;
    env->String_GetUTF8(string_object, utf8Buffer, strSize + 1, &bytesWritten);
    
    utf8Buffer[bytesWritten] = '\0';
    std::string content = std::string(utf8Buffer);
    PRINT_HILOGD("CallMeWithOptionalString Get = %{public}s", content.c_str());
    int32_t ret = PrintEntry::GetInstance()->On(content);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("On error, ret = %{public}d", ret);
        return ANI_ERROR;
    }
    return ANI_OK;
}

static ani_int Off([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object object, ani_string string_object)
{
    PRINT_HILOGI("enter Off");
    ani_size  strSize;
    env->String_GetUTF8Size(string_object, &strSize);
   
    std::vector<char> buffer(strSize + 1); // +1 for null terminator
    char* utf8Buffer = buffer.data();

    ani_size bytesWritten = 0;
    env->String_GetUTF8(string_object, utf8Buffer, strSize + 1, &bytesWritten);
    
    utf8Buffer[bytesWritten] = '\0';
    std::string content = std::string(utf8Buffer);
    PRINT_HILOGD("CallMeWithOptionalString Get = %{public}s", content.c_str());
    int32_t ret = PrintEntry::GetInstance()->Off(content);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("Off error, ret = %{public}d", ret);
        return ANI_ERROR;
    }
    return ANI_OK;
}

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    PRINT_HILOGI("enter ANI_Constructor");
    ani_status status = ANI_OK;
    ani_env *env;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        PRINT_HILOGE("Unsupported ANI_VERSION_1, status = %{public}u", status);
        return ANI_ERROR;
    }

    static const char *className = "Lani_print/printNative;";
    
    ani_class cls;
    status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        PRINT_HILOGE("Not found className = %{public}s, status = %{public}u", className, status);
        return status;
    }

    std::array methods = {
        ani_native_function {"printAsyncCallback", nullptr, reinterpret_cast<void *>(PrintAsyncCallback)},
        ani_native_function {"on", nullptr, reinterpret_cast<void *>(On)},
        ani_native_function {"off", nullptr, reinterpret_cast<void *>(Off)},
    };
    PRINT_HILOGD("Start bind native methods to = %{public}s", className);
    
    status = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (status != ANI_OK) {
        std::cerr << "Cannot bind native methods to '" << className << status << std::endl;
        return ANI_INVALID_ARGS;
    };
    PRINT_HILOGD("Finish bind native methods to = %{public}s", className);

    *result = ANI_VERSION_1;
    return ANI_OK;
}