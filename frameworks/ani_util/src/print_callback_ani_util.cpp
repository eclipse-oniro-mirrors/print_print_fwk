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
#include "print_callback_ani_util.h"
#include "print_log.h"

namespace {
const char *INVOKE_METHOD_NAME = "invoke";
static ani_object WrapError(ani_env *env, const std::string &msg)
{
    if (env == nullptr) {
        PRINT_HILOGE("null env");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_string aniMsg = nullptr;
    if ((status = env->String_NewUTF8(msg.c_str(), msg.size(), &aniMsg)) != ANI_OK) {
        PRINT_HILOGE("String_NewUTF8 failed %{public}d", status);
        return nullptr;
    }
    ani_ref undefRef;
    if ((status = env->GetUndefined(&undefRef)) != ANI_OK) {
        PRINT_HILOGE("GetUndefined failed %{public}d", status);
        return nullptr;
    }
    ani_class cls = nullptr;
    if ((status = env->FindClass("Lescompat/Error;", &cls)) != ANI_OK) {
        PRINT_HILOGE("FindClass failed %{public}d", status);
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "Lstd/core/String;Lescompat/ErrorOptions;:V", &method)) !=
        ANI_OK) {
        PRINT_HILOGE("Class_FindMethod failed %{public}d", status);
        return nullptr;
    }
    ani_object obj = nullptr;
    if ((status = env->Object_New(cls, method, &obj, aniMsg, undefRef)) != ANI_OK) {
        PRINT_HILOGE("Object_New failed %{public}d", status);
        return nullptr;
    }
    return obj;
}
}

namespace OHOS::Print {

bool AsyncCallback(ani_env *env, ani_object call, ani_object stsErrCode, ani_object retObj)
{
    if (env == nullptr) {
        PRINT_HILOGE("env is a nullptr");
        return false;
    }
    ani_class clsCall = nullptr;
    ani_status status = env->FindClass("@ohos.print.AsyncCallbackWrapper", &clsCall);
    if (status!= ANI_OK || clsCall == nullptr) {
        PRINT_HILOGE("FindClass status: %{public}d, or null clsCall", status);
        return false;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(clsCall, "invoke", nullptr, &method)) != ANI_OK || method == nullptr) {
        PRINT_HILOGE("Class_FindMethod status: %{public}d, or null method", status);
        return false;
    }
    if (stsErrCode == nullptr) {
        ani_ref nullRef = nullptr;
        env->GetNull(&nullRef);
        stsErrCode = reinterpret_cast<ani_object>(nullRef);
    }
    if (retObj == nullptr) {
        ani_ref undefinedRef = nullptr;
        env->GetUndefined(&undefinedRef);
        retObj = reinterpret_cast<ani_object>(undefinedRef);
    }
    if ((status = env->Object_CallMethod_Void(call, method, stsErrCode, retObj)) != ANI_OK) {
        PRINT_HILOGE("Object_CallMethod_Void status: %{public}d", status);
        return false;
    }
    return true;
}

bool StsCallback(ani_env *env, ani_object call, ani_object retObj)
{
    ani_status status = ANI_ERROR;
    ani_class clsCall {};
    if ((status = env->FindClass("@ohos.print.CallbackWrapper", &clsCall)) != ANI_OK) {
        PRINT_HILOGE("FindClass fail, status: %{public}d", status);
        return false;
    }
    ani_method method = {};
    if ((status = env->Class_FindMethod(
        clsCall, INVOKE_METHOD_NAME, nullptr, &method)) != ANI_OK) {
        PRINT_HILOGE("Class_FindMethod fail, status: %{public}d", status);
        return false;
    }
    if (retObj == nullptr) {
        ani_ref undefinedRef = nullptr;
        env->GetUndefined(&undefinedRef);
        retObj = reinterpret_cast<ani_object>(undefinedRef);
    }
    if ((status = env->Object_CallMethod_Void(call, method, retObj)) != ANI_OK) {
        PRINT_HILOGE("Object_CallMethod_Void fail, status: %{public}d", status);
        return false;
    }
    return true;
}

bool AsyncCallbackArray(ani_env *env, ani_object call, ani_object error, ani_object result)
{
    ani_status status = ANI_ERROR;
    ani_class clsCall {};
    if ((status = env->FindClass("@ohos.print.AsyncCallbackArrayWrapper", &clsCall)) != ANI_OK) {
        PRINT_HILOGE("FindClass fail, status: %{public}d", status);
        return false;
    }
    ani_method method = {};
    if ((status = env->Class_FindMethod(
        clsCall, INVOKE_METHOD_NAME, nullptr, &method)) != ANI_OK) {
        PRINT_HILOGE("Class_FindMethod fail, status: %{public}d", status);
        return false;
    }
    if (result == nullptr) {
        ani_ref undefinedRef = nullptr;
        env->GetUndefined(&undefinedRef);
        result = reinterpret_cast<ani_object>(undefinedRef);
    }
    if ((status = env->Object_CallMethod_Void(call, method, error, result)) != ANI_OK) {
        PRINT_HILOGE("Object_CallMethod_Void fail, status: %{public}d", status);
        return false;
    }
    return true;
}

ani_object CreateStsError(ani_env *env, ani_int code, const std::string& msg)
{
    if (env == nullptr) {
        PRINT_HILOGE("env is nullptr");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass("@ohos.base.BusinessError", &cls)) != ANI_OK) {
        PRINT_HILOGE("FindClass failed %{public}d", status);
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "ILescompat/Error;:V", &method)) != ANI_OK) {
        PRINT_HILOGE("Class_FindMethod failed %{public}d", status);
        return nullptr;
    }
    ani_object error = WrapError(env, msg);
    if (error == nullptr) {
        PRINT_HILOGE("error nulll");
        return nullptr;
    }
    ani_object obj = nullptr;
    if ((status = env->Object_New(cls, method, &obj, code, error)) != ANI_OK) {
        PRINT_HILOGE("Object_New failed %{public}d", status);
        return nullptr;
    }
    return obj;
}

}  // namespace OHOS::Print