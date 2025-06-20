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

#include <ani.h>
#include "ani_print_task_helper.h"
#include "print_base_ani_util.h"
#include "print_object_ani_util.h"
#include "print_log.h"
namespace OHOS::Print {
ani_object AniPrintTaskHelper::CreatePrintTask(ani_env *env, AniPrintTask* nativePrintTask)
{
    if (nativePrintTask == nullptr) {
        PRINT_HILOGE("nativePrintTask is a nullptr");
        return nullptr;
    }

    static const char *className = "L@ohos/print/print/PrintTaskImpl;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        PRINT_HILOGE("[ANI] Not found className");
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor)) {
        PRINT_HILOGE("[ANI] Not found ctor");
        return nullptr;
    }

    ani_object obj;
    if (ANI_OK !=env->Object_New(cls, ctor, &obj, reinterpret_cast<ani_long>(nativePrintTask))) {
        PRINT_HILOGE("New Context Fail");
        return nullptr;
    }
    return obj;
}

AniPrintTask* AniPrintTaskHelper::UnwrappPrintTask(ani_env *env, ani_object object)
{
    if (env == nullptr) {
        PRINT_HILOGE("env is a nullptr");
        return nullptr;
    }
    ani_long printTask;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativeTask", &printTask)) {
        PRINT_HILOGE("UnwrappPrintTask Fail");
        return nullptr;
    }
    return reinterpret_cast<AniPrintTask *>(printTask);
}
}  // namespace OHOS::Print