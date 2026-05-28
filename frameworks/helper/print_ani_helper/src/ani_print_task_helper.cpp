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

ani_object AniPrintTaskHelper::CreatePrintTask(ani_env *env, std::shared_ptr<AniPrintTask> nativePrintTask)
{
    if (env == nullptr) {
        PRINT_HILOGE("env is a nullptr");
        return nullptr;
    }
    if (nativePrintTask == nullptr) {
        PRINT_HILOGE("nativePrintTask is a nullptr");
        return nullptr;
    }

    static const char *className = "@ohos.print.print.PrintTaskImpl";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        PRINT_HILOGE("[ANI] Not found className");
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "l:", &ctor)) {
        PRINT_HILOGE("[ANI] Not found ctor");
        return nullptr;
    }

    uint64_t taskId = ++GetPrintTaskIdCounter();
    {
        std::lock_guard<std::mutex> lock(GetPrintTaskMapMutex());
        GetPrintTaskMap()[taskId] = nativePrintTask;
    }

    ani_object obj;
    if (ANI_OK != env->Object_New(cls, ctor, &obj, static_cast<ani_long>(taskId))) {
        PRINT_HILOGE("New Context Fail");
        std::lock_guard<std::mutex> lock(GetPrintTaskMapMutex());
        GetPrintTaskMap().erase(taskId);
        return nullptr;
    }
    return obj;
}

std::shared_ptr<AniPrintTask> AniPrintTaskHelper::UnwrappPrintTask(ani_env *env, ani_object object)
{
    if (env == nullptr) {
        PRINT_HILOGE("env is a nullptr");
        return nullptr;
    }
    ani_long taskId = 0;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativeTask", &taskId)) {
        PRINT_HILOGE("UnwrappPrintTask Fail");
        return nullptr;
    }
    uint64_t id = static_cast<uint64_t>(taskId);
    std::lock_guard<std::mutex> lock(GetPrintTaskMapMutex());
    auto it = GetPrintTaskMap().find(id);
    if (it == GetPrintTaskMap().end()) {
        PRINT_HILOGE("PrintTask not found in map, taskId=%{public}llu", static_cast<unsigned long long>(id));
        return nullptr;
    }
    return it->second;
}
}  // namespace OHOS::Print