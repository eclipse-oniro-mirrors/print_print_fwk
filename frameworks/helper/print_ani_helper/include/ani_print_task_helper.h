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
#ifndef OHOS_ANI_PRINT_TASK_HELPER_H
#define OHOS_ANI_PRINT_TASK_HELPER_H

#include <ani.h>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include "ani_print_task.h"
namespace OHOS::Print {
namespace {
inline std::atomic<uint64_t>& GetPrintTaskIdCounter()
{
    static std::atomic<uint64_t> g_printTaskId{0};
    return g_printTaskId;
}
inline std::mutex& GetPrintTaskMapMutex()
{
    static std::mutex g_printTaskMapMutex;
    return g_printTaskMapMutex;
}
inline std::unordered_map<uint64_t, std::shared_ptr<AniPrintTask>>& GetPrintTaskMap()
{
    static std::unordered_map<uint64_t, std::shared_ptr<AniPrintTask>> g_printTaskMap;
    return g_printTaskMap;
}
}
class AniPrintTaskHelper {
public:
    static ani_object CreatePrintTask(ani_env *env, std::shared_ptr<AniPrintTask> nativePrintTask);
    static std::shared_ptr<AniPrintTask> UnwrappPrintTask(ani_env *env, ani_object object);
};
}  // namespace OHOS::Print
#endif  // OHOS_ANI_PRINT_TASK_HELPER_H