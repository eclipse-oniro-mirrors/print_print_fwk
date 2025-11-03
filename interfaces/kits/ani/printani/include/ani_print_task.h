
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
#ifndef ANI_PRINT_TASK_H
#define ANI_PRINT_TASK_H

#include <vector>
#include <stdint.h>
#include <ani.h>
#include <string>
#include "ability.h"
#include "print_attributes.h"
#include "print_constant.h"
#include "print_utils.h"
#include "ui_ability_thread.h"
#include "fd_list_wrapper.h"
#include "print_ets_ui_callback.h"
#include "iprint_callback.h"
#include "modal_ui_extension_config.h"
#include "ui_content.h"

namespace OHOS::Print {
class AniPrintTask {
public:
    AniPrintTask(ani_env *env);
    ~AniPrintTask();
    int32_t StartPrint(const std::vector<std::string>& files);
    int32_t StartPrintWithContext(const std::vector<std::string>& files, std::shared_ptr<AbilityRuntime::Context> ctx);
    int32_t StartPrintWithAttributes(const std::string& jobName, std::shared_ptr<AbilityRuntime::Context> ctx,
        const PrintAttributes& attributes, const sptr<IPrintCallback> &listener);
    int32_t On(std::string type, sptr<IPrintCallback> callback);
    int32_t Off(std::string type, sptr<IPrintCallback> callback);
private:
    uint32_t CallSpooler(const std::shared_ptr<AdapterParam>& adapterParam,
        const std::vector<std::string>& files, std::shared_ptr<AbilityRuntime::Context> ctx);
    OHOS::Ace::UIContent* GetUIContent(std::shared_ptr<OHOS::AbilityRuntime::Context> ctx);
    bool CheckPermission(const std::string &name);
    ani_vm *aniVm_ = nullptr;
    std::string jobId_;
};

} // namespace OHOS::Print

#endif  // ANI_PRINT_TASK_H