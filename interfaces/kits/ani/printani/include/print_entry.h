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

#ifndef PRINT_ENTRY_H
#define PRINT_ENTRY_H

#include <memory>
#include <string>
#include <stdint.h>

#include "ui_content.h"
#include "modal_ui_extension_config.h"
#include "want.h"
#include "ipc_skeleton.h"
#include "bundle_mgr_client.h"
#include "iremote_object.h"
#include "print_utils.h"

namespace OHOS::Print {
class PrintEntry {
public:
    PrintEntry();
    ~PrintEntry();
    static std::shared_ptr<PrintEntry> GetInstance();
    int32_t StartPrint(const std::vector<std::string>& files);
    int32_t On(const std::string& type);
    int32_t Off(const std::string& type);
private:
    uint32_t CallSpooler(const std::shared_ptr<AdapterParam> &adapterParam,
        const std::vector<std::string>& files);
};
}  // namespace OHOS::Print
#endif  // PRINT_ENTRY_H
