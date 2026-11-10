/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef REMOTE_PRINTER_MANAGER_H
#define REMOTE_PRINTER_MANAGER_H

#include <mutex>

#include "i_print_feature.h"
#include "i_remote_printer_manager.h"
#include "print_feature_type.h"

namespace OHOS::Print {

class RemotePrinterManager {
public:
    static RemotePrinterManager &GetInstance();

    void SetEventHandler(IRemotePrinterEventHandler *handler);

    bool Disconnect();
    void StartPrinterDiscovery();
    bool StopPrinterDiscovery();
    void Reset();

private:
    RemotePrinterManager() = default;
    ~RemotePrinterManager() = default;
    RemotePrinterManager(const RemotePrinterManager &) = delete;
    RemotePrinterManager &operator=(const RemotePrinterManager &) = delete;

    static IRemotePrinterManager *GetRemoteInterface(IPrintFeature *feature);

    std::mutex mutex_;
    IRemotePrinterEventHandler *handler_ = nullptr;
};

} // namespace OHOS::Print
#endif // REMOTE_PRINTER_MANAGER_H
