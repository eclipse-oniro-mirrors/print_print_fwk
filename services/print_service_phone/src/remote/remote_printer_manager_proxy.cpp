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

#include "remote_printer_manager.h"

#include "i_print_feature.h"
#include "print_feature_plugin_manager.h"
#include "print_log.h"

namespace OHOS::Print {

RemotePrinterManager &RemotePrinterManager::GetInstance()
{
    static RemotePrinterManager instance;
    return instance;
}

IRemotePrinterManager *RemotePrinterManager::GetRemoteInterface(IPrintFeature *feature)
{
    if (feature == nullptr) {
        return nullptr;
    }
    return static_cast<IRemotePrinterManager *>(
        feature->QueryInterface(PrintFeatureIid::IID_REMOTE_PRINTER_MANAGER));
}

void RemotePrinterManager::SetEventHandler(IRemotePrinterEventHandler *handler)
{
    IRemotePrinterEventHandler *localHandler = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        handler_ = handler;
        localHandler = handler_;
    }

    auto &manager = PrintFeaturePluginManager::GetInstance();
    if (!manager.IsFeatureLoaded(PrintFeatureType::REMOTE_PRINTER_MANAGER)) {
        return;
    }
    auto guard = manager.AcquireFeature(PrintFeatureType::REMOTE_PRINTER_MANAGER);
    auto remote = GetRemoteInterface(guard.Get());
    if (remote != nullptr) {
        remote->SetEventHandler(localHandler);
    }
}

void RemotePrinterManager::StartPrinterDiscovery()
{
    IRemotePrinterEventHandler *localHandler = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        localHandler = handler_;
    }

    auto guard = PrintFeaturePluginManager::GetInstance().AcquireFeature(PrintFeatureType::REMOTE_PRINTER_MANAGER);
    auto remote = GetRemoteInterface(guard.Get());
    if (remote == nullptr) {
        PRINT_HILOGE("RemotePrinter plugin not available");
        return;
    }
    remote->SetEventHandler(localHandler);
    remote->StartPrinterDiscovery();
}

bool RemotePrinterManager::StopPrinterDiscovery()
{
    auto &manager = PrintFeaturePluginManager::GetInstance();
    if (!manager.IsFeatureLoaded(PrintFeatureType::REMOTE_PRINTER_MANAGER)) {
        return true;
    }
    auto guard = manager.AcquireFeature(PrintFeatureType::REMOTE_PRINTER_MANAGER);
    auto remote = GetRemoteInterface(guard.Get());
    if (remote == nullptr) {
        return true;
    }
    return remote->StopPrinterDiscovery();
}

bool RemotePrinterManager::Disconnect()
{
    auto &manager = PrintFeaturePluginManager::GetInstance();
    if (!manager.IsFeatureLoaded(PrintFeatureType::REMOTE_PRINTER_MANAGER)) {
        return true;
    }
    auto guard = manager.AcquireFeature(PrintFeatureType::REMOTE_PRINTER_MANAGER);
    auto remote = GetRemoteInterface(guard.Get());
    if (remote == nullptr) {
        return true;
    }
    return remote->Disconnect();
}

void RemotePrinterManager::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    handler_ = nullptr;
}

} // namespace OHOS::Print
