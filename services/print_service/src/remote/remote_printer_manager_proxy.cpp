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

void RemotePrinterManager::SetEventHandler(IRemotePrinterEventHandler *handler)
{
    std::lock_guard<std::mutex> lock(mutex_);
    handler_ = handler;
    if (impl_ != nullptr) {
        impl_->SetEventHandler(handler);
    }
}

void RemotePrinterManager::EnsureLoaded()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (impl_ != nullptr) {
        return;
    }

    auto base = PrintFeaturePluginManager::GetInstance().GetFeature(PrintFeatureType::REMOTE_PRINTER_MANAGER);
    if (base == nullptr) {
        PRINT_HILOGE("RemotePrinter plugin not loaded");
        return;
    }

    auto remote = static_cast<IRemotePrinterManager *>(
        base->QueryInterface(PrintFeatureIid::IID_REMOTE_PRINTER_MANAGER));
    if (remote == nullptr) {
        PRINT_HILOGE("RemotePrinter plugin does not implement IRemotePrinterManager");
        return;
    }

    remote->SetEventHandler(handler_);
    impl_ = remote;
}

void RemotePrinterManager::StartPrinterDiscovery()
{
    EnsureLoaded();
    if (impl_ != nullptr) {
        impl_->StartPrinterDiscovery();
    }
}

bool RemotePrinterManager::StopPrinterDiscovery()
{
    if (impl_ == nullptr) {
        return true;
    }
    return impl_->StopPrinterDiscovery();
}

bool RemotePrinterManager::Disconnect()
{
    if (impl_ == nullptr) {
        return true;
    }
    return impl_->Disconnect();
}

void RemotePrinterManager::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    impl_ = nullptr;
    handler_ = nullptr;
}

} // namespace OHOS::Print
