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

#ifndef REMOTE_PRINTER_MANAGER_IMPL_H
#define REMOTE_PRINTER_MANAGER_IMPL_H

#include <atomic>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "i_remote_printer_manager.h"
#include "remote_service_adapter.h"

namespace OHOS::Print {

class RemotePrinterManagerImpl : public IRemotePrinterManager {
public:
    static RemotePrinterManagerImpl &GetInstance();

    void *QueryInterface(PrintFeatureIid iid) override;

    void SetEventHandler(IRemotePrinterEventHandler *handler) override;

    bool Destroy() override;
    bool Disconnect() override;
    void StartPrinterDiscovery() override;
    bool StopPrinterDiscovery() override;

    std::shared_ptr<PrinterInfo> GetPrinterInfo(const std::string &printerId) override;
    bool UpdatePrinterStatus(const std::string &printerId, PrinterStatus status) override;
    bool OnPrinterListReceived(const Json::Value &jsonArray) override;
    bool OnPrinterStatusReceived(const Json::Value &jsonArray) override;
    void ClearAllPrinters() override;

    bool WaitForActiveCallsIdle(int32_t timeoutMs);

private:
    struct ActiveCallGuard {
        explicit ActiveCallGuard(RemotePrinterManagerImpl &impl) : impl_(impl)
        {
            impl_.activeCalls_.fetch_add(1, std::memory_order_relaxed);
        }
        ~ActiveCallGuard()
        {
            if (impl_.activeCalls_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
                std::lock_guard<std::mutex> lock(impl_.activeMutex_);
                impl_.activeCv_.notify_all();
            }
        }
        RemotePrinterManagerImpl &impl_;
    };

    RemotePrinterManagerImpl();
    ~RemotePrinterManagerImpl() override;
    RemotePrinterManagerImpl(const RemotePrinterManagerImpl &) = delete;
    RemotePrinterManagerImpl &operator=(const RemotePrinterManagerImpl &) = delete;

    PrinterStatus ConvertStatusToPrinterStatus(const std::string &statusStr);
    void SetDefaultCapability(PrinterCapability &capability);
    bool BuildPrinterInfo(const Json::Value &item, PrinterInfo &printerInfo);
    void DiscoveryLoop();
    void RemoveDeprecatedPrinters(const std::vector<std::string> &currentDevIds);
    void NotifyPrinterAdded(const PrinterInfo &info);
    void NotifyPrinterRemoved(const std::string &uri);

    RemoteServiceAdapter &serviceAdapter_;
    std::atomic<bool> isDiscoveryRunning_{false};
    std::mutex startMutex_;
    std::mutex controlMutex_;
    std::mutex printerMapLock_;
    std::condition_variable cv_;
    std::thread discoveryThread_;
    std::map<std::string, std::shared_ptr<PrinterInfo>> printerMap_;
    std::once_flag initFlag_;
    IRemotePrinterEventHandler *eventHandler_ = nullptr;
    std::mutex handlerMutex_;
    std::atomic<int32_t> activeCalls_{0};
    std::mutex activeMutex_;
    std::condition_variable activeCv_;
};

} // namespace OHOS::Print

#ifdef __cplusplus
extern "C" {
#endif

__attribute__((visibility("default"))) OHOS::Print::IPrintFeature *CreateRemotePrintFeature();
__attribute__((visibility("default"))) void DestroyRemotePrintFeature(OHOS::Print::IPrintFeature *feature);

#ifdef __cplusplus
}
#endif

#endif // REMOTE_PRINTER_MANAGER_IMPL_H
