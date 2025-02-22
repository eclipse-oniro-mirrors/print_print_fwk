/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef SCAN_MANAGER_CLIENT_H
#define SCAN_MANAGER_CLIENT_H
#define TDD_ENABLE 1

#include <condition_variable>
#include <map>
#include <mutex>
#include <shared_mutex>

#include "iscan_callback.h"
#include "iscan_service.h"
#include "iremote_object.h"

#include "scan_sync_load_callback.h"
#include "scan_sa_death_recipient.h"
#include "scanner_info.h"
#include "refbase.h"

namespace OHOS::Scan {
class ScanManagerClient : public RefBase {
public:
    ScanManagerClient();
    ~ScanManagerClient();
    static sptr<ScanManagerClient> GetInstance();

    void OnRemoteSaDied(const wptr<IRemoteObject> &object);

    int32_t InitScan(int32_t &scanVersion);
    int32_t ExitScan();
    int32_t GetScannerList();
    int32_t StopDiscover();
    int32_t OpenScanner(const std::string scannerId);
    int32_t CloseScanner(const std::string scannerId);
    int32_t GetScanOptionDesc(const std::string scannerId, const int32_t optionIndex, ScanOptionDescriptor &desc);
    int32_t OpScanOptionValue(const std::string scannerId, const int32_t optionIndex,
    const ScanOptionOpType op, ScanOptionValue &value, int32_t &info);
    int32_t GetScanParameters(const std::string scannerId, ScanParameters &para);
    int32_t StartScan(const std::string scannerId, const bool &batchMode);
    int32_t GetSingleFrameFD(const std::string scannerId, uint32_t &size, uint32_t fd);
    int32_t CancelScan(const std::string scannerId);
    int32_t SetScanIOMode(const std::string scannerId, const bool isNonBlocking);
    int32_t GetScanSelectFd(const std::string scannerId, int32_t &fd);
    int32_t GetScannerState(int32_t &scannerState);
    int32_t GetScanProgress(const std::string scannerId, ScanProgress &prog);
    int32_t AddScanner(const std::string& serialNumber, const std::string& discoverMode);
    int32_t DeleteScanner(const std::string& serialNumber, const std::string& discoverMode);
    int32_t GetAddedScanner(std::vector<ScanDeviceInfo>& allAddedScanner);
    int32_t UpdateScannerName(const std::string& serialNumber,
        const std::string& discoverMode, const std::string& deviceName);

    int32_t On(const std::string &taskId, const std::string &type, const sptr<IScanCallback> &listener);
    int32_t Off(const std::string &taskId, const std::string &type);

    void LoadServerSuccess(const sptr<IRemoteObject> &remoteObject);
    void LoadServerFail();

#ifndef TDD_ENABLE
private:
#endif
    bool LoadScanService();
    sptr<IScanService> GetScanServiceProxy();

#ifndef TDD_ENABLE
private:
#endif
    static std::mutex instanceLock_;
    static sptr<ScanManagerClient> instance_;
    sptr<IScanService> scanServiceProxy_;
    sptr<ScanSaDeathRecipient> deathRecipient_;
    std::mutex loadMutex_;
    std::mutex conditionMutex_;
    std::condition_variable_any syncCon_;
    bool ready_ = false;
    std::shared_mutex proxyLock_;
    static constexpr int LOAD_SA_TIMEOUT_MS = 15000;
};
} // namespace OHOS::Scan
#endif // SCAN_MANAGER_CLIENT_H
