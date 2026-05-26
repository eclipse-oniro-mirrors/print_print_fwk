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
#ifndef MOCK_SCAN_SERVICE_H
#define MOCK_SCAN_SERVICE_H

#include <gmock/gmock.h>
#include "scan_constant.h"
#include "scan_service_stub.h"

namespace OHOS::Scan {
class DummyScanServiceStub : public ScanServiceStub {
public:
    int32_t InitScan() override
    {
        return E_SCAN_NONE;
    }
    int32_t ExitScan() override
    {
        return E_SCAN_NONE;
    }
    int32_t GetScannerList() override
    {
        return E_SCAN_NONE;
    }
    int32_t OpenScanner(const std::string scannerId) override
    {
        return E_SCAN_NONE;
    }
    int32_t CloseScanner(const std::string scannerId) override
    {
        return E_SCAN_NONE;
    }
    int32_t GetScanOptionDesc(const std::string scannerId,
        const int32_t optionIndex, ScanOptionDescriptor &desc) override
    {
        return E_SCAN_NONE;
    }
    int32_t OpScanOptionValue(const std::string scannerId,
        const int32_t optionIndex, const ScanOptionOpType op, ScanOptionValue &value) override
    {
        return E_SCAN_NONE;
    }
    int32_t GetScanParameters(const std::string scannerId, ScanParameters &para) override
    {
        return E_SCAN_NONE;
    }
    int32_t StartScan(const std::string scannerId, const bool &batchMode) override
    {
        return E_SCAN_NONE;
    }
    int32_t CancelScan(const std::string scannerId) override
    {
        return E_SCAN_NONE;
    }
    int32_t GetScanProgress(const std::string scannerId, ScanProgress &prog) override
    {
        return E_SCAN_NONE;
    }
    int32_t AddScanner(const std::string& serialNumber, const std::string& discoverMode) override
    {
        return E_SCAN_NONE;
    }
    int32_t DeleteScanner(const std::string& serialNumber, const std::string& discoverMode) override
    {
        return E_SCAN_NONE;
    }
    int32_t GetAddedScanner(std::vector<ScanDeviceInfo>& allAddedScanner) override
    {
        return E_SCAN_NONE;
    }
    int32_t On(const std::string taskId, const std::string &type,
        const sptr<IScanCallback> &listener) override
    {
        return E_SCAN_NONE;
    }
    int32_t Off(const std::string taskId, const std::string &type) override
    {
        return E_SCAN_NONE;
    }
    int32_t ExportScanPicture(const std::string scannerId,
        const std::vector<int32_t>& pictureFdList, const int32_t format,
        std::vector<int32_t>& exportedFdList) override
    {
        return E_SCAN_NONE;
    }
};

class MockScanService final : public DummyScanServiceStub {
public:
    MOCK_METHOD0(InitScan, int32_t());
    MOCK_METHOD0(ExitScan, int32_t());
    MOCK_METHOD0(GetScannerList, int32_t());
    MOCK_METHOD1(OpenScanner, int32_t(const std::string));
    MOCK_METHOD1(CloseScanner, int32_t(const std::string));
    MOCK_METHOD3(GetScanOptionDesc, int32_t(const std::string, const int32_t, ScanOptionDescriptor &));
    MOCK_METHOD4(OpScanOptionValue, int32_t(const std::string, const int32_t, const ScanOptionOpType,
        ScanOptionValue &));
    MOCK_METHOD2(GetScanParameters, int32_t(const std::string, ScanParameters &));
    MOCK_METHOD2(StartScan, int32_t(const std::string, const bool &));
    MOCK_METHOD1(CancelScan, int32_t(const std::string));
    MOCK_METHOD2(GetScanProgress, int32_t(const std::string, ScanProgress &));
    MOCK_METHOD2(AddScanner, int32_t(const std::string&, const std::string&));
    MOCK_METHOD2(DeleteScanner, int32_t(const std::string&, const std::string&));
    MOCK_METHOD1(GetAddedScanner, int32_t(std::vector<ScanDeviceInfo>&));
    MOCK_METHOD3(On, int32_t(const std::string, const std::string &, const sptr<IScanCallback> &));
    MOCK_METHOD2(Off, int32_t(const std::string, const std::string &));
    MOCK_METHOD4(ExportScanPicture, int32_t(const std::string, const std::vector<int32_t>&, const int32_t,
        std::vector<int32_t>&));
};
}  // namespace OHOS::Scan
#endif  // MOCK_SCAN_SERVICE_H