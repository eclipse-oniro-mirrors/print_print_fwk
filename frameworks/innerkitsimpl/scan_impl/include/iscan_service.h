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

#ifndef SCAN_SERVICE_INTERFACE_H
#define SCAN_SERVICE_INTERFACE_H

#include <string>
#include <vector>

#include "iscan_callback.h"
#include "iremote_broker.h"
#include "scanner_info.h"
#include "scan_option_descriptor.h"
#include "scan_option_value.h"
#include "scan_parameters.h"
#include "scanner_info.h"
#include "scan_progress.h"

namespace OHOS::Scan {
class IScanService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Scan.IScanService");
    virtual int32_t InitScan(int32_t &scanVersion) = 0;
    virtual int32_t ExitScan() = 0;
    virtual int32_t GetScannerList() = 0;
    virtual int32_t StopDiscover() = 0;
    virtual int32_t OpenScanner(const std::string scannerId) = 0;
    virtual int32_t CloseScanner(const std::string scannerId) = 0;
    virtual int32_t GetScanOptionDesc(const std::string scannerId,
    const int32_t optionIndex, ScanOptionDescriptor &desc) = 0;
    virtual int32_t OpScanOptionValue(const std::string scannerId,
    const int32_t optionIndex, const ScanOptionOpType op, ScanOptionValue &value, int32_t &info) =0;
    virtual int32_t GetScanParameters(const std::string scannerId, ScanParameters &para) = 0;
    virtual int32_t StartScan(const std::string scannerffId, const bool &batchMode) = 0;
    virtual int32_t GetSingleFrameFD(const std::string scannerId, uint32_t &size, uint32_t fd) = 0;
    virtual int32_t CancelScan(const std::string scannerId) = 0;
    virtual int32_t SetScanIOMode(const std::string scannerId, const bool isNonBlocking) = 0;
    virtual int32_t GetScanSelectFd(const std::string scannerId, int32_t &fd) = 0;
    virtual int32_t GetScannerState(int32_t &scannerState)  = 0;
    virtual int32_t GetScanProgress(const std::string scannerId, ScanProgress &prog) = 0;
    virtual int32_t AddScanner(const std::string& serialNumber, const std::string& discoverMode) = 0;
    virtual int32_t DeleteScanner(const std::string& serialNumber, const std::string& discoverMode) = 0;
    virtual int32_t GetAddedScanner(std::vector<ScanDeviceInfo>& allAddedScanner) = 0;
    virtual int32_t UpdateScannerName(const std::string& serialNumber,
        const std::string& discoverMode, const std::string& deviceName) = 0;

    virtual int32_t On(const std::string taskId, const std::string &type, const sptr<IScanCallback> &listener) = 0;
    virtual int32_t Off(const std::string taskId, const std::string &type) = 0;
};

enum {
    CMD_INIT_SCAN,
    CMD_EXIT_SCAN,
    CMD_GET_SCANNER_LIST,
    CMD_STOP_DISCOVER,
    CMD_OPEN_SCANNER,
    CMD_CLOSE_SCANNER,
    CMD_GET_SCAN_OPTION_DESC,
    CMD_OP_SCAN_OPTION_VALUE,
    CMD_GET_SCAN_PARAMETERS,
    CMD_START_SCAN,
    CMD_GET_SINGLE_FRAME,
    CMD_GET_SINGLE_FRAME_FD,
    CMD_CANCEL_SCAN,
    CMD_SET_SCAN_IO_MODE,
    CMD_GET_SCAN_SELECT_FD,
    CMD_GET_SCANNER_STATE,
    CMD_GET_SCAN_PROGRESS,
    CMD_CONNECT_SCANNER,
    CMD_DISCONNECT_SCANNER,
    CMD_GET_CONNECTED_SCANNER,
    CMD_UPDATE_SCANNER_NAME,
    CMD_ADD_PRINTER,
    CMD_ON,
    CMD_OFF
};
} // namespace OHOS::Scan
#endif // SCAN_SERVICE_INTERFACE_H
