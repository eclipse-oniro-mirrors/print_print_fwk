/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "fuzzer/FuzzedDataProvider.h"
#include "scanservicestub_fuzzer.h"
#include "scan_service_ability.h"

namespace OHOS {
namespace Scan {
    constexpr uint8_t MAX_STRING_LENGTH = 255;
    constexpr int MAX_SET_NUMBER = 100;
    constexpr size_t FOO_MAX_LEN = 1024;
    constexpr size_t U32_AT_SIZE = 4;

    bool WriteInterfaceToken(MessageParcel &datas)
    {
        if (!datas.WriteInterfaceToken(ScanServiceAbility::GetInstance()->GetDescriptor())) {
            return false;
        }
        return true;
    }

    bool TestOnOpenScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MessageParcel datas;
        MessageParcel reply;
        MessageOption option;
        if (!WriteInterfaceToken(datas)) {
            return false;
        }
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        datas.WriteString(scannerId);
        ScanServiceAbility::GetInstance()->OnRemoteRequest(CMD_GET_SCANNER_LIST, datas, reply, option);
        ScanServiceAbility::GetInstance()->OnRemoteRequest(CMD_STOP_DISCOVER, datas, reply, option);
        ScanServiceAbility::GetInstance()->OnRemoteRequest(CMD_INIT_SCAN, datas, reply, option);
        ScanServiceAbility::GetInstance()->OnRemoteRequest(CMD_OPEN_SCANNER, datas, reply, option);
        ScanServiceAbility::GetInstance()->OnRemoteRequest(CMD_EXIT_SCAN, datas, reply, option);
        return true;
    }

    bool TestOnCloseScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MessageParcel datas;
        MessageParcel reply;
        MessageOption option;
        if (!WriteInterfaceToken(datas)) {
            return false;
        }
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        datas.WriteString(scannerId);
        ScanServiceAbility::GetInstance()->OnRemoteRequest(CMD_CLOSE_SCANNER, datas, reply, option);
        return true;
    }

    bool TestOnGetScanOptionDesc(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MessageParcel datas;
        MessageParcel reply;
        MessageOption option;
        if (!WriteInterfaceToken(datas)) {
            return false;
        }
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        datas.WriteString(scannerId);
        int32_t optionIndex = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        datas.WriteInt32(optionIndex);
        ScanServiceAbility::GetInstance()->OnRemoteRequest(CMD_GET_SCAN_OPTION_DESC, datas, reply, option);
        return true;
    }

    bool TestOnOpScanOptionValue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MessageParcel datas;
        MessageParcel reply;
        MessageOption option;
        if (!WriteInterfaceToken(datas)) {
            return false;
        }
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        datas.WriteString(scannerId);
        int32_t optionIndex = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        datas.WriteInt32(optionIndex);
        ScanOptionOpType op = SCAN_ACTION_SET_VALUE;
        datas.WriteUint32(op);
        ScanOptionValue value;
        value.Marshalling(datas);
        ScanServiceAbility::GetInstance()->OnRemoteRequest(CMD_OP_SCAN_OPTION_VALUE, datas, reply, option);
        return true;
    }

    bool TestOnGetScanParameters(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MessageParcel datas;
        MessageParcel reply;
        MessageOption option;
        if (!WriteInterfaceToken(datas)) {
            return false;
        }
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        datas.WriteString(scannerId);
        ScanServiceAbility::GetInstance()->OnRemoteRequest(CMD_GET_SCAN_PARAMETERS, datas, reply, option);
        return true;
    }

    bool TestOnStartScan(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MessageParcel datas;
        MessageParcel reply;
        MessageOption option;
        if (!WriteInterfaceToken(datas)) {
            return false;
        }
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        datas.WriteString(scannerId);
        ScanServiceAbility::GetInstance()->OnRemoteRequest(CMD_START_SCAN, datas, reply, option);
        return true;
    }

    bool TestOnGetSingleFrameFD(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MessageParcel datas;
        MessageParcel reply;
        MessageOption option;
        if (!WriteInterfaceToken(datas)) {
            return false;
        }
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        datas.WriteString(scannerId);
        uint32_t fd = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
        datas.WriteFileDescriptor(fd);
        ScanServiceAbility::GetInstance()->OnRemoteRequest(CMD_GET_SINGLE_FRAME_FD, datas, reply, option);
        return true;
    }

    bool TestOnCancelScan(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MessageParcel datas;
        MessageParcel reply;
        MessageOption option;
        if (!WriteInterfaceToken(datas)) {
            return false;
        }
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        datas.WriteString(scannerId);
        ScanServiceAbility::GetInstance()->OnRemoteRequest(CMD_CANCEL_SCAN, datas, reply, option);
        return true;
    }

    bool TestOnSetScanIOMode(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MessageParcel datas;
        MessageParcel reply;
        MessageOption option;
        if (!WriteInterfaceToken(datas)) {
            return false;
        }
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        datas.WriteString(scannerId);
        bool isNonBlocking = dataProvider->ConsumeBool();
        datas.WriteBool(isNonBlocking);
        ScanServiceAbility::GetInstance()->OnRemoteRequest(CMD_SET_SCAN_IO_MODE, datas, reply, option);
        return true;
    }

    bool TestOnGetScanSelectFd(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MessageParcel datas;
        MessageParcel reply;
        MessageOption option;
        if (!WriteInterfaceToken(datas)) {
            return false;
        }
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        datas.WriteString(scannerId);
        ScanServiceAbility::GetInstance()->OnRemoteRequest(CMD_GET_SCAN_SELECT_FD, datas, reply, option);
        return true;
    }

    bool TestOnGetScanProgress(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MessageParcel datas;
        MessageParcel reply;
        MessageOption option;
        if (!WriteInterfaceToken(datas)) {
            return false;
        }
        std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        datas.WriteString(scannerId);
        ScanServiceAbility::GetInstance()->OnRemoteRequest(CMD_GET_SCAN_PROGRESS, datas, reply, option);
        ScanServiceAbility::GetInstance()->OnRemoteRequest(CMD_GET_SCANNER_STATE, datas, reply, option);
        return true;
    }

    bool TestOnEventOn(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MessageParcel datas;
        MessageParcel reply;
        MessageOption option;
        if (!WriteInterfaceToken(datas)) {
            return false;
        }
        std::string taskId = "";
        datas.WriteString(taskId);
        std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        datas.WriteString(type);
        return true;
    }

    bool TestOnEventOff(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
    {
        MessageParcel datas;
        MessageParcel reply;
        MessageOption option;
        if (!WriteInterfaceToken(datas)) {
            return false;
        }
        std::string taskId = "";
        datas.WriteString(taskId);
        std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        datas.WriteString(type);
        ScanServiceAbility::GetInstance()->OnRemoteRequest(CMD_OFF, datas, reply, option);
        return true;
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::Scan::U32_AT_SIZE || size > OHOS::Scan::FOO_MAX_LEN) {
        return 0;
    }
    FuzzedDataProvider dataProvider(data, size);
    OHOS::Scan::TestOnOpenScanner(data, size, &dataProvider);
    OHOS::Scan::TestOnCloseScanner(data, size, &dataProvider);
    OHOS::Scan::TestOnGetScanOptionDesc(data, size, &dataProvider);
    OHOS::Scan::TestOnOpScanOptionValue(data, size, &dataProvider);
    OHOS::Scan::TestOnGetScanParameters(data, size, &dataProvider);
    OHOS::Scan::TestOnStartScan(data, size, &dataProvider);
    OHOS::Scan::TestOnGetSingleFrameFD(data, size, &dataProvider);
    OHOS::Scan::TestOnCancelScan(data, size, &dataProvider);
    OHOS::Scan::TestOnSetScanIOMode(data, size, &dataProvider);
    OHOS::Scan::TestOnGetScanSelectFd(data, size, &dataProvider);
    OHOS::Scan::TestOnGetScanProgress(data, size, &dataProvider);
    OHOS::Scan::TestOnEventOn(data, size, &dataProvider);
    OHOS::Scan::TestOnEventOff(data, size, &dataProvider);
    return 0;
}