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
#include "fuzzer/FuzzedDataProvider.h"
#include "scanserviceproxy_fuzzer.h"
#include "scan_service_proxy.h"
#include "iscan_service.h"
#include "scan_constant.h"
#include "scanner_info.h"
#include "scan_option_value.h"
#include "scan_parameters.h"
#include "scan_progress.h"
#include "print_log.h"
#include "iremote_object.h"
#include <functional>

namespace OHOS::Scan {
constexpr uint8_t MAX_STRING_LENGTH = 255;
constexpr int MAX_SET_NUMBER = 100;
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr uint32_t MAX_ADDED_SCANNER_LEN = 1002;
constexpr int32_t MAX_EXPORT_PICTURE_COUNT = 3;
constexpr uint32_t MAX_SCAN_FRAME_TYPE = SCAN_FRAME_BLUE + 1;
constexpr int32_t FUZZ_MAX_FD_COUNT = 3;
constexpr int32_t FUZZ_MAX_SCAN_FORMAT_TYPE = 10;

class FuzzScanRemoteObject : public IRemoteObject {
public:
    FuzzScanRemoteObject() : IRemoteObject(u"") {}

    int32_t GetObjectRefCount() override { return 1; }
    bool IsProxyObject() const override { return false; }
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        if (rpcCode_ != 0) {
            return rpcCode_;
        }
        reply.WriteInt32(resultCode_);
        if (writeMethodData_) {
            WriteMethodReply(code, reply);
        }
        return 0;
    }
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }
    int Dump(int fd, const std::vector<std::u16string> &args) override { return 0; }

    void WriteMethodReply(uint32_t code, MessageParcel &reply)
    {
        switch (code) {
            case CMD_GET_CONNECTED_SCANNER:
                reply.WriteUint32(addedScannerLen_);
                for (uint32_t i = 0; i < addedScannerLen_; i++) {
                    reply.WriteString("deviceId");
                    reply.WriteString("manufacturer");
                    reply.WriteString("model");
                    reply.WriteString("deviceType");
                    reply.WriteString("discoverMode");
                    reply.WriteString("serialNumber");
                    reply.WriteString("deviceName");
                    reply.WriteString("uniqueId");
                }
                break;
            case CMD_EXPORT_SCAN_PICTURE:
                reply.WriteInt32(exportedCount_);
                break;
            case CMD_OP_SCAN_OPTION_VALUE:
                reply.WriteUint32(optionValueType_);
                reply.WriteInt32(optionValueSize_);
                if (optionValueType_ == SCAN_VALUE_STR) {
                    reply.WriteString(optionStrValue_);
                } else {
                    reply.WriteInt32(optionNumValue_);
                }
                break;
            case CMD_GET_SCAN_PARAMETERS:
                reply.WriteUint32(paramFormat_);
                reply.WriteBool(paramLastFrame_);
                reply.WriteInt32(paramBytesPerLine_);
                reply.WriteInt32(paramPixelsPerLine_);
                reply.WriteInt32(paramLines_);
                reply.WriteInt32(paramDepth_);
                break;
            case CMD_GET_SCAN_PROGRESS:
                reply.WriteInt32(progressValue_);
                reply.WriteBool(progressIsFinal_);
                break;
            default:
                break;
        }
    }

    int32_t rpcCode_ = 0;
    int32_t resultCode_ = 0;
    bool writeMethodData_ = true;
    uint32_t addedScannerLen_ = 0;
    int32_t exportedCount_ = 0;
    uint32_t optionValueType_ = 0;
    int32_t optionValueSize_ = 1;
    int32_t optionNumValue_ = 0;
    std::string optionStrValue_ = "test";
    uint32_t paramFormat_ = 0;
    bool paramLastFrame_ = false;
    int32_t paramBytesPerLine_ = 1;
    int32_t paramPixelsPerLine_ = 1;
    int32_t paramLines_ = 1;
    int32_t paramDepth_ = 1;
    int32_t progressValue_ = 0;
    bool progressIsFinal_ = false;
};

void TestGetAddedScanner(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto mock = new FuzzScanRemoteObject();
    mock->rpcCode_ = dataProvider->ConsumeIntegralInRange<int32_t>(0, 1);
    if (mock->rpcCode_ == 0) {
        mock->resultCode_ = dataProvider->ConsumeIntegralInRange<int32_t>(0, 1);
        if (mock->resultCode_ == 0) {
            mock->addedScannerLen_ = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_ADDED_SCANNER_LEN);
            mock->writeMethodData_ = dataProvider->ConsumeBool();
        }
    }
    sptr<IRemoteObject> mockObj = mock;
    ScanServiceProxy proxy(mockObj);
    std::vector<ScanDeviceInfo> allAddedScanner;
    proxy.GetAddedScanner(allAddedScanner);
}

void TestExportScanPicture(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto mock = new FuzzScanRemoteObject();
    mock->rpcCode_ = dataProvider->ConsumeIntegralInRange<int32_t>(0, 1);
    if (mock->rpcCode_ == 0) {
        mock->resultCode_ = dataProvider->ConsumeIntegralInRange<int32_t>(0, 1);
        if (mock->resultCode_ == 0) {
            mock->exportedCount_ = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_EXPORT_PICTURE_COUNT);
            mock->writeMethodData_ = dataProvider->ConsumeBool();
        }
    }
    sptr<IRemoteObject> mockObj = mock;
    ScanServiceProxy proxy(mockObj);
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t fdCount = dataProvider->ConsumeIntegralInRange<int32_t>(0, FUZZ_MAX_FD_COUNT);
    std::vector<int32_t> pictureFdList;
    for (int32_t i = 0; i < fdCount; i++) {
        pictureFdList.push_back(dataProvider->ConsumeIntegralInRange<int32_t>(INVALID_FD, MAX_SET_NUMBER));
    }
    int32_t format = dataProvider->ConsumeIntegralInRange<int32_t>(INVALID_FD, FUZZ_MAX_SCAN_FORMAT_TYPE);
    std::vector<int32_t> exportedFdList;
    proxy.ExportScanPicture(scannerId, pictureFdList, format, exportedFdList);
}

void SetupOptionValue(FuzzScanRemoteObject* mock, FuzzedDataProvider* dataProvider)
{
    mock->optionValueType_ = dataProvider->ConsumeIntegralInRange<uint32_t>(0, SCAN_VALUE_GROUP);
    mock->optionValueSize_ = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    if (mock->optionValueType_ == SCAN_VALUE_STR) {
        mock->optionStrValue_ = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    } else {
        mock->optionNumValue_ = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    }
}

void TestOpScanOptionValue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto mock = new FuzzScanRemoteObject();
    mock->rpcCode_ = dataProvider->ConsumeIntegralInRange<int32_t>(0, 1);
    if (mock->rpcCode_ == 0) {
        mock->resultCode_ = dataProvider->ConsumeIntegralInRange<int32_t>(0, 1);
        if (mock->resultCode_ == 0) {
            mock->writeMethodData_ = dataProvider->ConsumeBool();
            if (mock->writeMethodData_) {
                SetupOptionValue(mock, dataProvider);
            }
        }
    }
    sptr<IRemoteObject> mockObj = mock;
    ScanServiceProxy proxy(mockObj);
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t optionIndex = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    ScanOptionOpType op = static_cast<ScanOptionOpType>(
        dataProvider->ConsumeIntegralInRange<uint32_t>(0, SCAN_ACTION_SET_AUTO));
    ScanOptionValue value;
    proxy.OpScanOptionValue(scannerId, optionIndex, op, value);
}

void TestGetScanParameters(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto mock = new FuzzScanRemoteObject();
    mock->rpcCode_ = dataProvider->ConsumeIntegralInRange<int32_t>(0, 1);
    if (mock->rpcCode_ == 0) {
        mock->resultCode_ = dataProvider->ConsumeIntegralInRange<int32_t>(0, 1);
        if (mock->resultCode_ == 0) {
            mock->writeMethodData_ = dataProvider->ConsumeBool();
            if (mock->writeMethodData_) {
                mock->paramFormat_ = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SCAN_FRAME_TYPE);
                mock->paramLastFrame_ = dataProvider->ConsumeBool();
                mock->paramBytesPerLine_ = dataProvider->ConsumeIntegralInRange<int32_t>(INVALID_FD, MAX_SET_NUMBER);
                mock->paramPixelsPerLine_ = dataProvider->ConsumeIntegralInRange<int32_t>(INVALID_FD, MAX_SET_NUMBER);
                mock->paramLines_ = dataProvider->ConsumeIntegralInRange<int32_t>(INVALID_FD, MAX_SET_NUMBER);
                mock->paramDepth_ = dataProvider->ConsumeIntegralInRange<int32_t>(INVALID_FD, MAX_SET_NUMBER);
            }
        }
    }
    sptr<IRemoteObject> mockObj = mock;
    ScanServiceProxy proxy(mockObj);
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ScanParameters para;
    proxy.GetScanParameters(scannerId, para);
}

void TestGetScanProgress(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    auto mock = new FuzzScanRemoteObject();
    mock->rpcCode_ = dataProvider->ConsumeIntegralInRange<int32_t>(0, 1);
    if (mock->rpcCode_ == 0) {
        mock->resultCode_ = dataProvider->ConsumeIntegralInRange<int32_t>(0, 1);
        if (mock->resultCode_ == 0) {
            mock->writeMethodData_ = dataProvider->ConsumeBool();
            if (mock->writeMethodData_) {
                mock->progressValue_ = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
                mock->progressIsFinal_ = dataProvider->ConsumeBool();
            }
        }
    }
    sptr<IRemoteObject> mockObj = mock;
    ScanServiceProxy proxy(mockObj);
    std::string scannerId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    ScanProgress prog;
    proxy.GetScanProgress(scannerId, prog);
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::Scan::U32_AT_SIZE || size > OHOS::Scan::FOO_MAX_LEN) {
    }
    FuzzedDataProvider dataProvider(data, size);
    PRINT_HILOGI("scanserviceproxy_fuzzer is running.");
    using TestHandler = std::function<void(const uint8_t*, size_t, FuzzedDataProvider*)>;
    TestHandler tasks[] = {
        &OHOS::Scan::TestGetAddedScanner,
        &OHOS::Scan::TestExportScanPicture,
        &OHOS::Scan::TestOpScanOptionValue,
        &OHOS::Scan::TestGetScanParameters,
        &OHOS::Scan::TestGetScanProgress
    };

    TestHandler handler = dataProvider.PickValueInArray(tasks);
    handler(data, size, &dataProvider);
    return 0;
}
