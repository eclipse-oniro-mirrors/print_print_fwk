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
#include "napi/native_api.h"
#include "message_parcel.h"
#include "scanhelper_fuzzer.h"
#include "scan_option_descriptor.h"
#include "scan_option_value.h"
#include "scan_parameters.h"
#include "scan_progress.h"
#include "scanner_info.h"
#include "scan_range.h"
#include "scan_option_descriptor_helper.h"
#include "scan_option_value_helper.h"
#include "scan_parameters_helper.h"
#include "scan_progress_helper.h"
#include "scan_range_helper.h"
#include "scanner_info_helper.h"

namespace OHOS {
namespace Scan {
constexpr uint8_t MAX_STRING_LENGTH = 255;
constexpr int MAX_SET_NUMBER = 100;
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;

void TestSetOptionName(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionDescriptor scanOptDes;
    std::string optionName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    scanOptDes.SetOptionName(optionName);
    optionName = scanOptDes.GetOptionName();
}

void TestSetOptionTitle(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionDescriptor scanOptDes;
    std::string optionTitle = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    scanOptDes.SetOptionTitle(optionTitle);
    optionTitle = scanOptDes.GetOptionTitle();
}

void TestSetOptionDesc(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionDescriptor scanOptDes;
    std::string optionDesc = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    scanOptDes.SetOptionDesc(optionDesc);
    optionDesc = scanOptDes.GetOptionDesc();
}

void TestSetOptionType(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionDescriptor scanOptDes;
    uint32_t optionType = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    scanOptDes.SetOptionType(optionType);
    optionType = scanOptDes.GetOptionType();
}

void TestSetOptionUnit(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionDescriptor scanOptDes;
    uint32_t optionUnit = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    scanOptDes.SetOptionUnit(optionUnit);
    optionUnit = scanOptDes.GetOptionUnit();
}

void TestSetOptionSize(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionDescriptor scanOptDes;
    int32_t optionSize = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    scanOptDes.SetOptionSize(optionSize);
    optionSize = scanOptDes.GetOptionSize();
}

void TestSetOptionCap(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionDescriptor scanOptDes;
    int32_t optionCap = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    scanOptDes.SetOptionCap(optionCap);
    optionCap = scanOptDes.GetOptionCap();
}

void TestSetOptionConstraintType(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionDescriptor scanOptDes;
    uint32_t optionConstraintType = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    scanOptDes.SetOptionConstraintType(optionConstraintType);
    optionConstraintType = scanOptDes.GetOptionConstraintType();
}

void TestSetOptionConstraintString(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionDescriptor scanOptDes;
    std::vector<std::string> optionConstraintString;
    int32_t vectorSize = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    for (int i = 0; i< vectorSize; i++) {
        std::string teststr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
        optionConstraintString.emplace_back(teststr);
    }
    scanOptDes.SetOptionConstraintString(optionConstraintString);
    scanOptDes.GetOptionConstraintString(optionConstraintString);
}

void TestSetOptionConstraintNumber(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionDescriptor scanOptDes;
    std::vector<int32_t> optionConstraintNumber;
    int32_t vectorSize = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    for (int i = 0; i< vectorSize; i++) {
        int32_t testNumber = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        optionConstraintNumber.emplace_back(testNumber);
    }
    scanOptDes.SetOptionConstraintNumber(optionConstraintNumber);
    scanOptDes.GetOptionConstraintNumber(optionConstraintNumber);
}

void TestSetOptionConstraintRange(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionDescriptor scanOptDes;
    ScanRange optionConstraintRange;
    scanOptDes.SetOptionConstraintRange(optionConstraintRange);
    scanOptDes.GetOptionConstraintRange(optionConstraintRange);
    std::string optionName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    scanOptDes.SetOptionName(optionName);
}

void TestScanOptionDescriptor(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionDescriptor scanOptDesTmp;
    uint32_t optionConstraintType = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    scanOptDesTmp.SetOptionConstraintType(optionConstraintType);
    ScanOptionDescriptor scanOptDesBak(scanOptDesTmp);
    ScanOptionDescriptor scanOptDesOpera = scanOptDesTmp;
    scanOptDesOpera.Dump();
    MessageParcel parcel;
    scanOptDesOpera.Marshalling(parcel);
    auto scanOptDesMarShall = ScanOptionDescriptor::Unmarshalling(parcel);
}

void TestSetScanOptionValueType(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionValue scanOptVal;
    int32_t valueType = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    scanOptVal.SetScanOptionValueType(static_cast<ScanOptionValueType>(valueType));
    valueType = scanOptVal.GetScanOptionValueType();
}

void TestSetValueSize(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionValue scanOptVal;
    int32_t valueSize = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    scanOptVal.SetValueSize(valueSize);
    valueSize = scanOptVal.GetValueSize();
}

void TestSetNumValue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionValue scanOptVal;
    int32_t numValue = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    scanOptVal.SetNumValue(numValue);
    numValue = scanOptVal.GetNumValue();
}

void TestSetNumListValue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionValue scanOptVal;
    int32_t vecSize = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    std::vector<int32_t> numListValue;
    for (int i = 0; i < vecSize; i++) {
        int32_t number = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
        numListValue.emplace_back(number);
    }
    scanOptVal.SetNumListValue(numListValue);
    scanOptVal.GetNumListValue(numListValue);
}

void TestSetStrValue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionValue scanOptVal;
    std::string optionTitle = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    scanOptVal.SetStrValue(optionTitle);
    optionTitle = scanOptVal.GetStrValue();
}

void TestSetBoolValue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionValue scanOptVal;
    bool boolValue = dataProvider->ConsumeBool();
    scanOptVal.SetBoolValue(boolValue);
    boolValue = scanOptVal.GetBoolValue();
}

void TestScanOptionValue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanOptionValue scanOptVal;
    int32_t valueType = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    scanOptVal.SetScanOptionValueType(static_cast<ScanOptionValueType>(valueType));
    ScanOptionValue scanOptValBak = scanOptVal;
    scanOptValBak.Reset();
    ScanOptionValue scanOptValOpera(scanOptValBak);
    int32_t valueSize = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    scanOptValOpera.SetValueSize(valueSize);
    MessageParcel parcel;
    scanOptValOpera.Marshalling(parcel);
    auto scanOptValMarShall = ScanOptionDescriptor::Unmarshalling(parcel);
    scanOptValMarShall->Dump();
}

void TestSetFormat(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanParameters scanPara;
    int32_t format = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    scanPara.SetFormat(static_cast<ScanFrame>(format));
    format = scanPara.GetFormat();
}

void TestSetLastFrame(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanParameters scanPara;
    bool lastFrame = dataProvider->ConsumeBool();
    scanPara.SetLastFrame(lastFrame);
    lastFrame = scanPara.GetLastFrame();
}

void TestSetBytesPerLine(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanParameters scanPara;
    int32_t bytesPerLine = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    scanPara.SetBytesPerLine(bytesPerLine);
    bytesPerLine = scanPara.GetBytesPerLine();
}

void TestSetPixelsPerLine(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanParameters scanPara;
    int32_t pixelsPerLine = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    scanPara.SetPixelsPerLine(pixelsPerLine);
    pixelsPerLine = scanPara.GetPixelsPerLine();
}

void TestSetLines(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanParameters scanPara;
    int32_t lines = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    scanPara.SetLines(lines);
    lines = scanPara.GetLines();
}

void TestSetDepth(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanParameters scanPara;
    int32_t depth = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    scanPara.SetDepth(depth);
    depth = scanPara.GetDepth();
}

void TestScanParameters(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanParameters scanPara;
    int32_t lines = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    scanPara.SetLines(lines);
    ScanParameters scanParaTmp(scanPara);
    ScanParameters scanParaBak = scanParaTmp;
    scanParaBak.Dump();
    MessageParcel parcel;
    scanParaBak.Marshalling(parcel);
    auto scanParaBakMarShall = ScanParameters::Unmarshalling(parcel);
}

void TestSetScanProgress(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanProgress scanProg;
    int32_t progress = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    scanProg.SetScanProgress(progress);
    progress = scanProg.GetScanProgress();
}

void TestSetScanPictureFd(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanProgress scanProg;
    int32_t fd = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    scanProg.SetScanPictureFd(fd);
    fd = scanProg.GetScanPictureFd();
}

void TestSetIsFinal(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanProgress scanProg;
    bool isFinal = dataProvider->ConsumeBool();
    scanProg.SetIsFinal(isFinal);
    isFinal = scanProg.GetIsFinal();
}

void TestSetPictureId(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanProgress scanProg;
    int32_t pictureId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    scanProg.SetPictureId(pictureId);
    pictureId = scanProg.GetPictureId();
}

void TestSetTaskCode(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanProgress scanProg;
    int32_t taskCode = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    scanProg.SetTaskCode(static_cast<ScanErrorCode>(taskCode));
    taskCode = scanProg.GetTaskCode();
}

void TestScanProgress(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanProgress scanProg;
    int32_t taskCode = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    scanProg.SetTaskCode(static_cast<ScanErrorCode>(taskCode));
    scanProg.Dump();
    taskCode = scanProg.GetTaskCode();
    ScanProgress scanProgTmp(scanProg);
    ScanProgress scanProgBak = scanProgTmp;
    MessageParcel parcel;
    scanProgBak.Marshalling(parcel);
    auto scanOptValMarShall = ScanProgress::Unmarshalling(parcel);
}

void TestTCPSetDeviceName(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfoTCP scanDevInfoTcp;
    std::string deviceName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    scanDevInfoTcp.SetDeviceName(deviceName);
    deviceName = scanDevInfoTcp.GetDeviceName();
}

void TestTCPSetUuid(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfoTCP scanDevInfoTcp;
    std::string uuid = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    scanDevInfoTcp.SetUuid(uuid);
    uuid = scanDevInfoTcp.GetUuid();
}

void TestTCPSetModel(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfoTCP scanDevInfoTcp;
    std::string model = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    scanDevInfoTcp.SetModel(model);
    model = scanDevInfoTcp.GetModel();
}

void TestTCPSetManufacturer(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfoTCP scanDevInfoTcp;
    std::string manufacturer = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    scanDevInfoTcp.SetManufacturer(manufacturer);
    manufacturer = scanDevInfoTcp.GetManufacturer();
}

void TestTCPSetDeviceType(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfoTCP scanDevInfoTcp;
    std::string deviceType = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    scanDevInfoTcp.SetDeviceType(deviceType);
    deviceType = scanDevInfoTcp.GetDeviceType();
}

void TestTCPSetPort(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfoTCP scanDevInfoTcp;
    std::string port = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    scanDevInfoTcp.SetPort(port);
    port = scanDevInfoTcp.GetPort();
}


void TestTCPSetAddr(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfoTCP scanDevInfoTcp;
    std::string addr = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    scanDevInfoTcp.SetAddr(addr);
    addr = scanDevInfoTcp.GetAddr();
}

void TestTCPSetButton(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfoTCP scanDevInfoTcp;
    std::string button = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    scanDevInfoTcp.SetButton(button);
    button = scanDevInfoTcp.GetButton();
}

void TestTCPSetFeeder(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfoTCP scanDevInfoTcp;
    std::string feeder = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    scanDevInfoTcp.SetFeeder(feeder);
    feeder = scanDevInfoTcp.GetFeeder();
}

void TestTCPSetDeviceState(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfoTCP scanDevInfoTcp;
    uint32_t deviceState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    scanDevInfoTcp.SetDeviceState(deviceState);
    deviceState = scanDevInfoTcp.GetDeviceState();
}

void TestUSBSetDeviceId(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfo deviceInfo;
    std::string deviceId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    deviceInfo.SetDeviceId(deviceId);
    deviceId = deviceInfo.GetDeviceId();
}

void TestUSBSetManufacturer(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfo deviceInfo;
    std::string manufacturer = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    deviceInfo.SetManufacturer(manufacturer);
    manufacturer = deviceInfo.GetManufacturer();
}

void TestUSBSetModel(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfo deviceInfo;
    std::string model = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    deviceInfo.SetModel(model);
    model = deviceInfo.GetModel();
}

void TestUSBSetDeviceType(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfo deviceInfo;
    std::string deviceType = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    deviceInfo.SetDeviceType(deviceType);
    deviceType = deviceInfo.GetDeviceType();
}

void TestUSBSetDeviceState(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfo deviceInfo;
    uint32_t deviceState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    deviceInfo.SetDeviceState(deviceState);
    deviceState = deviceInfo.GetDeviceState();
}

void TestUSBSetDiscoverMode(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfo deviceInfo;
    std::string discoverMode = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    deviceInfo.SetDiscoverMode(discoverMode);
    discoverMode = deviceInfo.GetDiscoverMode();
}

void TestUSBSetSerialNumber(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfo deviceInfo;
    std::string serialNumber = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    deviceInfo.SetSerialNumber(serialNumber);
    serialNumber = deviceInfo.GetSerialNumber();
}

void TestSetMinValue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanRange range;
    int32_t minValue = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    range.SetMinValue(minValue);
    minValue = range.GetMinValue();
}

void TestSetMaxValue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanRange range;
    int32_t maxValue = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    range.SetMaxValue(maxValue);
    maxValue = range.GetMaxValue();
}

void TestSetQuantValue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanRange range;
    int32_t quantValue = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    range.SetQuantValue(quantValue);
    quantValue = range.GetQuantValue();
}

void TestScanRange(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanRange range;
    range.Reset();
    int32_t maxValue = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    range.SetMaxValue(maxValue);
    ScanRange rangeBak(range);
    MessageParcel parcel;
    range.Marshalling(parcel);
    auto rangeMarshall = ScanRange::Unmarshalling(parcel);
}

void TestDeviceInfo(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    ScanDeviceInfoTCP infoTcp;
    uint32_t deviceState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    infoTcp.SetDeviceState(deviceState);
    ScanDeviceInfoTCP infoTcpTmp(infoTcp);
    ScanDeviceInfoTCP infoTcpBak(infoTcpTmp);
    MessageParcel parcel;
    infoTcpBak.Marshalling(parcel);
    auto infoTcpMarshall = ScanDeviceInfoTCP::Unmarshalling(parcel);

    ScanDeviceInfo info;
    info.SetDeviceState(deviceState);
    ScanDeviceInfo infoTmp(info);
    ScanDeviceInfo infoBak(infoTmp);
    infoBak.Marshalling(parcel);
    auto infoMarshall = ScanDeviceInfo::Unmarshalling(parcel);
}

void TestScanOptDesNapiInterface(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    ScanOptionDescriptor info;
    uint32_t optionUnit = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    info.SetOptionUnit(optionUnit);
    ScanOptionDescriptorHelper::MakeJsObject(env, info);
    napi_value jsValue = nullptr;
    ScanOptionDescriptorHelper::BuildFromJs(env, jsValue);
}

void TestScanOptValNapiInterface(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    ScanOptionValue info;
    int32_t valueType = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    info.SetScanOptionValueType(static_cast<ScanOptionValueType>(valueType));
    ScanOptionValueHelper::MakeJsObject(env, info);
    napi_value jsValue = nullptr;
    ScanOptionValueHelper::BuildFromJs(env, jsValue);
}

void TestScanParaNapiInterface(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    ScanParameters info;
    int32_t format = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    info.SetFormat(static_cast<ScanFrame>(format));
    ScanParametersHelper::MakeJsObject(env, info);
    napi_value jsValue = nullptr;
    ScanParametersHelper::BuildFromJs(env, jsValue);
}

void TestScanProgNapiInterface(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    ScanProgress info;
    int32_t progress = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    info.SetScanProgress(progress);
    ScanProgressHelper::MakeJsObject(env, info);
}

void TestScanRangeNapiInterface(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    ScanRange info;
    int32_t maxValue = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    info.SetMaxValue(maxValue);
    ScanRangeHelper::MakeJsObject(env, info);
    napi_value jsValue = nullptr;
    ScanRangeHelper::BuildFromJs(env, jsValue);
}

void TestScannerInfoNapiInterface(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    ScanDeviceInfo info;
    std::string deviceId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    info.SetDeviceId(deviceId);
    ScannerInfoHelper::MakeJsObject(env, info);
}

void TestScannerInfoTCPNapiInterface(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    ScanDeviceInfoTCP info;
    uint32_t deviceState = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    info.SetDeviceState(deviceState);
    ScannerInfoHelperTCP::MakeJsObject(env, info);
}

void TestSetNamedProperty(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_value object = nullptr;
    std::string name = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    napi_value value = nullptr;
    NapiScanUtils::SetNamedProperty(env, object, name, value);
}

void TestGetUint32FromValue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_value value = nullptr;
    NapiScanUtils::GetUint32FromValue(env, value);
}

void TestGetInt32FromValue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_value value = nullptr;
    NapiScanUtils::GetInt32FromValue(env, value);
}

void TestGetStringFromValueUtf8(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_value value = nullptr;
    NapiScanUtils::GetStringFromValueUtf8(env, value);
}

void TestValueIsArrayBuffer(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_value value = nullptr;
    NapiScanUtils::ValueIsArrayBuffer(env, value);
}

void TestGetInfoFromArrayBufferValue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_value value = nullptr;
    size_t *length = nullptr;
    NapiScanUtils::GetInfoFromArrayBufferValue(env, value, length);
}

void TestCreateObject(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    NapiScanUtils::CreateObject(env);
}

void TestGetUndefined(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    NapiScanUtils::GetUndefined(env);
}

void TestCallFunction(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_value recv = nullptr;
    napi_value func = nullptr;
    size_t argc = 0;
    napi_value *argv = nullptr;
    NapiScanUtils::CallFunction(env, recv, func, argc, argv);
}

void TestCreateReference(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_value callback = nullptr;
    NapiScanUtils::CreateReference(env, callback);
}

void TestCreateBoolean(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    bool value = 1;
    NapiScanUtils::CreateBoolean(env, value);
}

void TestGetBooleanFromValue(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_value value = nullptr;
    NapiScanUtils::GetBooleanFromValue(env, value);
}

void TestGetBooleanProperty(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_value object = nullptr;
    std::string propertyName = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    NapiScanUtils::GetBooleanProperty(env, object, propertyName);
}

void TestSetBooleanProperty(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_value object = nullptr;
    std::string name = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    bool value = 1;
    NapiScanUtils::SetBooleanProperty(env, object, name, value);
}

void TestToLower(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string s = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    NapiScanUtils::ToLower(s);
}

void TestGetValueString(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_value jsValue = nullptr;
    NapiScanUtils::GetValueString(env, jsValue);
}

void TestGetExtensionIdInterface(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string globalId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    NapiScanUtils::GetExtensionId(globalId);
}

void TestGetGlobalIdInterface(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string globalId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string localId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    NapiScanUtils::GetGlobalId(globalId, localId);
}

void TestGetLocalIdInterface(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string globalId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string extensionId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    NapiScanUtils::GetLocalId(globalId, extensionId);
}

void TestEncodeExtensionCidInterface(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string globalId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t callbackId = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    NapiScanUtils::EncodeExtensionCid(globalId, callbackId);
}

void TestDecodeExtensionCid(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string cid = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string extensionId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    uint32_t callbackId = dataProvider->ConsumeIntegralInRange<uint32_t>(0, MAX_SET_NUMBER);
    NapiScanUtils::DecodeExtensionCid(cid, extensionId, callbackId);
}

void TestGetTaskEventId(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string taskId = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string type = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    int32_t userId = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    int32_t callerPid = dataProvider->ConsumeIntegralInRange<int32_t>(0, MAX_SET_NUMBER);
    NapiScanUtils::GetTaskEventId(taskId, type, userId, callerPid);
}

void TestEncodeTaskEventId(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string eventType = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    std::string type;
    NapiScanUtils::EncodeTaskEventId(eventType, type);
}

void TestOpenFile(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string filePath = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    NapiScanUtils::OpenFile(filePath);
}

void TestIsPathValid(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    std::string filePath = dataProvider->ConsumeRandomLengthString(MAX_STRING_LENGTH);
    NapiScanUtils::IsPathValid(filePath);
}

void TestGetJsVal(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    napi_env env = nullptr;
    napi_callback_info info = nullptr;
    napi_value* jsValue = nullptr;
    size_t length = 1;
    NapiScanUtils::GetJsVal(env, info, jsValue, length);
}

void ScanOptionDescriptorFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    TestSetOptionName(data, size, dataProvider);
    TestSetOptionTitle(data, size, dataProvider);
    TestSetOptionDesc(data, size, dataProvider);
    TestSetOptionType(data, size, dataProvider);
    TestSetOptionUnit(data, size, dataProvider);
    TestSetOptionSize(data, size, dataProvider);
    TestSetOptionCap(data, size, dataProvider);
    TestSetOptionConstraintType(data, size, dataProvider);
    TestSetOptionConstraintString(data, size, dataProvider);
    TestSetOptionConstraintNumber(data, size, dataProvider);
    TestSetOptionConstraintRange(data, size, dataProvider);
    TestScanOptionDescriptor(data, size, dataProvider);
}

void ScanOptionValueFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    TestSetScanOptionValueType(data, size, dataProvider);
    TestSetValueSize(data, size, dataProvider);
    TestSetNumValue(data, size, dataProvider);
    TestSetNumListValue(data, size, dataProvider);
    TestSetStrValue(data, size, dataProvider);
    TestSetBoolValue(data, size, dataProvider);
    TestScanOptionValue(data, size, dataProvider);
}

void ScanParametersFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    TestSetFormat(data, size, dataProvider);
    TestSetLastFrame(data, size, dataProvider);
    TestSetBytesPerLine(data, size, dataProvider);
    TestSetPixelsPerLine(data, size, dataProvider);
    TestSetLines(data, size, dataProvider);
    TestSetDepth(data, size, dataProvider);
    TestScanParameters(data, size, dataProvider);
}

void ScanDeviceInfoFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    TestSetScanProgress(data, size, dataProvider);
    TestSetScanPictureFd(data, size, dataProvider);
    TestSetIsFinal(data, size, dataProvider);
    TestSetPictureId(data, size, dataProvider);
    TestSetTaskCode(data, size, dataProvider);
    TestScanProgress(data, size, dataProvider);
}

void ScannerInfoFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    TestTCPSetDeviceName(data, size, dataProvider);
    TestTCPSetUuid(data, size, dataProvider);
    TestTCPSetModel(data, size, dataProvider);
    TestTCPSetManufacturer(data, size, dataProvider);
    TestTCPSetDeviceType(data, size, dataProvider);
    TestTCPSetPort(data, size, dataProvider);
    TestTCPSetAddr(data, size, dataProvider);
    TestTCPSetButton(data, size, dataProvider);
    TestTCPSetFeeder(data, size, dataProvider);
    TestTCPSetDeviceState(data, size, dataProvider);
    TestUSBSetDeviceId(data, size, dataProvider);
    TestUSBSetManufacturer(data, size, dataProvider);
    TestUSBSetModel(data, size, dataProvider);
    TestUSBSetDeviceType(data, size, dataProvider);
    TestUSBSetDeviceState(data, size, dataProvider);
    TestUSBSetDiscoverMode(data, size, dataProvider);
    TestUSBSetSerialNumber(data, size, dataProvider);
    TestDeviceInfo(data, size, dataProvider);
}

void ScanRangeFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    TestSetMinValue(data, size, dataProvider);
    TestSetMaxValue(data, size, dataProvider);
    TestSetQuantValue(data, size, dataProvider);
    TestScanRange(data, size, dataProvider);
}

void ScanOptionDescriptorHelperFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    TestScanOptDesNapiInterface(data, size, dataProvider);
}

void ScanOptionValueHelperFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    TestScanOptValNapiInterface(data, size, dataProvider);
}

void ScanParametersHelperFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    TestScanParaNapiInterface(data, size, dataProvider);
}

void ScanProgressHelperFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    TestScanProgNapiInterface(data, size, dataProvider);
}

void ScanRangeHelperFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    TestScanRangeNapiInterface(data, size, dataProvider);
}

void ScannerInfoHelperFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    TestScannerInfoNapiInterface(data, size, dataProvider);
    TestScannerInfoTCPNapiInterface(data, size, dataProvider);
}

void NapiScanUtilsFuzzTest(const uint8_t* data, size_t size, FuzzedDataProvider* dataProvider)
{
    TestSetNamedProperty(data, size, dataProvider);
    TestGetUint32FromValue(data, size, dataProvider);
    TestGetInt32FromValue(data, size, dataProvider);
    TestGetStringFromValueUtf8(data, size, dataProvider);
    TestValueIsArrayBuffer(data, size, dataProvider);
    TestGetInfoFromArrayBufferValue(data, size, dataProvider);
    TestCreateObject(data, size, dataProvider);
    TestGetUndefined(data, size, dataProvider);
    TestCallFunction(data, size, dataProvider);
    TestCreateReference(data, size, dataProvider);
    TestCreateBoolean(data, size, dataProvider);
    TestGetBooleanFromValue(data, size, dataProvider);
    TestGetBooleanProperty(data, size, dataProvider);
    TestSetBooleanProperty(data, size, dataProvider);
    TestToLower(data, size, dataProvider);
    TestGetValueString(data, size, dataProvider);
    TestGetExtensionIdInterface(data, size, dataProvider);
    TestGetGlobalIdInterface(data, size, dataProvider);
    TestGetLocalIdInterface(data, size, dataProvider);
    TestEncodeExtensionCidInterface(data, size, dataProvider);
    TestDecodeExtensionCid(data, size, dataProvider);
    TestGetTaskEventId(data, size, dataProvider);
    TestEncodeTaskEventId(data, size, dataProvider);
    TestOpenFile(data, size, dataProvider);
    TestIsPathValid(data, size, dataProvider);
    TestGetJsVal(data, size, dataProvider);
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
    OHOS::Scan::ScanOptionDescriptorFuzzTest(data, size, &dataProvider);
    OHOS::Scan::ScanOptionValueFuzzTest(data, size, &dataProvider);
    OHOS::Scan::ScanParametersFuzzTest(data, size, &dataProvider);
    OHOS::Scan::ScanDeviceInfoFuzzTest(data, size, &dataProvider);
    OHOS::Scan::ScannerInfoFuzzTest(data, size, &dataProvider);
    OHOS::Scan::ScanRangeFuzzTest(data, size, &dataProvider);
    OHOS::Scan::ScanOptionDescriptorHelperFuzzTest(data, size, &dataProvider);
    OHOS::Scan::ScanOptionValueHelperFuzzTest(data, size, &dataProvider);
    OHOS::Scan::ScanParametersHelperFuzzTest(data, size, &dataProvider);
    OHOS::Scan::ScanProgressHelperFuzzTest(data, size, &dataProvider);
    OHOS::Scan::ScanRangeHelperFuzzTest(data, size, &dataProvider);
    OHOS::Scan::ScannerInfoHelperFuzzTest(data, size, &dataProvider);
    OHOS::Scan::NapiScanUtilsFuzzTest(data, size, &dataProvider);
    return 0;
}

