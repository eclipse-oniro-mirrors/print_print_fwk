/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include "scan_range.h"
#include "scan_option_value.h"
#include "scan_parameters.h"
#include "scan_progress.h"
#include "scan_option_descriptor.h"
#include "scanner_info.h"
#include "scan_constant.h"
#include "message_parcel.h"

using namespace testing::ext;

namespace OHOS {
namespace Scan {

// ==================== ScanRange Test ====================
class ScanRangeTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void ScanRangeTest::SetUpTestCase(void) {}
void ScanRangeTest::TearDownTestCase(void) {}

HWTEST_F(ScanRangeTest, ScanRangeTest_0001, TestSize.Level2)
{
    ScanRange range;
    EXPECT_EQ(0, range.GetMinValue());
    EXPECT_EQ(0, range.GetMaxValue());
    EXPECT_EQ(0, range.GetQuantValue());
}

HWTEST_F(ScanRangeTest, ScanRangeTest_0002, TestSize.Level2)
{
    ScanRange range;
    range.SetMinValue(10);
    range.SetMaxValue(100);
    range.SetQuantValue(5);
    EXPECT_EQ(10, range.GetMinValue());
    EXPECT_EQ(100, range.GetMaxValue());
    EXPECT_EQ(5, range.GetQuantValue());
}

HWTEST_F(ScanRangeTest, ScanRangeTest_0003_CopyConstructor, TestSize.Level2)
{
    ScanRange range1;
    range1.SetMinValue(10);
    range1.SetMaxValue(100);
    range1.SetQuantValue(5);
    ScanRange range2(range1);
    EXPECT_EQ(10, range2.GetMinValue());
    EXPECT_EQ(100, range2.GetMaxValue());
    EXPECT_EQ(5, range2.GetQuantValue());
}

HWTEST_F(ScanRangeTest, ScanRangeTest_0004_Assignment, TestSize.Level2)
{
    ScanRange range1;
    range1.SetMinValue(10);
    range1.SetMaxValue(100);
    range1.SetQuantValue(5);
    ScanRange range2;
    range2 = range1;
    EXPECT_EQ(10, range2.GetMinValue());
    EXPECT_EQ(100, range2.GetMaxValue());
    EXPECT_EQ(5, range2.GetQuantValue());
}

HWTEST_F(ScanRangeTest, ScanRangeTest_0005_Reset, TestSize.Level2)
{
    ScanRange range;
    range.SetMinValue(10);
    range.SetMaxValue(100);
    range.SetQuantValue(5);
    range.Reset();
    EXPECT_EQ(0, range.GetMinValue());
    EXPECT_EQ(0, range.GetMaxValue());
    EXPECT_EQ(0, range.GetQuantValue());
}

HWTEST_F(ScanRangeTest, ScanRangeTest_0006_Marshalling, TestSize.Level2)
{
    ScanRange range;
    range.SetMinValue(10);
    range.SetMaxValue(100);
    range.SetQuantValue(5);
    Parcel parcel;
    EXPECT_EQ(true, range.Marshalling(parcel));
}

HWTEST_F(ScanRangeTest, ScanRangeTest_0007_Unmarshalling, TestSize.Level2)
{
    ScanRange range;
    range.SetMinValue(10);
    range.SetMaxValue(100);
    range.SetQuantValue(5);
    Parcel parcel;
    range.Marshalling(parcel);
    auto result = ScanRange::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(10, result->GetMinValue());
    EXPECT_EQ(100, result->GetMaxValue());
    EXPECT_EQ(5, result->GetQuantValue());
}

HWTEST_F(ScanRangeTest, ScanRangeTest_0008_Dump, TestSize.Level2)
{
    ScanRange range;
    range.SetMinValue(10);
    range.SetMaxValue(100);
    range.SetQuantValue(5);
    range.Dump();
    EXPECT_EQ(10, range.GetMinValue());
}

// ==================== ScanOptionValue Test ====================
class ScanOptionValueTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void ScanOptionValueTest::SetUpTestCase(void) {}
void ScanOptionValueTest::TearDownTestCase(void) {}

HWTEST_F(ScanOptionValueTest, ScanOptionValueTest_0001, TestSize.Level2)
{
    ScanOptionValue value;
    EXPECT_EQ(SCAN_VALUE_BOOL, value.GetScanOptionValueType());
    EXPECT_EQ(0, value.GetValueSize());
    EXPECT_EQ(0, value.GetNumValue());
    EXPECT_EQ("", value.GetStrValue());
    EXPECT_EQ(false, value.GetBoolValue());
}

HWTEST_F(ScanOptionValueTest, ScanOptionValueTest_0002_SetNumValue, TestSize.Level2)
{
    ScanOptionValue value;
    value.SetScanOptionValueType(SCAN_VALUE_NUM);
    value.SetValueSize(1);
    value.SetNumValue(100);
    EXPECT_EQ(SCAN_VALUE_NUM, value.GetScanOptionValueType());
    EXPECT_EQ(1, value.GetValueSize());
    EXPECT_EQ(100, value.GetNumValue());
}

HWTEST_F(ScanOptionValueTest, ScanOptionValueTest_0003_SetStrValue, TestSize.Level2)
{
    ScanOptionValue value;
    value.SetScanOptionValueType(SCAN_VALUE_STR);
    value.SetValueSize(1);
    value.SetStrValue("test");
    EXPECT_EQ(SCAN_VALUE_STR, value.GetScanOptionValueType());
    EXPECT_EQ("test", value.GetStrValue());
}

HWTEST_F(ScanOptionValueTest, ScanOptionValueTest_0004_SetBoolValue, TestSize.Level2)
{
    ScanOptionValue value;
    value.SetBoolValue(true);
    EXPECT_EQ(true, value.GetBoolValue());
}

HWTEST_F(ScanOptionValueTest, ScanOptionValueTest_0005_SetNumListValue, TestSize.Level2)
{
    ScanOptionValue value;
    std::vector<int32_t> numList = {1, 2, 3, 4, 5};
    value.SetNumListValue(numList);
    std::vector<int32_t> result;
    value.GetNumListValue(result);
    EXPECT_EQ(5, result.size());
    EXPECT_EQ(1, result[0]);
    EXPECT_EQ(5, result[4]);
}

HWTEST_F(ScanOptionValueTest, ScanOptionValueTest_0006_CopyConstructor, TestSize.Level2)
{
    ScanOptionValue value1;
    value1.SetScanOptionValueType(SCAN_VALUE_NUM);
    value1.SetNumValue(100);
    ScanOptionValue value2(value1);
    EXPECT_EQ(SCAN_VALUE_NUM, value2.GetScanOptionValueType());
    EXPECT_EQ(100, value2.GetNumValue());
}

HWTEST_F(ScanOptionValueTest, ScanOptionValueTest_0007_Assignment, TestSize.Level2)
{
    ScanOptionValue value1;
    value1.SetScanOptionValueType(SCAN_VALUE_NUM);
    value1.SetNumValue(100);
    ScanOptionValue value2;
    value2 = value1;
    EXPECT_EQ(SCAN_VALUE_NUM, value2.GetScanOptionValueType());
    EXPECT_EQ(100, value2.GetNumValue());
}

HWTEST_F(ScanOptionValueTest, ScanOptionValueTest_0008_Reset, TestSize.Level2)
{
    ScanOptionValue value;
    value.SetScanOptionValueType(SCAN_VALUE_NUM);
    value.SetNumValue(100);
    value.Reset();
    EXPECT_EQ(SCAN_VALUE_BOOL, value.GetScanOptionValueType());
    EXPECT_EQ(0, value.GetNumValue());
}

HWTEST_F(ScanOptionValueTest, ScanOptionValueTest_0009_Marshalling_NumType, TestSize.Level2)
{
    ScanOptionValue value;
    value.SetScanOptionValueType(SCAN_VALUE_NUM);
    value.SetValueSize(1);
    value.SetNumValue(100);
    Parcel parcel;
    EXPECT_EQ(true, value.Marshalling(parcel));
}

HWTEST_F(ScanOptionValueTest, ScanOptionValueTest_0010_Marshalling_StrType, TestSize.Level2)
{
    ScanOptionValue value;
    value.SetScanOptionValueType(SCAN_VALUE_STR);
    value.SetValueSize(1);
    value.SetStrValue("test");
    Parcel parcel;
    EXPECT_EQ(true, value.Marshalling(parcel));
}

HWTEST_F(ScanOptionValueTest, ScanOptionValueTest_0011_Unmarshalling_NumType, TestSize.Level2)
{
    ScanOptionValue value;
    value.SetScanOptionValueType(SCAN_VALUE_NUM);
    value.SetValueSize(1);
    value.SetNumValue(100);
    Parcel parcel;
    value.Marshalling(parcel);
    auto result = ScanOptionValue::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(SCAN_VALUE_NUM, result->GetScanOptionValueType());
    EXPECT_EQ(100, result->GetNumValue());
}

HWTEST_F(ScanOptionValueTest, ScanOptionValueTest_0012_Unmarshalling_StrType, TestSize.Level2)
{
    ScanOptionValue value;
    value.SetScanOptionValueType(SCAN_VALUE_STR);
    value.SetValueSize(1);
    value.SetStrValue("test");
    Parcel parcel;
    value.Marshalling(parcel);
    auto result = ScanOptionValue::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(SCAN_VALUE_STR, result->GetScanOptionValueType());
    EXPECT_EQ("test", result->GetStrValue());
}

HWTEST_F(ScanOptionValueTest, ScanOptionValueTest_0013_Dump, TestSize.Level2)
{
    ScanOptionValue value;
    value.SetScanOptionValueType(SCAN_VALUE_NUM);
    value.SetNumValue(100);
    value.Dump();
    EXPECT_EQ(100, value.GetNumValue());
}

// ==================== ScanParameters Test ====================
class ScanParametersTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void ScanParametersTest::SetUpTestCase(void) {}
void ScanParametersTest::TearDownTestCase(void) {}

HWTEST_F(ScanParametersTest, ScanParametersTest_0001, TestSize.Level2)
{
    ScanParameters params;
    EXPECT_EQ(SCAN_FRAME_GRAY, params.GetFormat());
    EXPECT_EQ(false, params.GetLastFrame());
    EXPECT_EQ(0, params.GetBytesPerLine());
    EXPECT_EQ(0, params.GetPixelsPerLine());
    EXPECT_EQ(0, params.GetLines());
    EXPECT_EQ(0, params.GetDepth());
}

HWTEST_F(ScanParametersTest, ScanParametersTest_0002_SetValues, TestSize.Level2)
{
    ScanParameters params;
    params.SetFormat(SCAN_FRAME_RGB);
    params.SetLastFrame(true);
    params.SetBytesPerLine(100);
    params.SetPixelsPerLine(200);
    params.SetLines(300);
    params.SetDepth(8);
    EXPECT_EQ(SCAN_FRAME_RGB, params.GetFormat());
    EXPECT_EQ(true, params.GetLastFrame());
    EXPECT_EQ(100, params.GetBytesPerLine());
    EXPECT_EQ(200, params.GetPixelsPerLine());
    EXPECT_EQ(300, params.GetLines());
    EXPECT_EQ(8, params.GetDepth());
}

HWTEST_F(ScanParametersTest, ScanParametersTest_0003_CopyConstructor, TestSize.Level2)
{
    ScanParameters params1;
    params1.SetFormat(SCAN_FRAME_RGB);
    params1.SetBytesPerLine(100);
    ScanParameters params2(params1);
    EXPECT_EQ(SCAN_FRAME_RGB, params2.GetFormat());
    EXPECT_EQ(100, params2.GetBytesPerLine());
}

HWTEST_F(ScanParametersTest, ScanParametersTest_0004_Assignment, TestSize.Level2)
{
    ScanParameters params1;
    params1.SetFormat(SCAN_FRAME_RGB);
    params1.SetBytesPerLine(100);
    ScanParameters params2;
    params2 = params1;
    EXPECT_EQ(SCAN_FRAME_RGB, params2.GetFormat());
    EXPECT_EQ(100, params2.GetBytesPerLine());
}

HWTEST_F(ScanParametersTest, ScanParametersTest_0005_Reset, TestSize.Level2)
{
    ScanParameters params;
    params.SetFormat(SCAN_FRAME_RGB);
    params.SetBytesPerLine(100);
    params.Reset();
    EXPECT_EQ(SCAN_FRAME_GRAY, params.GetFormat());
    EXPECT_EQ(0, params.GetBytesPerLine());
}

HWTEST_F(ScanParametersTest, ScanParametersTest_0006_Marshalling, TestSize.Level2)
{
    ScanParameters params;
    params.SetFormat(SCAN_FRAME_RGB);
    params.SetLastFrame(true);
    params.SetBytesPerLine(100);
    params.SetPixelsPerLine(200);
    params.SetLines(300);
    params.SetDepth(8);
    Parcel parcel;
    EXPECT_EQ(true, params.Marshalling(parcel));
}

HWTEST_F(ScanParametersTest, ScanParametersTest_0007_Unmarshalling_Valid, TestSize.Level2)
{
    ScanParameters params;
    params.SetFormat(SCAN_FRAME_RGB);
    params.SetLastFrame(true);
    params.SetBytesPerLine(100);
    params.SetPixelsPerLine(200);
    params.SetLines(300);
    params.SetDepth(8);
    Parcel parcel;
    params.Marshalling(parcel);
    auto result = ScanParameters::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(SCAN_FRAME_RGB, result->GetFormat());
    EXPECT_EQ(100, result->GetBytesPerLine());
}

HWTEST_F(ScanParametersTest, ScanParametersTest_0008_Unmarshalling_Invalid, TestSize.Level2)
{
    ScanParameters params;
    params.SetBytesPerLine(0);  // Invalid value
    params.SetPixelsPerLine(0);
    params.SetLines(0);
    params.SetDepth(0);
    Parcel parcel;
    params.Marshalling(parcel);
    auto result = ScanParameters::Unmarshalling(parcel);
    EXPECT_EQ(nullptr, result);
}

HWTEST_F(ScanParametersTest, ScanParametersTest_0009_Dump, TestSize.Level2)
{
    ScanParameters params;
    params.SetFormat(SCAN_FRAME_RGB);
    params.SetBytesPerLine(100);
    params.Dump();
    EXPECT_EQ(SCAN_FRAME_RGB, params.GetFormat());
}

// ==================== ScanProgress Test ====================
class ScanProgressTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void ScanProgressTest::SetUpTestCase(void) {}
void ScanProgressTest::TearDownTestCase(void) {}

HWTEST_F(ScanProgressTest, ScanProgressTest_0001, TestSize.Level2)
{
    ScanProgress progress;
    EXPECT_EQ(0, progress.GetScanProgress());
    EXPECT_EQ(0, progress.GetScanPictureFd());
    EXPECT_EQ(true, progress.GetIsFinal());
    EXPECT_EQ(0, progress.GetPictureId());
    EXPECT_EQ(E_SCAN_NONE, progress.GetTaskCode());
    EXPECT_EQ("", progress.GetImageRealPath());
}

HWTEST_F(ScanProgressTest, ScanProgressTest_0002_SetValues, TestSize.Level2)
{
    ScanProgress progress;
    progress.SetScanProgress(50);
    progress.SetScanPictureFd(10);
    progress.SetIsFinal(false);
    progress.SetPictureId(100);
    progress.SetTaskCode(E_SCAN_GENERIC_FAILURE);
    progress.SetImageRealPath("/data/test.jpg");
    EXPECT_EQ(50, progress.GetScanProgress());
    EXPECT_EQ(10, progress.GetScanPictureFd());
    EXPECT_EQ(false, progress.GetIsFinal());
    EXPECT_EQ(100, progress.GetPictureId());
    EXPECT_EQ(E_SCAN_GENERIC_FAILURE, progress.GetTaskCode());
    EXPECT_EQ("/data/test.jpg", progress.GetImageRealPath());
}

HWTEST_F(ScanProgressTest, ScanProgressTest_0003_CopyConstructor, TestSize.Level2)
{
    ScanProgress progress1;
    progress1.SetScanProgress(50);
    progress1.SetScanPictureFd(10);
    ScanProgress progress2(progress1);
    EXPECT_EQ(50, progress2.GetScanProgress());
    EXPECT_EQ(10, progress2.GetScanPictureFd());
}

HWTEST_F(ScanProgressTest, ScanProgressTest_0004_Assignment, TestSize.Level2)
{
    ScanProgress progress1;
    progress1.SetScanProgress(50);
    progress1.SetScanPictureFd(10);
    ScanProgress progress2;
    progress2 = progress1;
    EXPECT_EQ(50, progress2.GetScanProgress());
    EXPECT_EQ(10, progress2.GetScanPictureFd());
}

HWTEST_F(ScanProgressTest, ScanProgressTest_0005_Marshalling, TestSize.Level2)
{
    ScanProgress progress;
    progress.SetScanProgress(50);
    progress.SetScanPictureFd(10);
    progress.SetIsFinal(false);
    MessageParcel parcel;
    EXPECT_EQ(true, progress.Marshalling(parcel));
}

HWTEST_F(ScanProgressTest, ScanProgressTest_0006_Unmarshalling, TestSize.Level2)
{
    ScanProgress progress;
    progress.SetScanProgress(50);
    progress.SetIsFinal(false);
    MessageParcel parcel;
    progress.Marshalling(parcel);
    auto result = ScanProgress::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ(50, result->GetScanProgress());
    EXPECT_EQ(false, result->GetIsFinal());
}

HWTEST_F(ScanProgressTest, ScanProgressTest_0007_Dump, TestSize.Level2)
{
    ScanProgress progress;
    progress.SetScanProgress(50);
    progress.SetScanPictureFd(10);
    progress.Dump();
    EXPECT_EQ(50, progress.GetScanProgress());
}

// ==================== ScanOptionDescriptor Test ====================
class ScanOptionDescriptorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void ScanOptionDescriptorTest::SetUpTestCase(void) {}
void ScanOptionDescriptorTest::TearDownTestCase(void) {}

HWTEST_F(ScanOptionDescriptorTest, ScanOptionDescriptorTest_0001, TestSize.Level2)
{
    ScanOptionDescriptor descriptor;
    EXPECT_EQ("", descriptor.GetOptionName());
    EXPECT_EQ(0, descriptor.GetOptionIndex());
    EXPECT_EQ("", descriptor.GetOptionTitle());
    EXPECT_EQ("", descriptor.GetOptionDesc());
    EXPECT_EQ(0, descriptor.GetOptionType());
    EXPECT_EQ(0, descriptor.GetOptionUnit());
    EXPECT_EQ(0, descriptor.GetOptionConstraintType());
}

HWTEST_F(ScanOptionDescriptorTest, ScanOptionDescriptorTest_0002_SetValues, TestSize.Level2)
{
    ScanOptionDescriptor descriptor;
    descriptor.SetOptionName("resolution");
    descriptor.SetOptionIndex(1);
    descriptor.SetOptionTitle("Resolution");
    descriptor.SetOptionDesc("Scan resolution in DPI");
    descriptor.SetOptionType(SCAN_VALUE_NUM);
    descriptor.SetOptionUnit(SCANNER_UNIT_DPI);
    descriptor.SetOptionConstraintType(SCAN_CONSTRAINT_RANGE);
    EXPECT_EQ("resolution", descriptor.GetOptionName());
    EXPECT_EQ(1, descriptor.GetOptionIndex());
    EXPECT_EQ("Resolution", descriptor.GetOptionTitle());
    EXPECT_EQ("Scan resolution in DPI", descriptor.GetOptionDesc());
    EXPECT_EQ(SCAN_VALUE_NUM, descriptor.GetOptionType());
    EXPECT_EQ(SCANNER_UNIT_DPI, descriptor.GetOptionUnit());
    EXPECT_EQ(SCAN_CONSTRAINT_RANGE, descriptor.GetOptionConstraintType());
}

HWTEST_F(ScanOptionDescriptorTest, ScanOptionDescriptorTest_0003_SetConstraintString, TestSize.Level2)
{
    ScanOptionDescriptor descriptor;
    std::vector<std::string> strList = {"auto", "color", "gray"};
    descriptor.SetOptionConstraintString(strList);
    std::vector<std::string> result;
    descriptor.GetOptionConstraintString(result);
    EXPECT_EQ(3, result.size());
    EXPECT_EQ("auto", result[0]);
    EXPECT_EQ("color", result[1]);
    EXPECT_EQ("gray", result[2]);
}

HWTEST_F(ScanOptionDescriptorTest, ScanOptionDescriptorTest_0004_SetConstraintNumber, TestSize.Level2)
{
    ScanOptionDescriptor descriptor;
    std::vector<int32_t> numList = {100, 200, 300, 600};
    descriptor.SetOptionConstraintNumber(numList);
    std::vector<int32_t> result;
    descriptor.GetOptionConstraintNumber(result);
    EXPECT_EQ(4, result.size());
    EXPECT_EQ(100, result[0]);
    EXPECT_EQ(600, result[3]);
}

HWTEST_F(ScanOptionDescriptorTest, ScanOptionDescriptorTest_0005_SetConstraintRange, TestSize.Level2)
{
    ScanOptionDescriptor descriptor;
    ScanRange range;
    range.SetMinValue(100);
    range.SetMaxValue(1200);
    range.SetQuantValue(100);
    descriptor.SetOptionConstraintRange(range);
    ScanRange result;
    descriptor.GetOptionConstraintRange(result);
    EXPECT_EQ(100, result.GetMinValue());
    EXPECT_EQ(1200, result.GetMaxValue());
    EXPECT_EQ(100, result.GetQuantValue());
}

HWTEST_F(ScanOptionDescriptorTest, ScanOptionDescriptorTest_0006_CopyConstructor, TestSize.Level2)
{
    ScanOptionDescriptor descriptor1;
    descriptor1.SetOptionName("resolution");
    descriptor1.SetOptionIndex(1);
    ScanOptionDescriptor descriptor2(descriptor1);
    EXPECT_EQ("resolution", descriptor2.GetOptionName());
    EXPECT_EQ(1, descriptor2.GetOptionIndex());
}

HWTEST_F(ScanOptionDescriptorTest, ScanOptionDescriptorTest_0007_Assignment, TestSize.Level2)
{
    ScanOptionDescriptor descriptor1;
    descriptor1.SetOptionName("resolution");
    descriptor1.SetOptionIndex(1);
    ScanOptionDescriptor descriptor2;
    descriptor2 = descriptor1;
    EXPECT_EQ("resolution", descriptor2.GetOptionName());
    EXPECT_EQ(1, descriptor2.GetOptionIndex());
}

HWTEST_F(ScanOptionDescriptorTest, ScanOptionDescriptorTest_0008_Marshalling, TestSize.Level2)
{
    ScanOptionDescriptor descriptor;
    descriptor.SetOptionName("resolution");
    descriptor.SetOptionIndex(1);
    descriptor.SetOptionTitle("Resolution");
    std::vector<std::string> strList = {"auto", "color"};
    descriptor.SetOptionConstraintString(strList);
    std::vector<int32_t> numList = {100, 200};
    descriptor.SetOptionConstraintNumber(numList);
    Parcel parcel;
    EXPECT_EQ(true, descriptor.Marshalling(parcel));
}

HWTEST_F(ScanOptionDescriptorTest, ScanOptionDescriptorTest_0009_Unmarshalling, TestSize.Level2)
{
    ScanOptionDescriptor descriptor;
    descriptor.SetOptionName("resolution");
    descriptor.SetOptionIndex(1);
    descriptor.SetOptionTitle("Resolution");
    std::vector<std::string> strList = {"auto", "color"};
    descriptor.SetOptionConstraintString(strList);
    std::vector<int32_t> numList = {100, 200};
    descriptor.SetOptionConstraintNumber(numList);
    Parcel parcel;
    descriptor.Marshalling(parcel);
    auto result = ScanOptionDescriptor::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ("resolution", result->GetOptionName());
    EXPECT_EQ(1, result->GetOptionIndex());
}

HWTEST_F(ScanOptionDescriptorTest, ScanOptionDescriptorTest_0010_Dump, TestSize.Level2)
{
    ScanOptionDescriptor descriptor;
    descriptor.SetOptionName("resolution");
    descriptor.SetOptionIndex(1);
    descriptor.Dump();
    EXPECT_EQ("resolution", descriptor.GetOptionName());
}

// ==================== ScanDeviceInfoTCP Test ====================
class ScanDeviceInfoTCPTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void ScanDeviceInfoTCPTest::SetUpTestCase(void) {}
void ScanDeviceInfoTCPTest::TearDownTestCase(void) {}

HWTEST_F(ScanDeviceInfoTCPTest, ScanDeviceInfoTCPTest_0001, TestSize.Level2)
{
    ScanDeviceInfoTCP info;
    EXPECT_EQ("", info.GetDeviceName());
    EXPECT_EQ("", info.GetUuid());
    EXPECT_EQ("", info.GetModel());
    EXPECT_EQ("", info.GetManufacturer());
    EXPECT_EQ("", info.GetDeviceType());
    EXPECT_EQ("", info.GetPort());
    EXPECT_EQ("", info.GetAddr());
    EXPECT_EQ("", info.GetButton());
    EXPECT_EQ("", info.GetFeeder());
    EXPECT_EQ(0, info.GetDeviceState());
}

HWTEST_F(ScanDeviceInfoTCPTest, ScanDeviceInfoTCPTest_0002_SetValues, TestSize.Level2)
{
    ScanDeviceInfoTCP info;
    info.SetDeviceName("Scanner1");
    info.SetUuid("uuid-1234");
    info.SetModel("Model-X");
    info.SetManufacturer("Manufacturer");
    info.SetDeviceType("scanner");
    info.SetPort("8080");
    info.SetAddr("192.168.1.100");
    info.SetButton("true");
    info.SetFeeder("true");
    info.SetDeviceState(1);
    EXPECT_EQ("Scanner1", info.GetDeviceName());
    EXPECT_EQ("uuid-1234", info.GetUuid());
    EXPECT_EQ("Model-X", info.GetModel());
    EXPECT_EQ("Manufacturer", info.GetManufacturer());
    EXPECT_EQ("scanner", info.GetDeviceType());
    EXPECT_EQ("8080", info.GetPort());
    EXPECT_EQ("192.168.1.100", info.GetAddr());
    EXPECT_EQ("true", info.GetButton());
    EXPECT_EQ("true", info.GetFeeder());
    EXPECT_EQ(1, info.GetDeviceState());
}

HWTEST_F(ScanDeviceInfoTCPTest, ScanDeviceInfoTCPTest_0003_CopyConstructor, TestSize.Level2)
{
    ScanDeviceInfoTCP info1;
    info1.SetDeviceName("Scanner1");
    info1.SetUuid("uuid-1234");
    ScanDeviceInfoTCP info2(info1);
    EXPECT_EQ("Scanner1", info2.GetDeviceName());
    EXPECT_EQ("uuid-1234", info2.GetUuid());
}

HWTEST_F(ScanDeviceInfoTCPTest, ScanDeviceInfoTCPTest_0004_Assignment, TestSize.Level2)
{
    ScanDeviceInfoTCP info1;
    info1.SetDeviceName("Scanner1");
    info1.SetUuid("uuid-1234");
    ScanDeviceInfoTCP info2;
    info2 = info1;
    EXPECT_EQ("Scanner1", info2.GetDeviceName());
    EXPECT_EQ("uuid-1234", info2.GetUuid());
}

HWTEST_F(ScanDeviceInfoTCPTest, ScanDeviceInfoTCPTest_0005_Marshalling, TestSize.Level2)
{
    ScanDeviceInfoTCP info;
    info.SetDeviceName("Scanner1");
    info.SetUuid("uuid-1234");
    Parcel parcel;
    EXPECT_EQ(true, info.Marshalling(parcel));
}

HWTEST_F(ScanDeviceInfoTCPTest, ScanDeviceInfoTCPTest_0006_Unmarshalling, TestSize.Level2)
{
    ScanDeviceInfoTCP info;
    info.SetDeviceName("Scanner1");
    info.SetUuid("uuid-1234");
    Parcel parcel;
    info.Marshalling(parcel);
    auto result = ScanDeviceInfoTCP::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ("Scanner1", result->GetDeviceName());
    EXPECT_EQ("uuid-1234", result->GetUuid());
}

// ==================== ScanDeviceInfo Test ====================
class ScanDeviceInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void ScanDeviceInfoTest::SetUpTestCase(void) {}
void ScanDeviceInfoTest::TearDownTestCase(void) {}

HWTEST_F(ScanDeviceInfoTest, ScanDeviceInfoTest_0001, TestSize.Level2)
{
    ScanDeviceInfo info;
    EXPECT_EQ("", info.GetDeviceId());
    EXPECT_EQ("", info.GetManufacturer());
    EXPECT_EQ("", info.GetModel());
    EXPECT_EQ("", info.GetDeviceType());
    EXPECT_EQ(0, info.GetDeviceState());
    EXPECT_EQ("", info.GetDiscoverMode());
    EXPECT_EQ("", info.GetSerialNumber());
    EXPECT_EQ("", info.GetDeviceName());
    EXPECT_EQ("", info.GetUniqueId());
    EXPECT_EQ("", info.GetUuid());
    EXPECT_EQ(true, info.GetDeviceAvailable());
}

HWTEST_F(ScanDeviceInfoTest, ScanDeviceInfoTest_0002_SetValues, TestSize.Level2)
{
    ScanDeviceInfo info;
    info.SetDeviceId("device-001");
    info.SetManufacturer("HP");
    info.SetModel("Scanner Pro");
    info.SetDeviceType("scanner");
    info.SetDeviceState(1);
    info.SetDiscoverMode("TCP");
    info.SetSerialNumber("SN12345");
    info.SetDeviceName("MyScanner");
    info.SetUniqueId("unique-001");
    info.SetUuid("uuid-1234");
    info.SetDeviceAvailable(false);
    EXPECT_EQ("device-001", info.GetDeviceId());
    EXPECT_EQ("HP", info.GetManufacturer());
    EXPECT_EQ("Scanner Pro", info.GetModel());
    EXPECT_EQ("scanner", info.GetDeviceType());
    EXPECT_EQ(1, info.GetDeviceState());
    EXPECT_EQ("TCP", info.GetDiscoverMode());
    EXPECT_EQ("SN12345", info.GetSerialNumber());
    EXPECT_EQ("MyScanner", info.GetDeviceName());
    EXPECT_EQ("unique-001", info.GetUniqueId());
    EXPECT_EQ("uuid-1234", info.GetUuid());
    EXPECT_EQ(false, info.GetDeviceAvailable());
}

HWTEST_F(ScanDeviceInfoTest, ScanDeviceInfoTest_0003_CopyConstructor, TestSize.Level2)
{
    ScanDeviceInfo info1;
    info1.SetDeviceId("device-001");
    info1.SetManufacturer("HP");
    ScanDeviceInfo info2(info1);
    EXPECT_EQ("device-001", info2.GetDeviceId());
    EXPECT_EQ("HP", info2.GetManufacturer());
}

HWTEST_F(ScanDeviceInfoTest, ScanDeviceInfoTest_0004_Assignment, TestSize.Level2)
{
    ScanDeviceInfo info1;
    info1.SetDeviceId("device-001");
    info1.SetManufacturer("HP");
    ScanDeviceInfo info2;
    info2 = info1;
    EXPECT_EQ("device-001", info2.GetDeviceId());
    EXPECT_EQ("HP", info2.GetManufacturer());
}

HWTEST_F(ScanDeviceInfoTest, ScanDeviceInfoTest_0005_Marshalling, TestSize.Level2)
{
    ScanDeviceInfo info;
    info.SetDeviceId("device-001");
    info.SetManufacturer("HP");
    Parcel parcel;
    EXPECT_EQ(true, info.Marshalling(parcel));
}

HWTEST_F(ScanDeviceInfoTest, ScanDeviceInfoTest_0006_Unmarshalling, TestSize.Level2)
{
    ScanDeviceInfo info;
    info.SetDeviceId("device-001");
    info.SetManufacturer("HP");
    Parcel parcel;
    info.Marshalling(parcel);
    auto result = ScanDeviceInfo::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ("device-001", result->GetDeviceId());
    EXPECT_EQ("HP", result->GetManufacturer());
}

HWTEST_F(ScanDeviceInfoTest, ScanDeviceInfoTest_0007_Dump, TestSize.Level2)
{
    ScanDeviceInfo info;
    info.SetDeviceId("device-001");
    info.SetManufacturer("HP");
    info.Dump();
    EXPECT_EQ("device-001", info.GetDeviceId());
}

// ==================== ScanDeviceInfoSync Test ====================
class ScanDeviceInfoSyncTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void ScanDeviceInfoSyncTest::SetUpTestCase(void) {}
void ScanDeviceInfoSyncTest::TearDownTestCase(void) {}

HWTEST_F(ScanDeviceInfoSyncTest, ScanDeviceInfoSyncTest_0001, TestSize.Level2)
{
    ScanDeviceInfoSync info;
    EXPECT_EQ("", info.GetDeviceId());
    EXPECT_EQ("", info.GetDiscoverMode());
    EXPECT_EQ("", info.GetSerialNumber());
    EXPECT_EQ("", info.GetSyncMode());
    EXPECT_EQ(0, info.GetDeviceState());
    EXPECT_EQ("", info.GetOldDeviceId());
    EXPECT_EQ("", info.GetUniqueId());
}

HWTEST_F(ScanDeviceInfoSyncTest, ScanDeviceInfoSyncTest_0002_SetValues, TestSize.Level2)
{
    ScanDeviceInfoSync info;
    info.SetDeviceId("device-001");
    info.SetDiscoverMode("TCP");
    info.SetSerialNumber("SN12345");
    info.SetSyncMode("update");
    info.SetDeviceState(1);
    info.SetOldDeviceId("old-device-001");
    info.SetUniqueId("unique-001");
    EXPECT_EQ("device-001", info.GetDeviceId());
    EXPECT_EQ("TCP", info.GetDiscoverMode());
    EXPECT_EQ("SN12345", info.GetSerialNumber());
    EXPECT_EQ("update", info.GetSyncMode());
    EXPECT_EQ(1, info.GetDeviceState());
    EXPECT_EQ("old-device-001", info.GetOldDeviceId());
    EXPECT_EQ("unique-001", info.GetUniqueId());
}

HWTEST_F(ScanDeviceInfoSyncTest, ScanDeviceInfoSyncTest_0003_CopyConstructor, TestSize.Level2)
{
    ScanDeviceInfoSync info1;
    info1.SetDeviceId("device-001");
    info1.SetSyncMode("update");
    ScanDeviceInfoSync info2(info1);
    EXPECT_EQ("device-001", info2.GetDeviceId());
    EXPECT_EQ("update", info2.GetSyncMode());
}

HWTEST_F(ScanDeviceInfoSyncTest, ScanDeviceInfoSyncTest_0004_Assignment, TestSize.Level2)
{
    ScanDeviceInfoSync info1;
    info1.SetDeviceId("device-001");
    info1.SetSyncMode("update");
    ScanDeviceInfoSync info2;
    info2 = info1;
    EXPECT_EQ("device-001", info2.GetDeviceId());
    EXPECT_EQ("update", info2.GetSyncMode());
}

HWTEST_F(ScanDeviceInfoSyncTest, ScanDeviceInfoSyncTest_0005_Marshalling, TestSize.Level2)
{
    ScanDeviceInfoSync info;
    info.SetDeviceId("device-001");
    info.SetSyncMode("update");
    Parcel parcel;
    EXPECT_EQ(true, info.Marshalling(parcel));
}

HWTEST_F(ScanDeviceInfoSyncTest, ScanDeviceInfoSyncTest_0006_Unmarshalling, TestSize.Level2)
{
    ScanDeviceInfoSync info;
    info.SetDeviceId("device-001");
    info.SetSyncMode("update");
    Parcel parcel;
    info.Marshalling(parcel);
    auto result = ScanDeviceInfoSync::Unmarshalling(parcel);
    EXPECT_NE(nullptr, result);
    EXPECT_EQ("device-001", result->GetDeviceId());
    EXPECT_EQ("update", result->GetSyncMode());
}

HWTEST_F(ScanDeviceInfoSyncTest, ScanDeviceInfoSyncTest_0007_Dump, TestSize.Level2)
{
    ScanDeviceInfoSync info;
    info.SetDeviceId("device-001");
    info.SetSyncMode("update");
    info.Dump();
    EXPECT_EQ("device-001", info.GetDeviceId());
}

}  // namespace Scan
}  // namespace OHOS
