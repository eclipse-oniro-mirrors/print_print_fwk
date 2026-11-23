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

#include <gtest/gtest.h>

#include "message_parcel.h"
#include "scanner_info.h"

using namespace testing::ext;

namespace OHOS {
namespace Scan {

class ScannerInfoTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void ScannerInfoTest::SetUpTestCase(void) {}
void ScannerInfoTest::TearDownTestCase(void) {}

// ==================== ScanDeviceInfoTCP ====================

/**
 * @tc.name: ScannerInfoTest_ScanDeviceInfoTCP_DefaultValues_0001
 * @tc.desc: Verify the default constructed ScanDeviceInfoTCP fields.
 */
HWTEST_F(ScannerInfoTest, ScannerInfoTest_ScanDeviceInfoTCP_DefaultValues_0001, TestSize.Level2)
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
    EXPECT_EQ(0u, info.GetDeviceState());
    EXPECT_FALSE(info.GetIsHttps());
}

/**
 * @tc.name: ScannerInfoTest_ScanDeviceInfoTCP_SettersGetters_0002
 * @tc.desc: Verify all setters and getters including isHttps.
 */
HWTEST_F(ScannerInfoTest, ScannerInfoTest_ScanDeviceInfoTCP_SettersGetters_0002, TestSize.Level2)
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
    info.SetDeviceState(7);
    info.SetIsHttps(true);
    EXPECT_EQ("Scanner1", info.GetDeviceName());
    EXPECT_EQ("uuid-1234", info.GetUuid());
    EXPECT_EQ("Model-X", info.GetModel());
    EXPECT_EQ("Manufacturer", info.GetManufacturer());
    EXPECT_EQ("scanner", info.GetDeviceType());
    EXPECT_EQ("8080", info.GetPort());
    EXPECT_EQ("192.168.1.100", info.GetAddr());
    EXPECT_EQ("true", info.GetButton());
    EXPECT_EQ("true", info.GetFeeder());
    EXPECT_EQ(7u, info.GetDeviceState());
    EXPECT_TRUE(info.GetIsHttps());
}

/**
 * @tc.name: ScannerInfoTest_ScanDeviceInfoTCP_CopyAndAssign_0003
 * @tc.desc: Verify copy constructor, assignment and self-assignment.
 */
HWTEST_F(ScannerInfoTest, ScannerInfoTest_ScanDeviceInfoTCP_CopyAndAssign_0003, TestSize.Level2)
{
    ScanDeviceInfoTCP info1;
    info1.SetDeviceName("Scanner1");
    info1.SetUuid("uuid-1234");
    info1.SetIsHttps(true);

    ScanDeviceInfoTCP info2(info1);
    EXPECT_EQ("Scanner1", info2.GetDeviceName());
    EXPECT_EQ("uuid-1234", info2.GetUuid());
    EXPECT_TRUE(info2.GetIsHttps());

    ScanDeviceInfoTCP info3;
    info3 = info1;
    EXPECT_EQ("Scanner1", info3.GetDeviceName());
    EXPECT_TRUE(info3.GetIsHttps());

    ScanDeviceInfoTCP &selfRef = info3;
    info3 = selfRef;
    EXPECT_EQ("Scanner1", info3.GetDeviceName());
    EXPECT_EQ("uuid-1234", info3.GetUuid());
}

/**
 * @tc.name: ScannerInfoTest_ScanDeviceInfoTCP_MarshallingRoundTrip_0004
 * @tc.desc: Verify marshalling/unmarshalling preserves serialized fields.
 */
HWTEST_F(ScannerInfoTest, ScannerInfoTest_ScanDeviceInfoTCP_MarshallingRoundTrip_0004, TestSize.Level2)
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
    info.SetIsHttps(true);

    MessageParcel parcel;
    EXPECT_TRUE(info.Marshalling(parcel));
    auto result = ScanDeviceInfoTCP::Unmarshalling(parcel);
    ASSERT_NE(nullptr, result);
    EXPECT_EQ("Scanner1", result->GetDeviceName());
    EXPECT_EQ("uuid-1234", result->GetUuid());
    EXPECT_EQ("Model-X", result->GetModel());
    EXPECT_EQ("Manufacturer", result->GetManufacturer());
    EXPECT_EQ("scanner", result->GetDeviceType());
    EXPECT_EQ("8080", result->GetPort());
    EXPECT_EQ("192.168.1.100", result->GetAddr());
    EXPECT_EQ("true", result->GetButton());
    EXPECT_EQ("true", result->GetFeeder());
    EXPECT_TRUE(result->GetIsHttps());
}

/**
 * @tc.name: ScannerInfoTest_ScanDeviceInfoTCP_ParcelFailure_0005
 * @tc.desc: Verify ReadFromParcel/Unmarshalling fail on an empty parcel.
 */
HWTEST_F(ScannerInfoTest, ScannerInfoTest_ScanDeviceInfoTCP_ParcelFailure_0005, TestSize.Level2)
{
    ScanDeviceInfoTCP info;
    MessageParcel emptyParcel;
    EXPECT_FALSE(info.ReadFromParcel(emptyParcel));

    MessageParcel emptyParcel2;
    EXPECT_EQ(nullptr, ScanDeviceInfoTCP::Unmarshalling(emptyParcel2));
}

// ==================== ScanDeviceInfo ====================

/**
 * @tc.name: ScannerInfoTest_ScanDeviceInfo_DefaultValues_0006
 * @tc.desc: Verify the default constructed ScanDeviceInfo fields.
 */
HWTEST_F(ScannerInfoTest, ScannerInfoTest_ScanDeviceInfo_DefaultValues_0006, TestSize.Level2)
{
    ScanDeviceInfo info;
    EXPECT_EQ("", info.GetDeviceId());
    EXPECT_EQ("", info.GetManufacturer());
    EXPECT_EQ("", info.GetModel());
    EXPECT_EQ("", info.GetDeviceType());
    EXPECT_EQ(0u, info.GetDeviceState());
    EXPECT_EQ("", info.GetDiscoverMode());
    EXPECT_EQ("", info.GetSerialNumber());
    EXPECT_EQ("", info.GetDeviceName());
    EXPECT_EQ("", info.GetUniqueId());
    EXPECT_EQ("", info.GetUuid());
    EXPECT_FALSE(info.GetIsHttps());
    EXPECT_TRUE(info.GetDeviceAvailable());
}

/**
 * @tc.name: ScannerInfoTest_ScanDeviceInfo_SettersGetters_0007
 * @tc.desc: Verify all setters and getters including uuid/isHttps/deviceAvailable.
 */
HWTEST_F(ScannerInfoTest, ScannerInfoTest_ScanDeviceInfo_SettersGetters_0007, TestSize.Level2)
{
    ScanDeviceInfo info;
    info.SetDeviceId("device-001");
    info.SetManufacturer("HP");
    info.SetModel("Scanner Pro");
    info.SetDeviceType("scanner");
    info.SetDeviceState(3);
    info.SetDiscoverMode("TCP");
    info.SetSerialNumber("SN12345");
    info.SetDeviceName("MyScanner");
    info.SetUniqueId("unique-001");
    info.SetUuid("uuid-1234");
    info.SetDeviceAvailable(false);
    info.SetIsHttps(true);
    EXPECT_EQ("device-001", info.GetDeviceId());
    EXPECT_EQ("HP", info.GetManufacturer());
    EXPECT_EQ("Scanner Pro", info.GetModel());
    EXPECT_EQ("scanner", info.GetDeviceType());
    EXPECT_EQ(3u, info.GetDeviceState());
    EXPECT_EQ("TCP", info.GetDiscoverMode());
    EXPECT_EQ("SN12345", info.GetSerialNumber());
    EXPECT_EQ("MyScanner", info.GetDeviceName());
    EXPECT_EQ("unique-001", info.GetUniqueId());
    EXPECT_EQ("uuid-1234", info.GetUuid());
    EXPECT_FALSE(info.GetDeviceAvailable());
    EXPECT_TRUE(info.GetIsHttps());
}

/**
 * @tc.name: ScannerInfoTest_ScanDeviceInfo_CopyAndAssign_0008
 * @tc.desc: Verify copy constructor, assignment and self-assignment.
 */
HWTEST_F(ScannerInfoTest, ScannerInfoTest_ScanDeviceInfo_CopyAndAssign_0008, TestSize.Level2)
{
    ScanDeviceInfo info1;
    info1.SetDeviceId("device-001");
    info1.SetUuid("uuid-1234");
    info1.SetIsHttps(true);
    info1.SetDeviceAvailable(false);

    ScanDeviceInfo info2(info1);
    EXPECT_EQ("device-001", info2.GetDeviceId());
    EXPECT_EQ("uuid-1234", info2.GetUuid());
    EXPECT_TRUE(info2.GetIsHttps());
    EXPECT_FALSE(info2.GetDeviceAvailable());

    ScanDeviceInfo info3;
    info3 = info1;
    EXPECT_EQ("device-001", info3.GetDeviceId());
    EXPECT_TRUE(info3.GetIsHttps());

    ScanDeviceInfo &selfRef = info3;
    info3 = selfRef;
    EXPECT_EQ("device-001", info3.GetDeviceId());
    EXPECT_EQ("uuid-1234", info3.GetUuid());
}

/**
 * @tc.name: ScannerInfoTest_ScanDeviceInfo_MarshallingRoundTrip_0009
 * @tc.desc: Verify marshalling/unmarshalling preserves serialized fields.
 */
HWTEST_F(ScannerInfoTest, ScannerInfoTest_ScanDeviceInfo_MarshallingRoundTrip_0009, TestSize.Level2)
{
    ScanDeviceInfo info;
    info.SetDeviceId("device-001");
    info.SetManufacturer("HP");
    info.SetModel("Scanner Pro");
    info.SetDeviceType("scanner");
    info.SetDiscoverMode("TCP");
    info.SetSerialNumber("SN12345");
    info.SetDeviceName("MyScanner");
    info.SetUniqueId("unique-001");
    info.SetIsHttps(true);

    MessageParcel parcel;
    EXPECT_TRUE(info.Marshalling(parcel));
    auto result = ScanDeviceInfo::Unmarshalling(parcel);
    ASSERT_NE(nullptr, result);
    EXPECT_EQ("device-001", result->GetDeviceId());
    EXPECT_EQ("HP", result->GetManufacturer());
    EXPECT_EQ("Scanner Pro", result->GetModel());
    EXPECT_EQ("scanner", result->GetDeviceType());
    EXPECT_EQ("TCP", result->GetDiscoverMode());
    EXPECT_EQ("SN12345", result->GetSerialNumber());
    EXPECT_EQ("MyScanner", result->GetDeviceName());
    EXPECT_EQ("unique-001", result->GetUniqueId());
    EXPECT_TRUE(result->GetIsHttps());
}

/**
 * @tc.name: ScannerInfoTest_ScanDeviceInfo_ParcelFailure_0010
 * @tc.desc: Verify ReadFromParcel/Unmarshalling fail on an empty parcel.
 */
HWTEST_F(ScannerInfoTest, ScannerInfoTest_ScanDeviceInfo_ParcelFailure_0010, TestSize.Level2)
{
    ScanDeviceInfo info;
    MessageParcel emptyParcel;
    EXPECT_FALSE(info.ReadFromParcel(emptyParcel));

    MessageParcel emptyParcel2;
    EXPECT_EQ(nullptr, ScanDeviceInfo::Unmarshalling(emptyParcel2));
}

// ==================== ScanDeviceInfoSync ====================

/**
 * @tc.name: ScannerInfoTest_ScanDeviceInfoSync_DefaultValues_0012
 * @tc.desc: Verify the default constructed ScanDeviceInfoSync fields.
 */
HWTEST_F(ScannerInfoTest, ScannerInfoTest_ScanDeviceInfoSync_DefaultValues_0012, TestSize.Level2)
{
    ScanDeviceInfoSync info;
    EXPECT_EQ("", info.GetDeviceId());
    EXPECT_EQ("", info.GetDiscoverMode());
    EXPECT_EQ("", info.GetSerialNumber());
    EXPECT_EQ("", info.GetSyncMode());
    EXPECT_EQ(0u, info.GetDeviceState());
    EXPECT_EQ("", info.GetOldDeviceId());
    EXPECT_EQ("", info.GetUniqueId());
}

/**
 * @tc.name: ScannerInfoTest_ScanDeviceInfoSync_SettersGetters_0013
 * @tc.desc: Verify all setters and getters.
 */
HWTEST_F(ScannerInfoTest, ScannerInfoTest_ScanDeviceInfoSync_SettersGetters_0013, TestSize.Level2)
{
    ScanDeviceInfoSync info;
    info.SetDeviceId("device-001");
    info.SetDiscoverMode("TCP");
    info.SetSerialNumber("SN12345");
    info.SetSyncMode("update");
    info.SetDeviceState(5);
    info.SetOldDeviceId("old-device-001");
    info.SetUniqueId("unique-001");
    EXPECT_EQ("device-001", info.GetDeviceId());
    EXPECT_EQ("TCP", info.GetDiscoverMode());
    EXPECT_EQ("SN12345", info.GetSerialNumber());
    EXPECT_EQ("update", info.GetSyncMode());
    EXPECT_EQ(5u, info.GetDeviceState());
    EXPECT_EQ("old-device-001", info.GetOldDeviceId());
    EXPECT_EQ("unique-001", info.GetUniqueId());
}

/**
 * @tc.name: ScannerInfoTest_ScanDeviceInfoSync_CopyAndAssign_0014
 * @tc.desc: Verify copy constructor, assignment and self-assignment.
 */
HWTEST_F(ScannerInfoTest, ScannerInfoTest_ScanDeviceInfoSync_CopyAndAssign_0014, TestSize.Level2)
{
    ScanDeviceInfoSync info1;
    info1.SetDeviceId("device-001");
    info1.SetSyncMode("update");
    info1.SetUniqueId("unique-001");

    ScanDeviceInfoSync info2(info1);
    EXPECT_EQ("device-001", info2.GetDeviceId());
    EXPECT_EQ("update", info2.GetSyncMode());
    EXPECT_EQ("unique-001", info2.GetUniqueId());

    ScanDeviceInfoSync info3;
    info3 = info1;
    EXPECT_EQ("device-001", info3.GetDeviceId());

    ScanDeviceInfoSync &selfRef = info3;
    info3 = selfRef;
    EXPECT_EQ("device-001", info3.GetDeviceId());
    EXPECT_EQ("unique-001", info3.GetUniqueId());
}

/**
 * @tc.name: ScannerInfoTest_ScanDeviceInfoSync_MarshallingRoundTrip_0015
 * @tc.desc: Verify marshalling/unmarshalling preserves serialized fields.
 */
HWTEST_F(ScannerInfoTest, ScannerInfoTest_ScanDeviceInfoSync_MarshallingRoundTrip_0015, TestSize.Level2)
{
    ScanDeviceInfoSync info;
    info.SetDeviceId("device-001");
    info.SetDiscoverMode("TCP");
    info.SetSyncMode("update");
    info.SetOldDeviceId("old-device-001");
    info.SetUniqueId("unique-001");

    MessageParcel parcel;
    EXPECT_TRUE(info.Marshalling(parcel));
    auto result = ScanDeviceInfoSync::Unmarshalling(parcel);
    ASSERT_NE(nullptr, result);
    EXPECT_EQ("device-001", result->GetDeviceId());
    EXPECT_EQ("TCP", result->GetDiscoverMode());
    EXPECT_EQ("update", result->GetSyncMode());
    EXPECT_EQ("old-device-001", result->GetOldDeviceId());
    EXPECT_EQ("unique-001", result->GetUniqueId());
}

/**
 * @tc.name: ScannerInfoTest_ScanDeviceInfoSync_ParcelFailure_0016
 * @tc.desc: Verify ReadFromParcel/Unmarshalling fail on an empty parcel.
 */
HWTEST_F(ScannerInfoTest, ScannerInfoTest_ScanDeviceInfoSync_ParcelFailure_0016, TestSize.Level2)
{
    ScanDeviceInfoSync info;
    MessageParcel emptyParcel;
    EXPECT_FALSE(info.ReadFromParcel(emptyParcel));

    MessageParcel emptyParcel2;
    EXPECT_EQ(nullptr, ScanDeviceInfoSync::Unmarshalling(emptyParcel2));
}

}  // namespace Scan
}  // namespace OHOS
