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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <thread>
#include <chrono>
#include "print_constant.h"
#define private public
#define protected public
#include "smb_host_search_helper.h"
#include "smb_printer_discoverer.h"
#include "smb_printer_state_monitor.h"
#undef protected
#undef private

using namespace testing::ext;
using namespace OHOS::Print;

namespace {
    constexpr int32_t TEST_TIMEOUT_MS = 500;
    constexpr int32_t INVALID_SOCKET = -1;
}

class SmbPrinterHelperTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
};

void SmbPrinterHelperTest::SetUpTestCase(void)
{}

void SmbPrinterHelperTest::TearDownTestCase(void)
{}

/**
 * @tc.name: SmbHostSearchHelper_Constructor_001
 * @tc.desc: Test SmbHostSearchHelper constructor and destructor
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, SmbHostSearchHelper_Constructor_001, TestSize.Level1)
{
    SmbHostSearchHelper helper;
    EXPECT_NE(helper.sock_, INVALID_SOCKET);
    EXPECT_NE(helper.ipRange_, nullptr);
    EXPECT_NE(helper.timer_, nullptr);
    EXPECT_NE(helper.scannedHosts_, nullptr);
}

/**
 * @tc.name: GetSharedHosts_001
 * @tc.desc: Test GetSharedHosts returns empty vector when no hosts scanned
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, GetSharedHosts_001, TestSize.Level1)
{
    SmbHostSearchHelper helper;
    auto hosts = helper.GetSharedHosts();
    EXPECT_TRUE(hosts.empty());
}

/**
 * @tc.name: TestSmbHostAlive_001
 * @tc.desc: Test TestSmbHostAlive with invalid IP
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, TestSmbHostAlive_001, TestSize.Level1)
{
    SmbHostSearchHelper helper;
    bool result = helper.TestSmbHostAlive("invalid_ip_address");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: TestSmbHostAlive_002
 * @tc.desc: Test TestSmbHostAlive with valid IP but no response
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, TestSmbHostAlive_002, TestSize.Level1)
{
    SmbHostSearchHelper helper;
    bool result = helper.TestSmbHostAlive("192.168.255.255", TEST_TIMEOUT_MS);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: HighResTimer_CanSend_001
 * @tc.desc: Test HighResTimer CanSend method
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, HighResTimer_CanSend_001, TestSize.Level1)
{
    int32_t sendIntervalUs = 2000;
    SmbHostSearchHelper::HighResTimer timer(sendIntervalUs);
    timer.SetInterval(sendIntervalUs);
    constexpr int32_t intervalMs = 2;
    std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
    bool canSend = timer.CanSend();
    EXPECT_TRUE(canSend);
    timer.UpdateSendTime();
    canSend = timer.CanSend();
    EXPECT_FALSE(canSend);
    std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
    canSend = timer.CanSend();
    EXPECT_TRUE(canSend);
}

/**
 * @tc.name: NetworkIpRange_Constructor_001
 * @tc.desc: Test NetworkIpRange constructor with valid range
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, NetworkIpRange_Constructor_001, TestSize.Level1)
{
    const std::string testIpRangeStart = "192.168.1.1";
    const std::string testIpRangeEnd = "192.168.1.254";
    SmbHostSearchHelper::NetworkIpRange ipRange(testIpRangeStart, testIpRangeEnd);
    struct in_addr nextAddr;
    bool hasNext = ipRange.Next(&nextAddr);
    EXPECT_TRUE(hasNext);
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &nextAddr, ipStr, INET_ADDRSTRLEN);
    EXPECT_STREQ(testIpRangeStart.c_str(), ipStr);
}

/**
 * @tc.name: NetworkIpRange_Next_001
 * @tc.desc: Test NetworkIpRange Next method iteration
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, NetworkIpRange_Next_001, TestSize.Level1)
{
    const std::string testIpRangeStart = "192.168.1.1";
    const std::string testIpRangeEnd = "192.168.1.3";
    SmbHostSearchHelper::NetworkIpRange ipRange(testIpRangeStart, testIpRangeEnd);
    struct in_addr nextAddr;
    std::vector<std::string> ips;
    while (ipRange.Next(&nextAddr)) {
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &nextAddr, ipStr, INET_ADDRSTRLEN);
        ips.push_back(ipStr);
    }
    EXPECT_EQ(ips.size(), 3);
    EXPECT_EQ(ips[0], "192.168.1.1");
    EXPECT_EQ(ips[1], "192.168.1.2");
    EXPECT_EQ(ips[2], "192.168.1.3");
}

/**
 * @tc.name: HostList_Contains_001
 * @tc.desc: Test HostList Contains method
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, HostList_Contains_001, TestSize.Level1)
{
    SmbHostSearchHelper::HostList hostList;
    const std::string testIpStr = "192.168.1.100";
    uint32_t testIp = inet_addr(testIpStr.c_str());
    hostList.Add(testIp, testIpStr);
    EXPECT_TRUE(hostList.Contains(testIp));
    uint32_t differentIp = inet_addr("192.168.1.101");
    EXPECT_FALSE(hostList.Contains(differentIp));
}

/**
 * @tc.name: HostList_GetPrintSharedHost_001
 * @tc.desc: Test HostList GetPrintSharedHost method
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, HostList_GetPrintSharedHost_001, TestSize.Level1)
{
    SmbHostSearchHelper::HostList hostList;
    const std::string testIp1 = "192.168.1.100";
    const std::string testIp2 = "192.168.1.101";
    const std::string testIp3 = "192.168.1.102";
    hostList.Add(inet_addr(testIp1.c_str()), testIp1);
    hostList.Add(inet_addr(testIp2.c_str()), testIp2);
    hostList.Add(inet_addr(testIp3.c_str()), testIp3);
    auto hosts = hostList.GetPrintSharedHost();
    constexpr int32_t hostListSize = 3;
    EXPECT_EQ(hosts.size(), hostListSize);
    if (hosts.size() == hostListSize) {
        EXPECT_EQ(hosts[0].GetIp(), testIp3);
        EXPECT_EQ(hosts[1].GetIp(), testIp2);
        EXPECT_EQ(hosts[2].GetIp(), testIp1);
    }
}

/**
 * @tc.name: InitializeSock_001
 * @tc.desc: Test InitializeSock method
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, InitializeSock_001, TestSize.Level1)
{
    SmbHostSearchHelper helper;
    if (helper.sock_ != INVALID_SOCKET) {
        close(helper.sock_);
        helper.sock_ = INVALID_SOCKET;
    }
    bool result = helper.InitializeSock();
    EXPECT_TRUE(result);
    EXPECT_NE(helper.sock_, INVALID_SOCKET);
}

/**
 * @tc.name: SetTimeval_001
 * @tc.desc: Test SetTimeval method
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, SetTimeval_001, TestSize.Level1)
{
    SmbHostSearchHelper helper;
    timeval tv;
    const long tvSec = 1;
    const long tvUsec = 500000; // 0.5 seconds
    helper.SetTimeval(tv, tvSec, tvUsec);
    EXPECT_EQ(tv.tv_sec, tvSec);
    EXPECT_EQ(tv.tv_usec, tvUsec);
}

/**
 * @tc.name: SetQuestionName_001
 * @tc.desc: Test SetQuestionName method
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, SetQuestionName_001, TestSize.Level1)
{
    SmbHostSearchHelper helper;
    SmbHostSearchHelper::NbnameRequest request = {};
    helper.SetQuestionName(request);
    EXPECT_NE(request.questionName[0], '\0');
}

/**
 * @tc.name: GetFileServerName_001
 * @tc.desc: Test GetFileServerName method
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, GetFileServerName_001, TestSize.Level1)
{
    SmbHostSearchHelper helper;
    std::string serverName = helper.GetFileServerName();
    EXPECT_TRUE(serverName.empty());
}

/**
 * @tc.name: SendQuery_001
 * @tc.desc: Test SendQuery method with invalid socket
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, SendQuery_001, TestSize.Level1)
{
    SmbHostSearchHelper helper;
    close(helper.sock_);
    helper.sock_ = INVALID_SOCKET;
    const std::string testIp = "192.168.1.100";
    struct in_addr destAddr;
    inet_pton(AF_INET, testIp.c_str(), &destAddr);
    bool result = helper.SendQuery(destAddr);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: HandleSend_001
 * @tc.desc: Test HandleSend method without initialized ipRange
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, HandleSend_001, TestSize.Level1)
{
    SmbHostSearchHelper helper;
    helper.ipRange_ = nullptr;
    bool result = helper.HandleSend();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: HandleReceive_001
 * @tc.desc: Test HandleReceive method with empty buffer
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, HandleReceive_001, TestSize.Level1)
{
    SmbHostSearchHelper helper;
    helper.scannedHosts_ = std::make_unique<SmbHostSearchHelper::HostList>();
    bool result = helper.HandleReceive();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: CreateFromLocalNetwork_001
 * @tc.desc: Test NetworkIpRange::CreateFromLocalNetwork static method
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, CreateFromLocalNetwork_001, TestSize.Level1)
{
    auto ipRange = SmbHostSearchHelper::NetworkIpRange::CreateFromLocalNetwork();
    EXPECT_NE(ipRange, nullptr);
    struct in_addr nextAddr;
    bool hasNext = ipRange->Next(&nextAddr);
    EXPECT_TRUE(hasNext);
}

/**
 * @tc.name: ParseIpFromSmbPrinterId_001
 * @tc.desc: Test ParseIpFromSmbPrinterId with valid SMB printer ID
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, ParseIpFromSmbPrinterId_001, TestSize.Level1)
{
    std::string printerId = "smb-192.168.1.100-PrinterName";
    std::string ip = SmbPrinterDiscoverer::ParseIpFromSmbPrinterId(printerId);
    EXPECT_EQ(ip, "192.168.1.100");
    printerId = "invalid_printer_id";
    ip = SmbPrinterDiscoverer::ParseIpFromSmbPrinterId(printerId);
    EXPECT_TRUE(ip.empty());
}

/**
 * @tc.name: IsSmbPrinterId_001
 * @tc.desc: Test IsSmbPrinterId with valid SMB printer ID
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, IsSmbPrinterId_001, TestSize.Level1)
{
    std::string printerId = "smb://192.168.1.100/PrinterName";
    bool result = SmbPrinterDiscoverer::IsSmbPrinterId(printerId);
    EXPECT_TRUE(result);
    printerId = "ipp://192.168.1.100/PrinterName";
    result = SmbPrinterDiscoverer::IsSmbPrinterId(printerId);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: CreatePrinterId_001
 * @tc.desc: Test CreatePrinterId method
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, CreatePrinterId_001, TestSize.Level1)
{
    SmbPrinterDiscoverer discoverer;
    std::string ip = "192.168.1.100";
    std::string name = "TestPrinter";
    std::string printerId = discoverer.CreatePrinterId(ip, name);
    EXPECT_EQ(printerId, "smb-192.168.1.100-TestPrinter");
}

/**
 * @tc.name: ReplaceSpacesInPrinterUri_001
 * @tc.desc: Test ReplaceSpacesInPrinterUri method
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, ReplaceSpacesInPrinterUri_001, TestSize.Level1)
{
    SmbPrinterDiscoverer discoverer;
    std::string input = "smb://192.168.1.100/TestPrinter";
    std::string result = discoverer.ReplaceSpacesInPrinterUri(input);
    EXPECT_EQ(result, "smb://192.168.1.100/TestPrinter");

    input = "smb://192.168.1.100/Test Printer Name";
    result = discoverer.ReplaceSpacesInPrinterUri(input);
    EXPECT_EQ(result, "smb://192.168.1.100/Test%20Printer%20Name");

    input = "smb://192.168.1.100/Printer  with   multiple    spaces";
    result = discoverer.ReplaceSpacesInPrinterUri(input);
    EXPECT_EQ(result, "smb://192.168.1.100/Printer%20%20with%20%20%20multiple%20%20%20%20spaces");
}

/**
 * @tc.name: SetCredentials_001
 * @tc.desc: Test SetCredentials method
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, SetCredentials_001, TestSize.Level1)
{
    SmbPrinterDiscoverer discoverer;
    std::string userName = "testuser";
    char userPasswd[] = "testpassword";
    
    int32_t result = discoverer.SetCredentials(userName, userPasswd);
    EXPECT_EQ(result, E_PRINT_NONE);
}


/**
 * @tc.name: QuerySmbPrinters_001
 * @tc.desc: Test QuerySmbPrinters with invalid shared host
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, QuerySmbPrinters_001, TestSize.Level1)
{
    SmbPrinterDiscoverer discoverer;
    PrintSharedHost sharedHost;
    sharedHost.SetIp("192.168.2.3");
    std::string userName = "testuser";
    char userPasswd[] = "testpassword";
    std::vector<PrinterInfo> infos;
    int32_t result = discoverer.QuerySmbPrinters(sharedHost, userName, userPasswd, infos);
    EXPECT_NE(result, 0);
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.name: SmbEventLoop_001
 * @tc.desc: Test SmbEventLoop with null smb context
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, SmbEventLoop_001, TestSize.Level1)
{
    SmbPrinterDiscoverer discoverer;
    discoverer.smbCtx_ = nullptr;
    int32_t result = discoverer.SmbEventLoop();
    EXPECT_NE(result, 0);
}

/**
 * @tc.name: GeneratePrinterInfos_001
 * @tc.desc: Test GeneratePrinterInfos with empty printers list
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, GeneratePrinterInfos_001, TestSize.Level1)
{
    SmbPrinterDiscoverer discoverer;
    std::vector<PrinterInfo> infos;
    std::string ip = "192.168.2.3";
    discoverer.GeneratePrinterInfos(ip, infos);
    EXPECT_TRUE(infos.empty());
    for (int32_t i = 0; i < 3; i++) {
        PrinterInfo info;
        infos.push_back(info);
    }
    discoverer.GeneratePrinterInfos(ip, infos);
    EXPECT_EQ(infos.size(), 3);
}

/**
 * @tc.name: ShareEnumCallback_001
 * @tc.desc: Test ShareEnumCallback with error status
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, ShareEnumCallback_001, TestSize.Level1)
{
    SmbPrinterDiscoverer discoverer;
    struct smb2_context* smb2 = nullptr;
    int32_t status = -1;
    void* commandData = nullptr;
    discoverer.ShareEnumCallback(smb2, status, commandData);
    EXPECT_TRUE(discoverer.isFinished_);
}

/**
 * @tc.name: SmbPrinterStateMonitor_Integration
 * @tc.desc: Test integration of all smbPrintermonitor functions
 * @tc.type: FUNC
 */
HWTEST_F(SmbPrinterHelperTest, SmbPrinterStateMonitor_Integration, TestSize.Level1)
{
    SmbPrinterStateMonitor& smbPrintermonitor = SmbPrinterStateMonitor::GetInstance();

    int32_t callbackCount = 0;
    auto notifyCallback = [&callbackCount](const PrinterInfo& printerInfo) {
        callbackCount++;
    };
    smbPrintermonitor.StartSmbPrinterStatusMonitor(notifyCallback);
    EXPECT_TRUE(smbPrintermonitor.isMonitoring_.load());
    PrinterInfo printerInfo;
    std::string printerId = "smb://100.100.100.100/test_printer";
    printerInfo.SetPrinterId(printerId);
    printerInfo.SetPrinterStatus(PrinterStatus::PRINTER_STATUS_IDLE);
    smbPrintermonitor.SetSmbPrinterInMonitorList(printerInfo);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    auto it = smbPrintermonitor.monitorSmbPrinters_.find(printerId);
    if (it != smbPrintermonitor.monitorSmbPrinters_.end()) {
        EXPECT_EQ(it->second.second, SmbPrinterStateMonitor::HostStatus::DEAD);
    }
    smbPrintermonitor.EraseSmbPrinterInMonitorListById(printerId);
    smbPrintermonitor.StopSmbPrinterStatusMonitor();
    EXPECT_FALSE(smbPrintermonitor.isMonitoring_.load());
    EXPECT_EQ(callbackCount, 1);
}