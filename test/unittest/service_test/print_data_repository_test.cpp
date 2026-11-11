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
#include <memory>
#include <thread>
#include "print_data_repository.h"
#include "printer_info.h"

using namespace testing::ext;

namespace OHOS {
namespace Print {

class PrintDataRepositoryTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() override;
    void TearDown() override;
};

void PrintDataRepositoryTest::SetUp()
{
    PrintDataRepository::GetInstance().Init();
}

void PrintDataRepositoryTest::TearDown()
{
    PrintDataRepository::GetInstance().ClearDiscoveredPrinterList();
}

HWTEST_F(PrintDataRepositoryTest, PrintDataRepository_QueryAddedPrinterInfoByPrinterId_FoundAndNotFound,
    TestSize.Level1)
{
    PrinterInfo info;
    info.SetPrinterId("printer-001");
    info.SetPrinterName("Test Printer");
    PrintDataRepository::GetInstance().InsertAddedPrinter("printer-001", info);

    PrinterInfo out;
    EXPECT_TRUE(PrintDataRepository::GetInstance().QueryAddedPrinterInfoByPrinterId("printer-001", out));
    EXPECT_EQ(out.GetPrinterId(), "printer-001");

    PrinterInfo missingOut;
    EXPECT_FALSE(PrintDataRepository::GetInstance().QueryAddedPrinterInfoByPrinterId("missing", missingOut));
}

HWTEST_F(PrintDataRepositoryTest, PrintDataRepository_QueryDiscoveredPrinterInfoById_Found, TestSize.Level1)
{
    auto info = std::make_shared<PrinterInfo>();
    info->SetPrinterId("discovered-001");
    PrintDataRepository::GetInstance().AddPrinterToDiscovery(info);

    auto out = PrintDataRepository::GetInstance().QueryDiscoveredPrinterInfoById("discovered-001");
    EXPECT_NE(out, nullptr);
    EXPECT_EQ(out->GetPrinterId(), "discovered-001");
}

HWTEST_F(PrintDataRepositoryTest, PrintDataRepository_QueryDiscoveredPrinterInfoById_ReturnsSnapshot, TestSize.Level1)
{
    auto original = std::make_shared<PrinterInfo>();
    original->SetPrinterId("snapshot-id");
    original->SetPrinterName("Original");
    PrintDataRepository::GetInstance().AddPrinterToDiscovery(original);

    auto out = PrintDataRepository::GetInstance().QueryDiscoveredPrinterInfoById("snapshot-id");
    ASSERT_NE(out, nullptr);
    EXPECT_EQ(out->GetPrinterName(), "Original");

    original->SetPrinterName("Mutated");
    out = PrintDataRepository::GetInstance().QueryDiscoveredPrinterInfoById("snapshot-id");
    ASSERT_NE(out, nullptr);
    EXPECT_EQ(out->GetPrinterName(), "Original");
}

HWTEST_F(PrintDataRepositoryTest, PrintDataRepository_AddPrinterToDiscovery_CopiesInput, TestSize.Level1)
{
    auto info = std::make_shared<PrinterInfo>();
    info->SetPrinterId("copy-id");
    info->SetPrinterName("Before");
    PrintDataRepository::GetInstance().AddPrinterToDiscovery(info);

    info->SetPrinterName("After");
    auto out = PrintDataRepository::GetInstance().QueryDiscoveredPrinterInfoById("copy-id");
    ASSERT_NE(out, nullptr);
    EXPECT_EQ(out->GetPrinterName(), "Before");
}

HWTEST_F(PrintDataRepositoryTest, PrintDataRepository_DiscoveredPrinter_ConcurrentQueryUpdateDelete, TestSize.Level1)
{
    const std::string printerId = "concurrent-id";
    auto info = std::make_shared<PrinterInfo>();
    info->SetPrinterId(printerId);
    info->SetPrinterName("Initial");
    PrintDataRepository::GetInstance().AddPrinterToDiscovery(info);

    constexpr int iterations = 1000;
    std::thread updater([printerId, iterations]() {
        for (int i = 0; i < iterations; ++i) {
            PrinterInfo update;
            update.SetPrinterId(printerId);
            update.SetPrinterName("Update" + std::to_string(i));
            PrintDataRepository::GetInstance().UpdateDiscoveredPrinterInfo(printerId, update);
            PrintDataRepository::GetInstance().SetDiscoveredPrinterState(printerId, PRINTER_CONNECTED);
        }
    });
    std::thread remover([printerId, iterations]() {
        for (int i = 0; i < iterations; ++i) {
            PrintDataRepository::GetInstance().RemovePrinterFromDiscovery(printerId);
            auto add = std::make_shared<PrinterInfo>();
            add->SetPrinterId(printerId);
            add->SetPrinterName("Readded" + std::to_string(i));
            PrintDataRepository::GetInstance().AddPrinterToDiscovery(add);
        }
    });
    std::thread reader([printerId, iterations]() {
        for (int i = 0; i < iterations; ++i) {
            auto out = PrintDataRepository::GetInstance().QueryDiscoveredPrinterInfoById(printerId);
            (void)out;
            auto map = PrintDataRepository::GetInstance().GetDiscoveredPrinterInfo();
            (void)map;
        }
    });

    updater.join();
    remover.join();
    reader.join();
    EXPECT_TRUE(true);
}

HWTEST_F(PrintDataRepositoryTest, PrintDataRepository_IpPrinter_ConcurrentQueryUpdateDelete, TestSize.Level1)
{
    const std::string printerId = "concurrent-ip-id";
    auto info = std::make_shared<PrinterInfo>();
    info->SetPrinterId(printerId);
    info->SetPrinterName("IP Initial");
    PrintDataRepository::GetInstance().AddIpPrinterToList(info);

    constexpr int iterations = 1000;
    std::thread updater([printerId, iterations]() {
        for (int i = 0; i < iterations; ++i) {
            PrinterInfo update;
            update.SetPrinterId(printerId);
            update.SetPrinterName("IP Update" + std::to_string(i));
            PrintDataRepository::GetInstance().UpdateIpPrinterInfo(printerId, update);
            PrintDataRepository::GetInstance().SetIpPrinterState(printerId, PRINTER_CONNECTED);
        }
    });
    std::thread remover([printerId, iterations]() {
        for (int i = 0; i < iterations; ++i) {
            PrintDataRepository::GetInstance().RemoveIpPrinterFromList(printerId);
            auto add = std::make_shared<PrinterInfo>();
            add->SetPrinterId(printerId);
            add->SetPrinterName("IP Readded" + std::to_string(i));
            PrintDataRepository::GetInstance().AddIpPrinterToList(add);
        }
    });
    std::thread reader([printerId, iterations]() {
        for (int i = 0; i < iterations; ++i) {
            auto out = PrintDataRepository::GetInstance().QueryIpPrinterInfoById(printerId);
            (void)out;
        }
    });

    updater.join();
    remover.join();
    reader.join();
    PrintDataRepository::GetInstance().RemoveIpPrinterFromList(printerId);
    EXPECT_TRUE(true);
}

HWTEST_F(PrintDataRepositoryTest, PrintDataRepository_QueryAddedPrinterInfoByPrinterId_P2PFallback, TestSize.Level1)
{
    auto nonP2pInfo = std::make_shared<PrinterInfo>();
    nonP2pInfo->SetPrinterId("discovered-001");
    nonP2pInfo->SetPrinterName("Discovered Printer");
    PrintDataRepository::GetInstance().AddPrinterToDiscovery(nonP2pInfo);

    PrinterInfo out;
    EXPECT_FALSE(PrintDataRepository::GetInstance().QueryAddedPrinterInfoByPrinterId("discovered-001", out));

    auto p2pInfo = std::make_shared<PrinterInfo>();
    p2pInfo->SetPrinterId("p2p-discovered-001");
    p2pInfo->SetPrinterName("P2P Discovered Printer");
    PrintDataRepository::GetInstance().AddPrinterToDiscovery(p2pInfo);

    EXPECT_TRUE(PrintDataRepository::GetInstance().QueryAddedPrinterInfoByPrinterId("p2p-discovered-001", out));
    EXPECT_EQ(out.GetPrinterId(), "p2p-discovered-001");
    EXPECT_EQ(out.GetPrinterName(), "P2P Discovered Printer");
}

HWTEST_F(PrintDataRepositoryTest, PrintDataRepository_IsPrinterPpdUpdateRequired_HashScenarios, TestSize.Level1)
{
    PrinterInfo info;
    info.SetPrinterId("StandardPrinter");
    info.SetPrinterName("StandardPrinter");
    PrintDataRepository::GetInstance().InsertAddedPrinter("StandardPrinter", info);

    EXPECT_TRUE(PrintDataRepository::GetInstance().IsPrinterPpdUpdateRequired("StandardPrinter", "hash-1"));
    PrintDataRepository::GetInstance().UpdatePpdHashCode("StandardPrinter", "hash-1");
    EXPECT_FALSE(PrintDataRepository::GetInstance().IsPrinterPpdUpdateRequired("StandardPrinter", "hash-1"));
    EXPECT_TRUE(PrintDataRepository::GetInstance().IsPrinterPpdUpdateRequired("StandardPrinter", "hash-2"));
    EXPECT_TRUE(PrintDataRepository::GetInstance().IsPrinterPpdUpdateRequired("OtherPrinter", "hash-1"));
    EXPECT_TRUE(PrintDataRepository::GetInstance().IsPrinterPpdUpdateRequired("StandardPrinter", "hash-3"));
}

HWTEST_F(PrintDataRepositoryTest, PrintDataRepository_UpdateDiscoveredPrinterInfo_SuccessAndFailure, TestSize.Level1)
{
    auto info = std::make_shared<PrinterInfo>();
    info->SetPrinterId("update-target");
    info->SetPrinterName("Original Name");
    PrintDataRepository::GetInstance().AddPrinterToDiscovery(info);

    PrinterInfo updatedInfo;
    updatedInfo.SetPrinterId("update-target");
    updatedInfo.SetPrinterName("Updated Name");
    PrintDataRepository::GetInstance().UpdateDiscoveredPrinterInfo("update-target", updatedInfo);

    auto out = PrintDataRepository::GetInstance().QueryDiscoveredPrinterInfoById("update-target");
    ASSERT_NE(out, nullptr);
    EXPECT_EQ(out->GetPrinterName(), "Updated Name");

    PrinterInfo notExistInfo;
    notExistInfo.SetPrinterId("not-exist");
    PrintDataRepository::GetInstance().UpdateDiscoveredPrinterInfo("not-exist", notExistInfo);
}

HWTEST_F(PrintDataRepositoryTest, PrintDataRepository_DiscoveredPrinterAliasAndState, TestSize.Level1)
{
    auto info = std::make_shared<PrinterInfo>();
    info->SetPrinterId("alias-target");
    info->SetPrinterName("Alias Printer");
    PrintDataRepository::GetInstance().AddPrinterToDiscovery(info);

    PrintDataRepository::GetInstance().SetDiscoveredPrinterAlias("alias-target", "my-alias");
    auto out = PrintDataRepository::GetInstance().QueryDiscoveredPrinterInfoById("alias-target");
    ASSERT_NE(out, nullptr);
    EXPECT_EQ(out->GetAlias(), "my-alias");

    PrintDataRepository::GetInstance().SetDiscoveredPrinterAlias("missing", "alias");
    PrintDataRepository::GetInstance().SetDiscoveredPrinterState("missing", PRINTER_ADDED);
}

} // namespace Print
} // namespace OHOS
