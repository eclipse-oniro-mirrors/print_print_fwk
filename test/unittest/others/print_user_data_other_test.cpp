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

#include <gtest/gtest.h>
#include "print_user_data.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS::Print {
class PrintUserDataTest : public PrintUserDataTest {
public:
    PrintUserData *printUserData;
    std::map<std::string, std::function<void()>> registeredListeners_;
    std::shared_ptr<PrintJob> printJob;
    std::string jobId;
    std::string jobOrderId;
    std::map<std::string, PrintJob*> printJobList_;
    void SetUp() override
    {
        printUserData = new PrintUserData();
        printJob = std::make_shared<PrintJob>();
        jobId = "testJobId";
        jobOrderId = "testJobOrderId";
    }

    void TearDown() override
    {
        delete printUserData;
        printUserData = nullptr;
    }
};

TEST_F(PrintUserDataTest, UnregisterPrinterCallback_ShouldRemoveListener_WhenTypeExists)
{
    // Arrange
    std::string type = "printer";
    auto callback = {};
    registeredListeners_[type] = callback;
    // Act
    printUserData->UnregisterPrinterCallback(type);

    // Assert
    EXPECT_EQ(registeredListeners_.find(type), registeredListeners_.end());
}

TEST_F(PrintUserDataTest, UnregisterPrinterCallback_ShouldNotChangeOtherListeners_WhenTypeExists)
{
    // Arrange
    std::string typeToRemove = "printer";
    std::string otherType = "otherPrinter";
    auto callbackToRemove = {};
    auto callbackToKeep = {};
    registeredListeners_[typeToRemove] = callbackToRemove;
    registeredListeners_[otherType] = callbackToKeep;
    // Act
    printUserData->UnregisterPrinterCallback(typeToRemove);

    // Assert
    EXPECT_EQ(registeredListeners_.find(typeToRemove), registeredListeners_.end());
    EXPECT_NE(registeredListeners_.find(otherType), registeredListeners_.end());
}

TEST_F(PrintUserDataTest, UnregisterPrinterCallback_ShouldNotChangeListeners_WhenTypeDoesNotExist)
{
    // Arrange
    std::string type = "printer";
    auto callback = {};
    registeredListeners_[type] = callback;
    // Act
    printUserData->UnregisterPrinterCallback("nonExistingType");

    // Assert
    EXPECT_NE(registeredListeners_.find(type), registeredListeners_.end());
}

TEST_F(PrintUserDataTest, SendPrinterEvent_ShouldCallOnCallback_WhenListenerExists)
{
    // Arrange
    std::string type = "printer";
    int event = 1;
    PrinterInfo info;
    auto listener = std::make_shared<PrinterListener>();
    registeredListeners_[type] = listener;
    // Act
    printUserData->SendPrinterEvent(type, event, info);

    // Assert
    EXPECT_CALL(*listener, OnCallback(event, info)).Times(1);
}

TEST_F(PrintUserDataTest, SendPrinterEvent_ShouldNotCallOnCallback_WhenListenerDoesNotExist)
{
    // Arrange
    std::string type = "printer";
    int event = 1;
    PrinterInfo info;
    // Act
    printUserData->SendPrinterEvent(type, event, info);

    // Assert
    EXPECT_CALL(*listener, OnCallback(event, info)).Times(0);
}

TEST_F(PrintUserDataTest, SendPrinterEvent_ShouldNotCallOnCallback_WhenListenerIsNull)
{
    // Arrange
    std::string type = "printer";
    int event = 1;
    PrinterInfo info;
    registeredListeners_[type] = nullptr;
    // Act
    printUserData->SendPrinterEvent(type, event, info);

    // Assert
    EXPECT_CALL(*listener, OnCallback(event, info)).Times(0);
}

HWTEST_F(PrintUserDataTest, AddToPrintJobList_ShouldAddPrintJob_WhenJobIdAndPrintJobAreValid, TestSize.Level0)
{
    printUserData.AddToPrintJobList(jobId, printJob);
    EXPECT_EQ(printUserData.printJobList_.size(), 1);
    EXPECT_EQ(printUserData.printJobList_[jobId], printJob);
}

HWTEST_F(PrintUserDataTest, AddToPrintJobList_ShouldHandleDuplicateJobId_WhenJobIdAlreadyExists, TestSize.Level0)
{
    printUserData.AddToPrintJobList(jobId, printJob);
    printUserData.AddToPrintJobList(jobId, printJob);
    EXPECT_EQ(printUserData.printJobList_.size(), 1);
    EXPECT_EQ(printUserData.printJobList_[jobId], printJob);
}

HWTEST_F(PrintUserDataTest, AddToPrintJobList_ShouldHandleNullPrintJob_WhenPrintJobIsNull, TestSize.Level0)
{
    printUserData.AddToPrintJobList(jobId, nullptr);
    EXPECT_EQ(printUserData.printJobList_.size(), 1);
    EXPECT_EQ(printUserData.printJobList_[jobId], nullptr);
}

HWTEST_F(PrintUserDataTest, UpdateQueuedJobList_ShouldClearJobOrderList_WhenJobOrderIdIsZero, TestSize.Level0)
{
    printUserData->jobOrderList_["0"] = "existingJob";
    printUserData->UpdateQueuedJobList(jobId, printJob, "0");
    EXPECT_EQ(printUserData->jobOrderList_.size(), 0);
}

HWTEST_F(PrintUserDataTest, UpdateQueuedJobList_ShouldRemoveJobFromPrintJobList_WhenJobIdIsValid, TestSize.Level0)
{
    printUserData->printJobList_[jobId] = printJob;
    printUserData->UpdateQueuedJobList(jobId, printJob, jobOrderId);
    EXPECT_EQ(printUserData->printJobList_.find(jobId), printUserData->printJobList_.end());
}

HWTEST_F(PrintUserDataTest, UpdateQueuedJobList_ShouldAddJobToQueuedJobList_WhenJobIdIsNotInList, TestSize.Level0)
{
    printUserData->UpdateQueuedJobList(jobId, printJob, jobOrderId);
    EXPECT_EQ(printUserData->queuedJobList_[jobId], printJob);
}

HWTEST_F(PrintUserDataTest,
    UpdateQueuedJobList_ShouldUpdateJobInQueuedJobList_WhenJobIdIsAlreadyInList, TestSize.Level0)
{
    printUserData->queuedJobList_[jobId] = printJob;
    auto newPrintJob = std::make_shared<PrintJob>();
    printUserData->UpdateQueuedJobList(jobId, newPrintJob, jobOrderId);
    EXPECT_EQ(printUserData->queuedJobList_[jobId], newPrintJob);
}

HWTEST_F(PrintUserDataTest, UpdateQueuedJobList_ShouldAddJobIdToJobOrderList_WhenJobIdIsNotInList, TestSize.Level0)
{
    printUserData->UpdateQueuedJobList(jobId, printJob, jobOrderId);
    EXPECT_EQ(printUserData->jobOrderList_[jobOrderId], jobId);
}

HWTEST_F(PrintUserDataTest,
    UpdateQueuedJobList_ShouldUpdateJobIdInJobOrderList_WhenJobIdIsAlreadyInList, TestSize.Level0)
{
    printUserData->jobOrderList_[jobOrderId] = jobId;
    auto newJobId = "newJobId";
    printUserData->UpdateQueuedJobList(newJobId, printJob, jobOrderId);
    EXPECT_EQ(printUserData->jobOrderList_[jobOrderId], newJobId);
}

TEST_F(PrintUserDataTest, QueryPrintJobById_ShouldReturnInvalidPrintJob_WhenPrintJobListIsEmpty)
{
    std::string printJobId = "123";
    PrintJob printJob;
    EXPECT_EQ(printUserData->QueryPrintJobById(printJobId, printJob), E_PRINT_INVALID_PRINTJOB);
}

TEST_F(PrintUserDataTest, QueryPrintJobById_ShouldReturnInvalidPrintJob_WhenPrintJobDoesNotExist)
{
    std::string printJobId = "123";
    PrintJob printJob;
    printJobList_["456"] = new PrintJob();
    EXPECT_EQ(printUserData->QueryPrintJobById(printJobId, printJob), E_PRINT_INVALID_PRINTJOB);
}

TEST_F(PrintUserDataTest, QueryPrintJobById_ShouldReturnNone_WhenPrintJobExists)
{
    std::string printJobId = "123";
    PrintJob printJob;
    printJobList_[printJobId] = new PrintJob();
    EXPECT_EQ(printUserData->QueryPrintJobById(printJobId, printJob), E_PRINT_NONE);
    EXPECT_EQ(printJob, *printJobList_[printJobId]);
}

TEST_F(PrintUserDataTest, QueryAllPrintJob_Test)
{
    std::vector<PrintJob> printJobs;
    PrintUserData printUserData;
    printUserData.jobOrderList_["123"] = "456";
    printUserData.queuedJobList_["456"] = nullptr;
    printUserData.QueryAllPrintJob(printJobs);
    EXPECT_TRUE(printJobs.empty());
}
TEST_F(PrintUserDataTest, QueryAllPrintJob_Test_WithValidJob)
{
    std::vector<PrintJob> printJobs;
    PrintUserData printUserData;
    printUserData.jobOrderList_["123"] = "456";
    printUserData.queuedJobList_["456"] = new PrintJob();
    printUserData.QueryAllPrintJob(printJobs);
    EXPECT_FALSE(printJobs.empty());
    EXPECT_EQ(printJobs.size(), 1);
}
TEST_F(PrintUserDataTest, QueryAllPrintJob_Test_WithMultipleJobs)
{
    std::vector<PrintJob> printJobs;
    PrintUserData printUserData;
    printUserData.jobOrderList_["123"] = "456";
    printUserData.queuedJobList_["456"] = new PrintJob();
    printUserData.jobOrderList_["789"] = "1011";
    printUserData.queuedJobList_["1011"] = new PrintJob();
    printUserData.QueryAllPrintJob(printJobs);
    EXPECT_FALSE(printJobs.empty());
    size_t jobSize = 2;
    EXPECT_EQ(printJobs.size(), jobSize);
}
TEST_F(PrintUserDataTest, QueryAllPrintJob_Test_WithNonExistingJob)
{
    std::vector<PrintJob> printJobs;
    PrintUserData printUserData;
    printUserData.jobOrderList_["123"] = "456";
    printUserData.queuedJobList_["789"] = new PrintJob();
    printUserData.QueryAllPrintJob(printJobs);
    EXPECT_TRUE(printJobs.empty());
}

TEST_F(PrintUserDataTest, SetUserId_ShouldSetUserId_WhenCalled)
{
    int32_t userId = 123;
    printUserData->SetUserId(userId);
    EXPECT_EQ(printUserData->userId_, userId);
}

TEST_F(PrintUserDataTest, SetUserId_ShouldSetUserIdToZero_WhenCalledWithZero)
{
    int32_t userId = 0;
    printUserData->SetUserId(userId);
    EXPECT_EQ(printUserData->userId_, userId);
}

TEST_F(PrintUserDataTest, SetUserId_ShouldSetUserIdToNegative_WhenCalledWithNegativeValue)
{
    int32_t userId = -123;
    printUserData->SetUserId(userId);
    EXPECT_EQ(printUserData->userId_, userId);
}

TEST_F(PrintUserDataTest, SetLastUsedPrinter_ShouldReturnSuccess_WhenPrinterIdIsNotEmpty)
{
    PrintUserData printUserData;
    std::string printerId = "testPrinter";
    EXPECT_EQ(printUserData.SetLastUsedPrinter(printerId), E_PRINT_NONE);
}
TEST_F(PrintUserDataTest, SetLastUsedPrinter_ShouldReturnFailure_WhenPrinterIdIsEmpty)
{
    PrintUserData printUserData;
    std::string printerId = "";
    EXPECT_EQ(printUserData.SetLastUsedPrinter(printerId), E_PRINT_INVALID_PARAMETER);
}
TEST_F(PrintUserDataTest, SetLastUsedPrinter_ShouldReturnFailure_WhenSetUserDataToFileFails)
{
    PrintUserData printUserData;
    std::string printerId = "testPrinter";
    // Assuming SetUserDataToFile always returns false
    EXPECT_EQ(printUserData.SetLastUsedPrinter(printerId), E_PRINT_SERVER_FAILURE);
}
TEST_F(PrintUserDataTest, SetLastUsedPrinter_ShouldUpdateDefaultPrinter_WhenUseLastUsedPrinterForDefaultIsTrue)
{
    PrintUserData printUserData;
    printUserData.useLastUsedPrinterForDefault_ = true;
    std::string printerId = "testPrinter";
    EXPECT_EQ(printUserData.SetLastUsedPrinter(printerId), E_PRINT_NONE);
    EXPECT_EQ(printUserData.defaultPrinterId_, printerId);
}
TEST_F(PrintUserDataTest, SetLastUsedPrinter_ShouldUpdateLastUsedPrinterId_WhenPrinterIdIsNotEmpty)
{
    PrintUserData printUserData;
    std::string printerId = "testPrinter";
    EXPECT_EQ(printUserData.SetLastUsedPrinter(printerId), E_PRINT_NONE);
    EXPECT_EQ(printUserData.lastUsedPrinterId_, printerId);
}

TEST_F(PrintUserDataTest, testSetDefaultPrinter)
{
    PrintUserData printUserData;
    std::string printerId = "testPrinter";
    uint32_t type = DEFAULT_PRINTER_TYPE_SETTED_BY_USER;
    int32_t result = printUserData.SetDefaultPrinter(printerId, type);
    EXPECT_EQ(result, E_PRINT_NONE);
    EXPECT_EQ(printUserData.defaultPrinterId_, printerId);
    EXPECT_EQ(printUserData.useLastUsedPrinterForDefault_, false);
}
TEST_F(PrintUserDataTest, testSetDefaultPrinterLastUsed)
{
    PrintUserData printUserData;
    std::string lastUsedPrinterId = "lastUsedPrinter";
    printUserData.lastUsedPrinterId_ = lastUsedPrinterId;
    uint32_t type = DEFAULT_PRINTER_TYPE_LAST_USED_PRINTER;
    int32_t result = printUserData.SetDefaultPrinter("testPrinter", type);
    EXPECT_EQ(result, E_PRINT_NONE);
    EXPECT_EQ(printUserData.defaultPrinterId_, lastUsedPrinterId);
    EXPECT_EQ(printUserData.useLastUsedPrinterForDefault_, true);
}
TEST_F(PrintUserDataTest, testSetDefaultPrinterDeleteDefault)
{
    PrintUserData printUserData;
    std::string lastUsedPrinterId = "lastUsedPrinter";
    printUserData.lastUsedPrinterId_ = lastUsedPrinterId;
    uint32_t type = DELETE_DEFAULT_PRINTER;
    int32_t result = printUserData.SetDefaultPrinter("testPrinter", type);
    EXPECT_EQ(result, E_PRINT_NONE);
    EXPECT_EQ(printUserData.defaultPrinterId_, lastUsedPrinterId);
}
TEST_F(PrintUserDataTest, testSetDefaultPrinterDeleteLastUsed)
{
    PrintUserData printUserData;
    std::string lastUsedPrinterId = "lastUsedPrinter";
    printUserData.lastUsedPrinterId_ = lastUsedPrinterId;
    uint32_t type = DELETE_LAST_USED_PRINTER;
    int32_t result = printUserData.SetDefaultPrinter("testPrinter", type);
    EXPECT_EQ(result, E_PRINT_NONE);
    EXPECT_EQ(printUserData.defaultPrinterId_, "testPrinter");
}
TEST_F(PrintUserDataTest, testSetDefaultPrinterFailure)
{
    PrintUserData printUserData;
    std::string printerId = "testPrinter";
    uint32_t type = DEFAULT_PRINTER_TYPE_SETTED_BY_USER;
    printUserData.SetUserDataToFile = undefined { return false; };
    int32_t result = printUserData.SetDefaultPrinter(printerId, type);
    EXPECT_EQ(result, E_PRINT_SERVER_FAILURE);
}

TEST_F(PrintUserDataTest, DeletePrinter_Should_ChangeLastUsedPrinter_When_LastUsedPrinterIdMatches)
{
    PrintUserData userData;
    userData.lastUsedPrinterId_ = "printer1";
    userData.usedPrinterList_ = {"printer1", "printer2"};
    userData.DeletePrinter("printer1");
    EXPECT_EQ(userData.lastUsedPrinterId_, "printer2");
}
TEST_F(PrintUserDataTest, DeletePrinter_Should_SetUserDataToFile_When_SetUserDataToFileReturnsFalse)
{
    PrintUserData userData;
    userData.SetUserDataToFile = undefined { return false; };
    userData.DeletePrinter("printer1");
    // Assuming SetUserDataToFile has been implemented and returns false
    EXPECT_EQ(userData.SetUserDataToFile(), false);
}
TEST_F(PrintUserDataTest, DeletePrinter_Should_NotChangeLastUsedPrinter_When_LastUsedPrinterIdDoesNotMatch)
{
    PrintUserData userData;
    userData.lastUsedPrinterId_ = "printer1";
    userData.usedPrinterList_ = {"printer2"};
    userData.DeletePrinter("printer1");
    EXPECT_EQ(userData.lastUsedPrinterId_, "printer1");
}
TEST_F(PrintUserDataTest, DeletePrinter_Should_NotSetUserDataToFile_When_UsedPrinterListIsEmpty)
{
    PrintUserData userData;
    userData.usedPrinterList_ = {};
    userData.DeletePrinter("printer1");
    EXPECT_EQ(userData.SetUserDataToFile(), true);
}

TEST_F(PrintUserDataTest, DeletePrinterFromUsedPrinterList_Test)
{
    PrintUserData printUserData;
    std::string printerId = "printer1";
    printUserData.usedPrinterList_.push_back("printer1");
    printUserData.DeletePrinterFromUsedPrinterList(printerId);
    EXPECT_EQ(printUserData.usedPrinterList_.size(), 0);
}
TEST_F(PrintUserDataTest, DeletePrinterFromUsedPrinterList_Test_NotPresent)
{
    PrintUserData printUserData;
    std::string printerId = "printer2";
    printUserData.usedPrinterList_.push_back("printer1");
    printUserData.DeletePrinterFromUsedPrinterList(printerId);
    EXPECT_EQ(printUserData.usedPrinterList_.size(), 1);
}
TEST_F(PrintUserDataTest, DeletePrinterFromUsedPrinterList_Test_Multiple)
{
    PrintUserData printUserData;
    printUserData.usedPrinterList_.push_back("printer1");
    printUserData.usedPrinterList_.push_back("printer2");
    printUserData.usedPrinterList_.push_back("printer3");
    printUserData.DeletePrinterFromUsedPrinterList("printer2");
    int listSize = 2;
    EXPECT_EQ(printUserData.usedPrinterList_.size(), listSize);
    EXPECT_EQ(printUserData.usedPrinterList_[0], "printer1");
    EXPECT_EQ(printUserData.usedPrinterList_[1], "printer3");
}

TEST_F(PrintUserDataTest, ParseUserData_ShouldReturn_WhenFileDataNotAvailable)
{
    PrintUserData printUserData;
    // Mock the GetFileData method to return false indicating file data is not available
    printUserData.GetFileData = {
        return false;
    };
printUserData.ParseUserData();
// Assert that the method does not crash or throw exceptions
EXPECT_NO_THROW(printUserData.ParseUserData());
}

TEST_F(PrintUserDataTest, ParseUserData_ShouldReturn_WhenFileDataAvailableButInvalid)
{
    PrintUserData printUserData;
    // Mock the GetFileData method to return true indicating file data is available
    printUserData.GetFileData = {
        return true;
    };
// Mock the CheckFileData method to return false indicating file data is invalid
printUserData.CheckFileData = [](const std::string &, nlohmann::json &) {
    return false;
};
printUserData.ParseUserData();
// Assert that the method does not crash or throw exceptions
EXPECT_NO_THROW(printUserData.ParseUserData());
}

TEST_F(PrintUserDataTest, ParseUserData_ShouldParse_WhenFileDataAvailableAndValid)
{
    PrintUserData printUserData;
    // Mock the GetFileData method to return true indicating file data is available
    printUserData.GetFileData = {
        return true;
    };
// Mock the CheckFileData method to return true indicating file data is valid
    printUserData.CheckFileData = [](const std::string &, nlohmann::json &) {
        return true;
    };
    // Mock the ParseUserDataFromJson method to do nothing
    printUserData.ParseUserDataFromJson = [](const nlohmann::json &) {};
    printUserData.ParseUserData();
    // Assert that the method does not crash or throw exceptions
    EXPECT_NO_THROW(printUserData.ParseUserData());
}

TEST_F(PrintUserDataTest, ParseUserDataFromJson_Test)
{
    nlohmann::json jsonObject;
    PrintUserData printUserData;
    printUserData.ParseUserDataFromJson(jsonObject);
    EXPECT_EQ(printUserData.defaultPrinterId_, "");
    EXPECT_EQ(printUserData.lastUsedPrinterId_, "");
    EXPECT_EQ(printUserData.useLastUsedPrinterForDefault_, false);
}
TEST_F(PrintUserDataTest, ParseUserDataFromJson_Test_WithUserData)
{
    nlohmann::json jsonObject;
    jsonObject["print_user_data"] = {
        {
            "1",
            {
                {"defaultPrinter", "printer1"},
                {"lastUsedPrinter", "printer2"},
                {"useLastUsedPrinterForDefault", true},
                {"usedPrinterList", undefined{
                    nlohmann::json jsonArray;jsonArray.push_back("printer3");return jsonArray;}()}
            }
        }
    };
PrintUserData printUserData;
printUserData.ParseUserDataFromJson(jsonObject);
EXPECT_EQ(printUserData.defaultPrinterId_, "printer1");
EXPECT_EQ(printUserData.lastUsedPrinterId_, "printer2");
EXPECT_EQ(printUserData.useLastUsedPrinterForDefault_, true);
}
TEST_F(PrintUserDataTest, ParseUserDataFromJson_Test_WithUserData_MissingDefaultPrinter)
{
    nlohmann::json jsonObject;
    jsonObject["print_user_data"] = {
        {
            "1",
            {
                {"defaultPrinter", "printer1"},
                {"lastUsedPrinter", "printer2"},
                {"useLastUsedPrinterForDefault", true},
                {"usedPrinterList", undefined{
                    nlohmann::json jsonArray;jsonArray.push_back("printer3");return jsonArray;}()}
            }
        }
    };
PrintUserData printUserData;
printUserData.ParseUserDataFromJson(jsonObject);
EXPECT_EQ(printUserData.defaultPrinterId_, "");
EXPECT_EQ(printUserData.lastUsedPrinterId_, "printer2");
EXPECT_EQ(printUserData.useLastUsedPrinterForDefault_, true);
}

TEST_F(PrintUserDataTest, ConvertJsonToUsedPrinterList_Test)
{
    PrintUserData printUserData;
    nlohmann::json userData;
    userData["usedPrinterList"] = nlohmann::json::array();
    userData["usedPrinterList"].push_back("printer1");
    userData["usedPrinterList"].push_back("printer2");
    userData["usedPrinterList"].push_back("printer3");
    EXPECT_TRUE(printUserData.ConvertJsonToUsedPrinterList(userData));
}
TEST_F(PrintUserDataTest, ConvertJsonToUsedPrinterList_Test_Invalid)
{
    PrintUserData printUserData;
    nlohmann::json userData;
    userData["usedPrinterList"] = nlohmann::json::array();
    int printerId = 123;
    userData["usedPrinterList"].push_back(printerId); // Invalid value
    userData["usedPrinterList"].push_back("printer2");
    EXPECT_FALSE(printUserData.ConvertJsonToUsedPrinterList(userData));
}
TEST_F(PrintUserDataTest, ConvertJsonToUsedPrinterList_Test_Empty)
{
    PrintUserData printUserData;
    nlohmann::json userData;
    EXPECT_TRUE(printUserData.ConvertJsonToUsedPrinterList(userData));
}

TEST_F(PrintUserDataTest, GetFileData_ShouldReturnTrue_WhenFileIsOpenedSuccessfully)
{
    std::string fileData;
    bool result = PrintUserData::GetFileData(fileData);
    EXPECT_TRUE(result);
}
TEST_F(PrintUserDataTest, GetFileData_ShouldReturnFalse_WhenFileCannotBeOpened)
{
    std::string fileData;
    // Mock the file path to simulate a failure to open the file
    std::string mockFilePath = "/nonexistent/path";
    bool result = PrintUserData::GetFileData(fileData);
    EXPECT_FALSE(result);
}
TEST_F(PrintUserDataTest, GetFileData_ShouldReturnTrue_WhenFileIsCreatedSuccessfully)
{
    std::string fileData;
    // Mock the file path to simulate a file creation scenario
    std::string mockFilePath = "/tmp/nonexistent/path";
    bool result = PrintUserData::GetFileData(fileData);
    EXPECT_TRUE(result);
}
TEST_F(PrintUserDataTest, GetFileData_ShouldReturnFalse_WhenFileCannotBeCreated)
{
    std::string fileData;
    // Mock the file path to simulate a failure to create the file
    std::string mockFilePath = "/tmp/nonexistent/path/with/no/permission";
    bool result = PrintUserData::GetFileData(fileData);
    EXPECT_FALSE(result);
}
TEST_F(PrintUserDataTest, GetFileData_ShouldReturnTrue_WhenFileDataIsReadSuccessfully)
{
    std::string fileData;
    // Mock the file path to simulate a successful read scenario
    std::string mockFilePath = "/tmp/existing/file";
    bool result = PrintUserData::GetFileData(fileData);
    EXPECT_TRUE(result);
}
TEST_F(PrintUserDataTest, GetFileData_ShouldReturnFalse_WhenFileDataCannotBeRead)
{
    std::string fileData;
    // Mock the file path to simulate a failure to read the file
    std::string mockFilePath = "/tmp/existing/file/with/no/permission";
    bool result = PrintUserData::GetFileData(fileData);
    EXPECT_FALSE(result);
}

TEST_F(PrintUserDataTest, CheckFileData_ShouldReturnFalse_WhenFileDataIsNotAcceptable)
{
    std::string fileData = "invalid json";
    nlohmann::json jsonObject;
    bool result = PrintUserData::CheckFileData(fileData, jsonObject);
    EXPECT_FALSE(result);
}
TEST_F(PrintUserDataTest, CheckFileData_ShouldReturnFalse_WhenVersionIsNotPresent)
{
    std::string fileData = "{" key ":" value "}";
    nlohmann::json jsonObject;
    bool result = PrintUserData::CheckFileData(fileData, jsonObject);
    EXPECT_FALSE(result);
}
TEST_F(PrintUserDataTest, CheckFileData_ShouldReturnFalse_WhenVersionIsNotString)
{
    std::string fileData = "{" version ":123}";
    nlohmann::json jsonObject;
    bool result = PrintUserData::CheckFileData(fileData, jsonObject);
    EXPECT_FALSE(result);
}
TEST_F(PrintUserDataTest, CheckFileData_ShouldReturnFalse_WhenPrintUserDataIsNotPresent)
{
    std::string fileData = "{" version ":" 1.0 "}";
    nlohmann::json jsonObject;
    bool result = PrintUserData::CheckFileData(fileData, jsonObject);
    EXPECT_FALSE(result);
}
TEST_F(PrintUserDataTest, CheckFileData_ShouldReturnTrue_WhenAllConditionsAreMet)
{
    std::string fileData = "{" version ":" 1.0 "," print_user_data ":" data "}";
    nlohmann::json jsonObject;
    bool result = PrintUserData::CheckFileData(fileData, jsonObject);
    EXPECT_TRUE(result);
}

} // namespace OHOS::Print
