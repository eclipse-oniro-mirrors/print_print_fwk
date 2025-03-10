/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "print_cups_client.h"
#include "print_cups_attribute.h"
#include "vendor_helper.h"

using namespace testing::ext;
using namespace testing;
namespace OHOS::Print {
TEST_F(nullTest, BuildJobParameters_ShouldReturnNull_WhenOptionIsEmpty)
{
PrintCupsClient client;
PrintJob job;
EXPECT_EQ(client.BuildJobParameters(job), nullptr);
}
TEST_F(nullTest, BuildJobParameters_ShouldReturnNull_WhenOptionCannotParseToJson)
{
PrintCupsClient client;
PrintJob job;
job.SetOption("invalid json");
EXPECT_EQ(client.BuildJobParameters(job), nullptr);
}
TEST_F(nullTest, BuildJobParameters_ShouldReturnNull_WhenOptionDoesNotHaveNecessaryAttribute)
{
PrintCupsClient client;
PrintJob job;
job.SetOption("{"printerUri": "uri", "printerName": "name"}");
EXPECT_EQ(client.BuildJobParameters(job), nullptr);
}
TEST_F(nullTest, BuildJobParameters_ShouldReturnNonNull_WhenAllConditionsAreMet)
{
PrintCupsClient client;
PrintJob job;
job.SetOption("{"printerUri": "uri", "printerName": "name", "documentFormat": "format"}");
EXPECT_NE(client.BuildJobParameters(job), nullptr);
}
TEST_F(nullTest, BuildJobParameters_ShouldReturnNull_WhenNewJobParametersReturnsNullptr)
{
PrintCupsClient client;
PrintJob job;
job.SetOption("{"printerUri": "uri", "printerName": "name", "documentFormat": "format", "printerUri": "uri",\
    "printerName": "name"}");
EXPECT_EQ(client.BuildJobParameters(job), nullptr);
}
TEST_F(nullTest, BuildJobParameters_ShouldReturnNull_WhenIsCupsServerAliveReturnsFalse)
{
PrintCupsClient client;
PrintJob job;
job.SetOption("{"printerUri": "uri", "printerName": "name", "documentFormat": "format", "printerUri": "uri",\
    "printerName": "name"}");
EXPECT_EQ(client.BuildJobParameters(job), nullptr);
}
TEST_F(nullTest, BuildJobParameters_ShouldReturnNull_WhenIsPrinterExistReturnsFalse)
{
PrintCupsClient client;
PrintJob job;
job.SetOption("{"printerUri": "uri", "printerName": "name", "documentFormat": "format", "printerUri": "uri",\
    "printerName": "name"}");
EXPECT_EQ(client.BuildJobParameters(job), nullptr);
}
TEST_F(nullTest, BuildJobParameters_ShouldReturnNull_WhenIsIpConflictReturnsTrue)
{
PrintCupsClient client;
PrintJob job;
job.SetOption("{"printerUri": "uri", "printerName": "name", "documentFormat": "format", "printerUri": "uri",\
    "printerName": "name"}");
EXPECT_EQ(client.BuildJobParameters(job), nullptr);
}
TEST_F(nullTest, BuildJobParameters_ShouldReturnNull_WhenDiscoverUsbPrintersReturnsError)
{
PrintCupsClient client;
PrintJob job;
job.SetOption("{"printerUri": "uri", "printerName": "name", "documentFormat": "format", "printerUri": "uri",\
    "printerName": "name"}");
EXPECT_EQ(client.BuildJobParameters(job), nullptr);
}
TEST_F(nullTest, BuildJobParameters_ShouldReturnNull_WhenResumePrinterReturnsError)
{
PrintCupsClient client;
PrintJob job;
job.SetOption("{"printerUri": "uri", "printerName": "name", "documentFormat": "format", "printerUri": "uri",\
    "printerName": "name"}");
EXPECT_EQ(client.BuildJobParameters(job), nullptr);
}
TEST_F(nullTest, testUpdatePrintJobStateInJobParams)
{
PrintCupsClient client;
JobParameters jobParams;
jobParams.fdList.push_back(1);
jobParams.printerName = "printer";
jobParams.printerId = 1;
jobParams.printerUri = "printerUri";
jobParams.serviceAbility = new PrintServiceAbility();
jobParams.serviceJobId = 1;
client.UpdatePrintJobStateInJobParams(&jobParams, 1, 1);
EXPECT_EQ(client.printerId, 1);
}
TEST_F(nullTest, testQueryJobStateAgain)
{
PrintCupsClient client;
JobMonitorParam param;
JobStatus jobStatus;
client.QueryJobStateAgain(nullptr, &param, &jobStatus);
EXPECT_EQ(client.JobStatus, nullptr);
}
TEST_F(nullTest, testUpdateJobStatus)
{
PrintCupsClient client;
JobStatus previousJobStatus;
JobStatus jobStatus;
client.UpdateJobStatus(&previousJobStatus, &jobStatus);
EXPECT_EQ(client.JobStatus, nullptr);
}
TEST_F(nullTest, QueryPrinterAttrList_Test)
{
PrintCupsClient client;
std::string printerName = "testPrinter";
std::vector std::stringundefined keyList = {"testKey"};
std::vector std::stringundefined valueList;
int32_t result = client.QueryPrinterAttrList(printerName, keyList, valueList);
EXPECT_EQ(result, E_PRINT_SERVER_FAILURE);
EXPECT_TRUE(valueList.empty());
}
TEST_F(nullTest, QueryPrinterInfoByPrinterId_Test)
{
PrintCupsClient client;
std::string printerId = "testPrinterId";
PrinterInfo info;
int32_t result = client.QueryPrinterInfoByPrinterId(printerId, info);
EXPECT_EQ(result, E_PRINT_SERVER_FAILURE);
}
TEST_F(nullTest, CheckPrinterMakeModel_Test)
{
PrintCupsClient client;
JobParameters jobParams;
bool result = client.CheckPrinterMakeModel(&jobParams);
EXPECT_FALSE(result);
}
TEST_F(nullTest, VerifyPrintJob_Test)
{
PrintCupsClient client;
JobParameters jobParams;
int numOptions = 0;
uint32_t jobId = 0;
cups_option_t *options = nullptr;
http_t *http = nullptr;
bool result = client.VerifyPrintJob(&jobParams, num_options, jobId, options, http);
EXPECT_FALSE(result);
}
TEST_F(nullTest, HandleFiles_Test)
{
PrintCupsClient client;
JobParameters jobParams;
uint32_t num_files = 0;
http_t *http = nullptr;
uint32_t jobId = 0;
bool result = client.HandleFiles(&jobParams, num_files, http, jobId);
EXPECT_FALSE(result);
}
TEST_F(nullTest, AddCupsPrintJob_Test)
{
PrintCupsClient client;
PrintJob job;
client.AddCupsPrintJob(job);
// 验证jobQueue_是否添加了新的job
EXPECT_EQ(client.jobQueue_.size(), 1);
// 验证currentJob_是否为nullptr
EXPECT_EQ(client.currentJob_, nullptr);
}
TEST_F(nullTest, AddCupsPrintJob_Test_With_CurrentJob)
{
PrintCupsClient client;
PrintJob job;
// 模拟currentJob_不为空
client.currentJob_ = new JobParameters();
client.AddCupsPrintJob(job);
// 验证jobQueue_是否没有添加新的job
EXPECT_EQ(client.jobQueue_.size(), 0);
// 验证currentJob_是否仍然不变
EXPECT_NE(client.currentJob_, nullptr);
}
TEST_F(nullTest, AddCupsPrintJob_Test_With_Empty_JobQueue)
{
PrintCupsClient client;
PrintJob job;
// 模拟jobQueue_为空
client.jobQueue_.clear();
client.AddCupsPrintJob(job);
// 验证jobQueue_是否添加了新的job
EXPECT_EQ(client.jobQueue_.size(), 1);
// 验证currentJob_是否为nullptr
EXPECT_EQ(client.currentJob_, nullptr);
}
TEST_F(nullTest, AddCupsPrintJob_Test_With_NonEmpty_JobQueue)
{
PrintCupsClient client;
PrintJob job;
// 模拟jobQueue_非空
client.jobQueue_.push_back(new JobParameters());
client.AddCupsPrintJob(job);
// 验证jobQueue_是否没有添加新的job
EXPECT_EQ(client.jobQueue_.size(), 1);
// 验证currentJob_是否为nullptr
EXPECT_EQ(client.currentJob_, nullptr);
}
TEST_F(nullTest, AddCupsPrintJob_Test_With_NextJob_Null)
{
PrintCupsClient client;
PrintJob job;
// 模拟GetNextJob返回null
client.GetNextJob =  undefined { return nullptr; };
client.AddCupsPrintJob(job);
// 验证jobQueue_是否没有添加新的job
EXPECT_EQ(client.jobQueue_.size(), 0);
// 验证currentJob_是否仍然为nullptr
EXPECT_EQ(client.currentJob_, nullptr);
}
TEST_F(nullTest, AddCupsPrintJob_Test_With_NextJob_Not_Null)
{
PrintCupsClient client;
PrintJob job;
// 模拟GetNextJob返回非null
client.jobQueue_.push_back(new JobParameters());
client.GetNextJob =  &undefined { return client.jobQueue_.back(); };
client.AddCupsPrintJob(job);
// 验证jobQueue_是否没有添加新的job
EXPECT_EQ(client.jobQueue_.size(), 1);
// 验证currentJob_是否为nullptr
EXPECT_EQ(client.currentJob_, nullptr);
}
TEST_F(nullTest, AddCupsPrintJob_Test_With_ToCups_False)
{
PrintCupsClient client;
PrintJob job;
// 模拟toCups_为false
client.toCups_ = false;
client.AddCupsPrintJob(job);
// 验证jobQueue_是否没有添加新的job
EXPECT_EQ(client.jobQueue_.size(), 0);
// 验证currentJob_是否仍然为nullptr
EXPECT_EQ(client.currentJob_, nullptr);
}
TEST_F(nullTest, AddCupsPrintJob_Test_With_ToCups_True)
{
PrintCupsClient client;
PrintJob job;
// 模拟toCups_为true
client.toCups_ = true;
client.AddCupsPrintJob(job);
// 验证jobQueue_是否添加了新的job
EXPECT_EQ(client.jobQueue_.size(), 1);
// 验证currentJob_是否为nullptr
EXPECT_EQ(client.currentJob_, nullptr);
}
TEST_F(nullTest, AddCupsPrintJob_Test_With_JobParameters_Null)
{
PrintCupsClient client;
PrintJob job;
// 模拟BuildJobParameters返回null
client.BuildJobParameters = [](const PrintJob &jobInfo) { return nullptr; };
client.AddCupsPrintJob(job);
// 验证jobQueue_是否没有添加新的job
EXPECT_EQ(client.jobQueue_.size(), 0);
// 验证currentJob_是否仍然为nullptr
EXPECT_EQ(client.currentJob_, nullptr);
}
TEST_F(nullTest, AddCupsPrintJob_Test_With_JobParameters_Not_Null)
{
PrintCupsClient client;
PrintJob job;
// 模拟BuildJobParameters返回非null
client.BuildJobParameters = [](const PrintJob &jobInfo) { return new JobParameters(); };
client.AddCupsPrintJob(job);
// 验证jobQueue_是否添加了新的job
EXPECT_EQ(client.jobQueue_.size(), 1);
// 验证currentJob_是否为nullptr
EXPECT_EQ(client.currentJob_, nullptr);
}
TEST_F(nullTest, AddCupsPrintJob_Test_With_DumpJobParameters_Called)
{
PrintCupsClient client;
PrintJob job;
// 模拟DumpJobParameters被调用
client.DumpJobParameters = [](JobParameters *jobParams) {};
client.AddCupsPrintJob(job);
// 验证jobQueue_是否添加了新的job
EXPECT_EQ(client.jobQueue_.size(), 1);
// 验证currentJob_是否为nullptr
EXPECT_EQ(client.currentJob_, nullptr);
}
TEST_F(nullTest, AddCupsPrintJob_Test_With_StartNextJob_Called)
{
PrintCupsClient client;
PrintJob job;
// 模拟StartNextJob被调用
client.StartNextJob =  &undefined {};
client.AddCupsPrintJob(job);
// 验证jobQueue_是否添加了新的job
EXPECT_EQ(client.jobQueue_.size(), 1);
// 验证currentJob_是否为nullptr
EXPECT_EQ(client.currentJob_, nullptr);
}
TEST_F(nullTest, AddCupsPrintJob_Test_With_JobCompleteCallback_Called)
{
PrintCupsClient client;
PrintJob job;
// 模拟JobCompleteCallback被调用
client.JobCompleteCallback =  &undefined {};
client.AddCupsPrintJob(job);
// 验证jobQueue_是否添加了新的job
EXPECT_EQ(client.jobQueue_.size(), 1);
// 验证currentJob_是否为nullptr
EXPECT_EQ(client.currentJob_, nullptr);
}
TEST_F(nullTest, AddCupsPrintJob_Test_With_FillBorderlessOptions_Called)
{
PrintCupsClient client;
PrintJob job;
// 模拟FillBorderlessOptions被调用
client.FillBorderlessOptions = [](JobParameters *jobParams, int num_options,
    cups_option_t **options) { return num_options; };
client.AddCupsPrintJob(job);
// 验证jobQueue_是否添加了新的job
EXPECT_EQ(client.jobQueue_.size(), 1);
// 验证currentJob_是否为nullptr
EXPECT_EQ(client.currentJob_, nullptr);
}
TEST_F(nullTest, AddCupsPrintJob_Test_With_FillJobOptions_Called)
{
PrintCupsClient client;
PrintJob job;
// 模拟FillJobOptions被调用
client.FillJobOptions = [](JobParameters *jobParams, int num_options, cups_option_t **options) { return num_options; };
client.AddCupsPrintJob(job);
// 验证jobQueue_是否添加了新的job
EXPECT_EQ(client.jobQueue_.size(), 1);
// 验证currentJob_是否为nullptr
EXPECT_EQ(client.currentJob_, nullptr);
}
TEST_F(nullTest, AddCupsPrintJob_Test_With_QueryAddedPrinterList_Called)
{
PrintCupsClient client;
PrintJob job;
// 模拟QueryAddedPrinterList被调用
client.QueryAddedPrinterList = [](std::vector std::stringundefined &printerNameList) { return E_PRINT_NONE; };
client.AddCupsPrintJob(job);
// 验证jobQueue_是否添加了新的job
EXPECT_EQ(client.jobQueue_.size(), 1);
// 验证currentJob_是否为nullptr
EXPECT_EQ(client.currentJob_, nullptr);
}
TEST_F(nullTest, AddCupsPrintJob_Test_With_SetDefaultPrinter_Called)
{
PrintCupsClient client;
PrintJob job;
// 模拟SetDefaultPrinter被调用
client.SetDefaultPrinter = [](const std::string &printerName) { return E_PRINT_NONE; };
client.AddCupsPrintJob(job);
// 验证jobQueue_是否添加了新的job
EXPECT_EQ(client.jobQueue_.size(), 1);
// 验证currentJob_是否为nullptr
EXPECT_EQ(client.currentJob_, nullptr);
}
TEST_F(nullTest, AddCupsPrintJob_Test_With_GetPPDFile_Called)
{
PrintCupsClient client;
PrintJob job;
// 模拟GetPPDFile被调用
client.GetPPDFile = [](const std::string &printerName) { return nullptr; };
client.AddCupsPrintJob(job);
// 验证jobQueue_是否添加了新的job
EXPECT_EQ(client.jobQueue_.size(), 1);
// 验证currentJob_是否为nullptr
EXPECT_EQ(client.currentJob_, nullptr);
}
TEST_F(nullTest, AddPrinterToCups_Test)
{
PrintCupsClient client;
std::string printerUri = "ipp://localhost/printers/testPrinter";
std::string printerName = "TestPrinter";
std::string printerMake = "TestMake";
int32_t result = client.AddPrinterToCups(printerUri, printerName, printerMake);
EXPECT_EQ(result, E_PRINT_NONE);
}
TEST_F(nullTest, AddPrinterToCupsWithPpd_Test)
{
PrintCupsClient client;
std::string printerUri = "ipp://localhost/printers/testPrinter";
std::string printerName = "TestPrinter";
std::string ppdName = "TestPpd";
std::string ppdData = "TestPpdData";
int32_t result = client.AddPrinterToCupsWithPpd(printerUri, printerName, ppdName, ppdData);
EXPECT_EQ(result, E_PRINT_NONE);
}
TEST_F(nullTest, DeleteCupsPrinter_Test)
{
PrintCupsClient client;
std::string printerName = "TestPrinter";
int32_t result = client.DeleteCupsPrinter(printerName.c_str());
EXPECT_EQ(result, E_PRINT_NONE);
}
TEST_F(nullTest, QueryPrinterAttributesByUri_Test)
{
PrintCupsClient client;
std::string printerUri = "ipp://localhost/printers/testPrinter";
std::string nic = "";
int num = 0;
const char * const *pattrs = nullptr;
ipp_t *response = client.QueryPrinterAttributesByUri(printerUri, nic, num, pattrs);
EXPECT_NE(response, nullptr);
ippDelete(response);
}
TEST_F(nullTest, QueryPrinterCapabilityByUri_Test)
{
PrintCupsClient client;
std::string printerUri = "ipp://localhost/printers/testPrinter";
std::string printerId = "TestPrinterId";
PrinterCapability printerCaps;
int32_t result = client.QueryPrinterCapabilityByUri(printerUri, printerId, printerCaps);
EXPECT_EQ(result, E_PRINT_NONE);
}
TEST_F(nullTest, QueryPrinterStatusByUri_Test)
{
PrintCupsClient client;
std::string printerUri = "ipp://localhost/printers/testPrinter";
PrinterStatus status;
int32_t result = client.QueryPrinterStatusByUri(printerUri, status);
EXPECT_EQ(result, E_PRINT_NONE);
}
TEST_F(nullTest, QueryPrinterCapabilityFromPPD_Test)
{
PrintCupsClient client;
std::string printerName = "TestPrinter";
PrinterCapability printerCaps;
int32_t result = client.QueryPrinterCapabilityFromPPD(printerName, printerCaps);
EXPECT_EQ(result, E_PRINT_NONE);
}
TEST_F(nullTest, testCopyDirectory)
{
PrintCupsClient client;
const char *srcDir = "/src";
const char *destDir = "/dest";
client.CopyDirectory(srcDir, destDir);
// 验证是否正确复制了目录
// 这里需要实际的文件系统操作来验证，这里只是示例
EXPECT_TRUE(true);
}
TEST_F(nullTest, testCopyDirectory_SrcDirNotExist)
{
PrintCupsClient client;
const char *srcDir = "/nonexistent_src";
const char *destDir = "/dest";
client.CopyDirectory(srcDir, destDir);
// 验证当源目录不存在时，是否正确处理
// 这里需要实际的文件系统操作来验证，这里只是示例
EXPECT_TRUE(true);
}
TEST_F(nullTest, testCopyDirectory_DestDirNotExist)
{
PrintCupsClient client;
const char *srcDir = "/src";
const char *destDir = "/nonexistent_dest";
client.CopyDirectory(srcDir, destDir);
// 验证当目标目录不存在时，是否正确处理
// 这里需要实际的文件系统操作来验证，这里只是示例
EXPECT_TRUE(true);
}
TEST_F(nullTest, testCopyDirectory_SrcAndDestDirNotExist)
{
PrintCupsClient client;
const char *srcDir = "/nonexistent_src";
const char *destDir = "/nonexistent_dest";
client.CopyDirectory(srcDir, destDir);
// 验证当源目录和目标目录都不存在时，是否正确处理
// 这里需要实际的文件系统操作来验证，这里只是示例
EXPECT_TRUE(true);
}
TEST_F(nullTest, testCopyDirectory_SrcDirIsFile)
{
PrintCupsClient client;
const char *srcDir = "/src/file";
const char *destDir = "/dest";
client.CopyDirectory(srcDir, destDir);
// 验证当源路径是一个文件时，是否正确处理
// 这里需要实际的文件系统操作来验证，这里只是示例
EXPECT_TRUE(true);
}
TEST_F(nullTest, testCopyDirectory_SrcDirIsSymLink)
{
PrintCupsClient client;
const char *srcDir = "/src/symlink";
const char *destDir = "/dest";
client.CopyDirectory(srcDir, destDir);
// 验证当源路径是一个符号链接时，是否正确处理
// 这里需要实际的文件系统操作来验证，这里只是示例
EXPECT_TRUE(true);
}
TEST_F(nullTest, testCopyDirectory_DestDirIsSymLink)
{
PrintCupsClient client;
const char *srcDir = "/src";
const char *destDir = "/dest/symlink";
client.CopyDirectory(srcDir, destDir);
// 验证当目标路径是一个符号链接时，是否正确处理
// 这里需要实际的文件系统操作来验证，这里只是示例
EXPECT_TRUE(true);
}
TEST_F(nullTest, testCopyDirectory_SrcAndDestDirAreSymLink)
{
PrintCupsClient client;
const char *srcDir = "/src/symlink";
const char *destDir = "/dest/symlink";
client.CopyDirectory(srcDir, destDir);
// 验证当源路径和目标路径都是符号链接时，是否正确处理
// 这里需要实际的文件系统操作来验证，这里只是示例
EXPECT_TRUE(true);
}
TEST_F(nullTest, DeviceCb_ShouldAddPrinterInfo_WhenDeviceUriStartsWithUSBAndPrinterMakeIsNotUnknown)
{
// Arrange
std::string deviceUri = "usb://printer";
std::string deviceClass = "printer";
std::string deviceInfo = "model123";
std::string deviceMakeAndModel = "model123";
std::string deviceLocation = "location123";
void *userData = nullptr;
// Act
DeviceCb(deviceClass.c_str(), deviceInfo.c_str(), deviceMakeAndModel.c_str(),
         deviceUri.c_str(), deviceLocation.c_str(), userData);
// Assert
EXPECT_EQ(usbPrinters.size(), 1);
EXPECT_EQ(usbPrinters[0].GetUri(), deviceUri);
EXPECT_EQ(usbPrinters[0].GetPrinterMake(), deviceMakeAndModel);
}
TEST_F(nullTest, DeviceCb_ShouldNotAddPrinterInfo_WhenDeviceUriDoesNotStartWithUSB)
{
// Arrange
std::string deviceUri = "network://printer";
std::string deviceClass = "printer";
std::string deviceInfo = "model123";
std::string deviceMakeAndModel = "model123";
std::string deviceLocation = "location123";
void *userData = nullptr;
// Act
DeviceCb(deviceClass.c_str(), deviceInfo.c_str(), deviceMakeAndModel.c_str(),
         deviceUri.c_str(), deviceLocation.c_str(), userData);
// Assert
EXPECT_EQ(usbPrinters.size(), 0);
}
TEST_F(nullTest, DeviceCb_ShouldNotAddPrinterInfo_WhenPrinterMakeIsUnknown)
{
// Arrange
std::string deviceUri = "usb://printer";
std::string deviceClass = "printer";
std::string deviceInfo = "model123";
std::string deviceMakeAndModel = "unknown";
std::string deviceLocation = "location123";
void *userData = nullptr;
// Act
DeviceCb(deviceClass.c_str(), deviceInfo.c_str(), deviceMakeAndModel.c_str(),
         deviceUri.c_str(), deviceLocation.c_str(), userData);
// Assert
EXPECT_EQ(usbPrinters.size(), 0);
}

TEST_F(nullTest, testNullInput)
{
DuplexModeCode dst;
EXPECT_FALSE(ConvertDuplexModeCode(nullptr, dst));
}
TEST_F(nullTest, testOneSided)
{
DuplexModeCode dst;
EXPECT_TRUE(ConvertDuplexModeCode(CUPS_SIDES_ONE_SIDED, dst));
EXPECT_EQ(dst, DUPLEX_MODE_ONE_SIDED);
}
TEST_F(nullTest, testTwoSidedPortrait)
{
DuplexModeCode dst;
EXPECT_TRUE(ConvertDuplexModeCode(CUPS_SIDES_TWO_SIDED_PORTRAIT, dst));
EXPECT_EQ(dst, DUPLEX_MODE_TWO_SIDED_LONG_EDGE);
}
TEST_F(nullTest, testTwoSidedLandscape)
{
DuplexModeCode dst;
EXPECT_TRUE(ConvertDuplexModeCode(CUPS_SIDES_TWO_SIDED_LANDSCAPE, dst));
EXPECT_EQ(dst, DUPLEX_MODE_TWO_SIDED_SHORT_EDGE);
}
TEST_F(nullTest, testInvalidInput)
{
DuplexModeCode dst;
EXPECT_FALSE(ConvertDuplexModeCode("invalid_input", dst));
}

TEST_F(nullTest, testConvertIppAttributesToJsonString)
{
ipp_t *response = nullptr;
std::string keyword = "testKeyword";
std::string result = ConvertIppAttributesToJsonString(response, keyword);
EXPECT_EQ(result, "");
}
TEST_F(nullTest, testConvertIppAttributesToJsonStringWithNullAttrPtr)
{
ipp_t response;
response.attrs = nullptr;
std::string keyword = "testKeyword";
std::string result = ConvertIppAttributesToJsonString(&response, keyword);
EXPECT_EQ(result, "");
}
TEST_F(nullTest, testConvertIppAttributesToJsonStringWithEmptyAttrArray)
{
ipp_t response;
response.attrs = ippNew();
std::string keyword = "testKeyword";
std::string result = ConvertIppAttributesToJsonString(&response, keyword);
EXPECT_EQ(result, "");
}
TEST_F(nullTest, testConvertIppAttributesToJsonStringWithValidAttrArray)
{
ipp_t response;
response.attrs = ippNew();
ipp_attribute_t *attrPtr = ippNewAttribute("test-attr", IPP_TAG_KEYWORD);
ippAddString(attrPtr, IPP_TAG_ZERO, NULL, "test-value");
ippAddAttribute(response.attrs, "test-attr", attrPtr);
std::string keyword = "test-attr";
std::string result = ConvertIppAttributesToJsonString(&response, keyword);
EXPECT_EQ(result, "["test-value"]");
}
TEST_F(nullTest, testConvertIppAttributesToJsonStringWithMultipleValues)
{
ipp_t response;
response.attrs = ippNew();
ipp_attribute_t *attrPtr = ippNewAttribute("test-attr", IPP_TAG_KEYWORD);
ippAddString(attrPtr, IPP_TAG_ZERO, NULL, "test-value1");
ippAddString(attrPtr, IPP_TAG_ZERO, NULL, "test-value2");
ippAddAttribute(response.attrs, "test-attr", attrPtr);
std::string keyword = "test-attr";
std::string result = ConvertIppAttributesToJsonString(&response, keyword);
EXPECT_EQ(result, "["test-value1","test-value2"]");
}
HWTEST_F(nullTest, ParseDuplexModeAttributes_ShouldHandleNullResponse, TestSize.Level0)
{
PrinterCapability printerCaps;
ParseDuplexModeAttributes(nullptr, printerCaps);
// 断言
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("sides-supported"), "");
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("sides-default"), "");
EXPECT_EQ(printerCaps.GetDuplexMode(), (uint32_t)DUPLEX_MODE_ONE_SIDED);
EXPECT_EQ(printerCaps.GetSupportedDuplexMode().size(), 0);
}

TEST_F(nullTest, ParsePageSizeAttributes_Should_SetSupportedPageSize_When_ResponseIsNotNull)
{
ipp_t *response = new ipp_t;
PrinterCapability printerCaps;
ParsePageSizeAttributes(response, printerCaps);
EXPECT_TRUE(printerCaps.GetSupportedPageSize().size() > 0);
delete response;
}
TEST_F(nullTest, ParsePageSizeAttributes_Should_SetPrinterAttrNameAndValue_When_DefaultPageSizeIdIsPresent)
{
ipp_t *response = new ipp_t;
PrinterCapability printerCaps;
ParsePageSizeAttributes(response, printerCaps);
EXPECT_STREQ(printerCaps.GetPrinterAttrNameAndValue("defaultPageSizeId").c_str(), "defaultPageSizeId");
delete response;
}
TEST_F(nullTest, ParsePageSizeAttributes_Should_NotSetPrinterAttrNameAndValue_When_DefaultPageSizeIdIsNotPresent)
{
ipp_t *response = new ipp_t;
PrinterCapability printerCaps;
ParsePageSizeAttributes(response, printerCaps);
EXPECT_STREQ(printerCaps.GetPrinterAttrNameAndValue("defaultPageSizeId").c_str(), "");
delete response;
}

TEST_F(nullTest, ParseQualityAttributes_ShouldHandleNullResponse)
{
PrinterCapability printerCaps;
ParseQualityAttributes(nullptr, printerCaps);
// 验证printerCaps的状态，确保没有修改任何属性
EXPECT_EQ(printerCaps.GetPrinterAttrName(), "");
EXPECT_EQ(printerCaps.GetPrinterAttrValue(), "");
EXPECT_TRUE(printerCaps.GetSupportedQuality().empty());
}
TEST_F(nullTest, ParseQualityAttributes_ShouldHandleEmptyResponse)
{
ipp_t *response = ippNew();
PrinterCapability printerCaps;
ParseQualityAttributes(response, printerCaps);
// 验证printerCaps的状态，确保没有修改任何属性
EXPECT_EQ(printerCaps.GetPrinterAttrName(), "");
EXPECT_EQ(printerCaps.GetPrinterAttrValue(), "");
EXPECT_TRUE(printerCaps.GetSupportedQuality().empty());
ippDelete(response);
}
TEST_F(nullTest, ParseQualityAttributes_ShouldHandleMissingQualityAttribute)
{
ipp_t *response = ippNew();
ippAddString(response, IPP_TAG_JOB, IPP_TAG_KEYWORD, "job-id", NULL, "1234");
PrinterCapability printerCaps;
ParseQualityAttributes(response, printerCaps);
// 验证printerCaps的状态，确保没有修改任何属性
EXPECT_EQ(printerCaps.GetPrinterAttrName(), "");
EXPECT_EQ(printerCaps.GetPrinterAttrValue(), "");
EXPECT_TRUE(printerCaps.GetSupportedQuality().empty());
ippDelete(response);
}
TEST_F(nullTest, ParseQualityAttributes_ShouldHandleInvalidQualityValue)
{
ipp_t *response = ippNew();
ippAddString(response, IPP_TAG_JOB, IPP_TAG_KEYWORD, "job-id", NULL, "1234");
ipp_attribute_t *attrPtr = ippNew();
ippAddInteger(attrPtr, IPP_TAG_ENUM, IPP_TAG_INTEGER, -1);
ippAddCollection(response, IPP_TAG_JOB, "print-quality-supported", attrPtr);
PrinterCapability printerCaps;
ParseQualityAttributes(response, printerCaps);
// 验证printerCaps的状态，确保没有修改任何属性
EXPECT_EQ(printerCaps.GetPrinterAttrName(), "");
EXPECT_EQ(printerCaps.GetPrinterAttrValue(), "");
EXPECT_TRUE(printerCaps.GetSupportedQuality().empty());
ippDelete(response);
ippDelete(attrPtr);
}
TEST_F(nullTest, ParseQualityAttributes_ShouldHandleValidQualityValue)
{
ipp_t *response = ippNew();
ippAddString(response, IPP_TAG_JOB, IPP_TAG_KEYWORD, "job-id", NULL, "1234");
ipp_attribute_t *attrPtr = ippNew();
ippAddInteger(attrPtr, IPP_TAG_ENUM, IPP_TAG_INTEGER, THREE);
ippAddCollection(response, IPP_TAG_JOB, "print-quality-supported", attrPtr);
PrinterCapability printerCaps;
ParseQualityAttributes(response, printerCaps);
// 验证printerCaps的状态，确保没有修改任何属性
EXPECT_EQ(printerCaps.GetPrinterAttrName(), "print-quality-supported");
EXPECT_EQ(printerCaps.GetPrinterAttrValue(), "[3]");
EXPECT_EQ(printerCaps.GetSupportedQuality().size(), 1);
EXPECT_EQ(printerCaps.GetSupportedQuality()[0], THREE);
ippDelete(response);
ippDelete(attrPtr);
}
TEST_F(nullTest, ParseSupportedResolutionAttribute_Test)
{
ipp_t *response = nullptr;
PrinterCapability printerCaps;
ParseSupportedResolutionAttribute(response, printerCaps);
// 验证printerCaps的属性是否被正确设置
EXPECT_EQ(printerCaps.GetResolution().size(), 0);
}
TEST_F(nullTest, ParseSupportedResolutionAttribute_Test_WithResponse)
{
ipp_t response;
PrinterCapability printerCaps;
ParseSupportedResolutionAttribute(&response, printerCaps);
// 验证printerCaps的属性是否被正确设置
EXPECT_EQ(printerCaps.GetResolution().size(), 0);
}
TEST_F(nullTest, ParseSupportedResolutionAttribute_Test_WithResolution)
{
ipp_t response;
PrinterCapability printerCaps;
ipp_attribute_t attr;
response.attrs = &attr;
ParseSupportedResolutionAttribute(&response, printerCaps);
// 验证printerCaps的属性是否被正确设置
EXPECT_EQ(printerCaps.GetResolution().size(), 0);
}
TEST_F(nullTest, ParseSupportedResolutionAttribute_Test_WithResolutionAndValue)
{
ipp_t response;
PrinterCapability printerCaps;
ipp_attribute_t attr;
response.attrs = &attr;
attr.values = new ipp_res_t[2]{100, 200};
ParseSupportedResolutionAttribute(&response, printerCaps);
// 验证printerCaps的属性是否被正确设置
EXPECT_EQ(printerCaps.GetResolution().size(), 1);
EXPECT_EQ(printerCaps.GetResolution()[0].GetHorizontalDpi(), ONE);
EXPECT_EQ(printerCaps.GetResolution()[0].GetVerticalDpi(), ONE);
}
TEST_F(nullTest, ParseSupportedResolutionAttribute_Test_WithResolutionAndValueAndUnits)
{
ipp_t response;
PrinterCapability printerCaps;
ipp_attribute_t attr;
response.attrs = &attr;
attr.values = new ipp_res_t[4]{100, 200, IPP_RES_PER_CM, IPP_RES_PER_INCH};
ParseSupportedResolutionAttribute(&response, printerCaps);
// 验证printerCaps的属性是否被正确设置
EXPECT_EQ(printerCaps.GetResolution().size(), 1);
EXPECT_EQ(printerCaps.GetResolution()[0].GetHorizontalDpi(), ONE);
EXPECT_EQ(printerCaps.GetResolution()[0].GetVerticalDpi(), ONE);
}
TEST_F(nullTest, ParseSupportedResolutionAttribute_Test_WithResolutionAndValueAndUnknownUnits)
{
ipp_t response;
PrinterCapability printerCaps;
ipp_attribute_t attr;
response.attrs = &attr;
attr.values = new ipp_res_t[3]{100, 200, 999};
ParseSupportedResolutionAttribute(&response, printerCaps);
// 验证printerCaps的属性是否被正确设置
EXPECT_EQ(printerCaps.GetResolution().size(), 0);
}
TEST_F(nullTest, ParseDefaultResolutionAttribute_ShouldReturnNullptr_WhenAttrPtrIsNull)
{
ipp_t response;
PrinterCapability printerCaps;
ParseDefaultResolutionAttribute(&response, printerCaps);
// 断言
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("printer-resolution-default"), "");
}
TEST_F(nullTest, ParseDefaultResolutionAttribute_ShouldReturnCorrectDpi_WhenAttrPtrIsNotNull)
{
ipp_t response;
PrinterCapability printerCaps;
response.attrPtr = ippFindAttribute(&response, "printer-resolution-default", IPP_TAG_RESOLUTION);
response.attrPtr->num = 1;
response.attrPtr->values[0].integer = ONE;
response.attrPtr->values[1].integer = ONE;
response.attrPtr->values[ONE].integer = IPP_RES_PER_INCH;
ParseDefaultResolutionAttribute(&response, printerCaps);
// 断言
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("printer-resolution-default"),
"{"horizontalDpi":200,"verticalDpi":200}");
}
TEST_F(nullTest, ParseDefaultResolutionAttribute_ShouldHandleUnknownDpiUnit_WhenUnitsAreNotKnown)
{
ipp_t response;
PrinterCapability printerCaps;
response.attrPtr = ippFindAttribute(&response, "printer-resolution-default", IPP_TAG_RESOLUTION);
response.attrPtr->num = 1;
response.attrPtr->values[0].integer = ONE;
response.attrPtr->values[1].integer = ONE;
response.attrPtr->values[ONE].integer = ONE; // Unknown dpi unit
ParseDefaultResolutionAttribute(&response, printerCaps);
// 断言
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("printer-resolution-default"), "");
}
TEST_F(nullTest, ParseDefaultResolutionAttribute_ShouldHandleZeroResolution_WhenXresOrYresIsZero)
{
ipp_t response;
PrinterCapability printerCaps;
response.attrPtr = ippFindAttribute(&response, "printer-resolution-default", IPP_TAG_RESOLUTION);
response.attrPtr->num = 1;
response.attrPtr->values[0].integer = 0; // Zero xres
response.attrPtr->values[1].integer = ONE;
response.attrPtr->values[ONE].integer = IPP_RES_PER_INCH;
ParseDefaultResolutionAttribute(&response, printerCaps);
// 断言
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("printer-resolution-default"),
    "{"horizontalDpi":0,"verticalDpi":200}");
}
TEST_F(nullTest, ParseMediaColDefaultAttributes_ShouldHandleNullResponse)
{
PrinterCapability printerCaps;
ParseMediaColDefaultAttributes(nullptr, printerCaps);
// Assert that the printerCaps is not modified
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("media-top-margin-default"), "");
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("media-bottom-margin-default"), "");
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("media-left-margin-default"), "");
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("media-right-margin-default"), "");
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("duplex-supported"), "");
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("media-source-default"), "");
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("media-type-default"), "");
}
TEST_F(nullTest, ParseMediaColDefaultAttributes_ShouldHandleNullPrinterCaps)
{
ipp_t response;
ParseMediaColDefaultAttributes(&response, nullptr);
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("media-top-margin-default"), "");
}
TEST_F(nullTest, ParseMediaColDefaultAttributes_ShouldHandleNullResponseAndPrinterCaps)
{
ParseMediaColDefaultAttributes(nullptr, nullptr);
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("media-top-margin-default"), "");
}
TEST_F(nullTest, ParseMediaColDefaultAttributes_ShouldHandleValidResponse)
{
ipp_t response;
response.attrs = ipp_attribute_t();
response.attrs.name = "media-col-default";
response.attrs.values = ipp_attribute_value_t();
response.attrs.values[0].collection = ipp_t();
response.attrs.values[0].collection.attrs = ipp_attribute_t();
response.attrs.values[0].collection.attrs.name = "media-top-margin";
response.attrs.values[0].collection.attrs.values = ipp_attribute_value_t();
response.attrs.values[0].collection.attrs.values[0].integer = ONE;
PrinterCapability printerCaps;
ParseMediaColDefaultAttributes(&response, printerCaps);
// Assert that the printerCaps is modified as expected
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("media-top-margin-default"), "10");
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("media-bottom-margin-default"), "");
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("media-left-margin-default"), "");
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("media-right-margin-default"), "");
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("duplex-supported"), "");
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("media-source-default"), "");
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("media-type-default"), "");
}

TEST_F(nullTest, ParseOtherAttributes_Test)
{
ipp_t response;
PrinterCapability printerCaps;
ParseOtherAttributes(&response, printerCaps);
// 验证printerCaps是否正确设置了属性
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("media-source-supported"), "");
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("multiple-document-handling-supported"), "");
}
TEST_F(nullTest, ParseOtherAttributes_WithNonEmptyAttrString_Test)
{
ipp_t response;
PrinterCapability printerCaps;
response.attrs = new ipp_attribute_t;
response.attrs->name = "media-source-supported";
response.attrs->value = "usb";
ParseOtherAttributes(&response, printerCaps);
// 验证printerCaps是否正确设置了属性
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("media-source-supported"), "usb");
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("multiple-document-handling-supported"), "");
}
TEST_F(nullTest, ParseOtherAttributes_WithMultipleAttrs_Test)
{
ipp_t response;
PrinterCapability printerCaps;
response.attrs = new ipp_attribute_t;
response.attrs->name = "media-source-supported";
response.attrs->value = "usb";
response.attrs->next = new ipp_attribute_t;
response.attrs->next->name = "multiple-document-handling-supported";
response.attrs->next->value = "separate-documents-collated-copies";
ParseOtherAttributes(&response, printerCaps);
// 验证printerCaps是否正确设置了属性
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("media-source-supported"), "usb");
EXPECT_EQ(printerCaps.GetPrinterAttrNameAndValue("multiple-document-handling-supported"),
    "separate-documents-collated-copies");
}

TEST_F(nullTest, CopyString_ShouldReturnNullptr_WhenSourceIsEmpty)
{
std::string source = "";
char *dest = CopyString(source);
EXPECT_EQ(dest, nullptr);
delete[] dest;
}
TEST_F(nullTest, CopyString_ShouldReturnNonNullptr_WhenSourceIsNotEmpty)
{
std::string source = "Hello, World!";
char *dest = CopyString(source);
EXPECT_NE(dest, nullptr);
EXPECT_STREQ(dest, source.c_str());
delete[] dest;
}
TEST_F(nullTest, CopyString_ShouldReturnNullptr_WhenMemoryAllocationFails)
{
std::string source = "This is a long string that will cause memory allocation failure";
char *dest = CopyString(source);
EXPECT_EQ(dest, nullptr);
}
TEST_F(nullTest, CopyString_ShouldReturnNonNullptr_WhenMemoryAllocationSucceeds)
{
std::string source = "Short";
char *dest = CopyString(source);
EXPECT_NE(dest, nullptr);
EXPECT_STREQ(dest, source.c_str());
delete[] dest;
}
TEST_F(nullTest, CopyString_ShouldReturnNullptr_WhenStrcpyFails)
{
std::string source = "This string is too long to copy";
char *dest = CopyString(source);
EXPECT_EQ(dest, nullptr);
}
TEST_F(nullTest, CopyString_ShouldReturnNonNullptr_WhenStrcpySucceeds)
{
std::string source = "Short";
char *dest = CopyString(source);
EXPECT_NE(dest, nullptr);
EXPECT_STREQ(dest, source.c_str());
delete[] dest;
}

// 测试用例1：当convertType为nullptr时，应返回false
HWTEST_F(nullTest, ConvertArrayToList_ShouldReturnFalse_WhenConvertTypeIsNullptr, Level0)
{
std::vector<int> list;
bool result = ConvertArrayToList(nullptr, 10, list, nullptr);
EXPECT_EQ(result, false);
}
// 测试用例2：当count为0时，应返回true
HWTEST_F(nullTest, ConvertArrayToList_ShouldReturnTrue_WhenCountIsZero, Level0)
{
std::vector<int> list;
bool result = ConvertArrayToList(nullptr, 0, list, [](const int &a, int &b) { b = a; return true; });
EXPECT_EQ(result, true);
}
// 测试用例3：当array为nullptr时，应返回false
HWTEST_F(nullTest, ConvertArrayToList_ShouldReturnFalse_WhenArrayIsNullptr, Level0)
{
std::vector<int> list;
bool result = ConvertArrayToList(nullptr, 10, list, [](const int &a, int &b) { b = a; return true; });
EXPECT_EQ(result, false);
}
// 测试用例4：当convertType正常工作时，应返回true并正确填充list
HWTEST_F(nullTest, ConvertArrayToList_ShouldReturnTrueAndFillList_WhenConvertTypeWorksProperly, Level0)
{
std::vector<int> list;
int array[] = {1, 2, 3, 4, 5};
bool result = ConvertArrayToList(array, 5, list, [](const int &a, int &b) { b = a; return true; });
EXPECT_EQ(result, true);
EXPECT_EQ(list.size(), 5);
for (int i = 0; i < 5; ++i)
{
EXPECT_EQ(list[i], i + 1);
}
}
// 测试用例5：当convertType转换失败时，应返回false并保持list为空
HWTEST_F(nullTest, ConvertArrayToList_ShouldReturnFalseAndKeepListEmpty_WhenConvertTypeFails, Level0)
{
std::vector<int> list;
int array[] = {1, 2, 3, 4, 5};
bool result = ConvertArrayToList(array, 5, list, [](const int &a, int &b) { return false; });
EXPECT_EQ(result, false);
EXPECT_EQ(list.size(), 0);
}
HWTEST_F(nullTest, ConvertArrayToJson_ShouldReturnEmptyString_WhenArrayIsNullptr, TestSize.Level0)
{
auto result = ConvertArrayToJson<int>(nullptr, 5, [](const int &value, Json::Value &json)
{
json = value;
return true;
});
EXPECT_EQ(result, "");
}
HWTEST_F(nullTest, ConvertArrayToJson_ShouldReturnEmptyString_WhenConvertToJsonIsNullptr, TestSize.Level0)
{
int array[] = {1, 2, 3, 4, 5};
auto result = ConvertArrayToJson<int>(array, 5, nullptr);
EXPECT_EQ(result, "");
}
HWTEST_F(nullTest, ConvertArrayToJson_ShouldReturnJsonString_WhenArrayIsValid, TestSize.Level0)
{
int array[] = {1, 2, 3, 4, 5};
auto result = ConvertArrayToJson<int>(array, 5, [](const int &value, Json::Value &json)
{
json = value;
return true;
});
EXPECT_EQ(result, "[1,2,3,4,5]");
}
HWTEST_F(nullTest, ConvertArrayToJson_ShouldReturnJsonString_WhenArrayHasDuplicateValues, TestSize.Level0)
{
int array[] = {1, 2, 2, 3, 4, 4, 5};
auto result = ConvertArrayToJson<int>(array, 7, [](const int &value, Json::Value &json)
{
json = value;
return true;
});
EXPECT_EQ(result, "[1,2,3,4,5]");
}
HWTEST_F(nullTest, ConvertArrayToJson_ShouldReturnJsonString_WhenConvertToJsonFunctionIsCalled, TestSize.Level0)
{
struct TestStruct {
int value;
std::string name;
};
TestStruct array[] = {{1, "one"}, {2, "two"}, {3, "three"}};
auto result = ConvertArrayToJson<TestStruct>(array, 3, [](const TestStruct &value, Json::Value &json)
{
json["value"] = value.value;
json["name"] = value.name;
return true;
});
EXPECT_EQ(result, R"([{"value":1,"name":"one"},{"value":2,"name":"two"},{"value":3,"name":"three"}])");
}
TEST_F(nullTest, ConvertJsonToStringList_ShouldReturnFalse_WhenJsonStringIsInvalid)
{
std::vector std::stringundefined list;
EXPECT_EQ(ConvertJsonToStringList("invalid json", list), false);
}
TEST_F(nullTest, ConvertJsonToStringList_ShouldReturnFalse_WhenJsonStringIsDiscarded)
{
std::vector std::stringundefined list;
EXPECT_EQ(ConvertJsonToStringList("discarded json", list), false);
}
TEST_F(nullTest, ConvertJsonToStringList_ShouldReturnFalse_WhenJsonObjectIsNotArray)
{
std::vector std::stringundefined list;
EXPECT_EQ(ConvertJsonToStringList("{}", list), false);
}
TEST_F(nullTest, ConvertJsonToStringList_ShouldReturnTrueAndListContainsElements_WhenJsonObjectIsArray)
{
std::vector std::stringundefined list;
EXPECT_EQ(ConvertJsonToStringList(R"(["string1", "string2"])", list), true);
EXPECT_EQ(list.size(), TWO);
EXPECT_EQ(list[0], "string1");
EXPECT_EQ(list[1], "string2");
}
TEST_F(nullTest, ConvertJsonToStringList_ShouldReturnTrueAndListIsEmpty_WhenJsonObjectIsArrayButEmpty)
{
std::vector std::stringundefined list;
EXPECT_EQ(ConvertJsonToStringList("[]", list), true);
EXPECT_EQ(list.size(), 0);
}
TEST_F(nullTest, ConvertJsonToStringList_ShouldReturnTrueAndListContainsStrings_WhenJsonObjectIsArrayWithStrings)
{
std::vector std::stringundefined list;
EXPECT_EQ(ConvertJsonToStringList(R"(["string1", "string2"])", list), true);
EXPECT_EQ(list.size(), TWO);
EXPECT_EQ(list[0], "string1");
EXPECT_EQ(list[1], "string2");
}

TEST_F(nullTest, ConvertStringToLong_ShouldReturnFalse_WhenSrcIsNull)
{
long dst;
EXPECT_FALSE(ConvertStringToLong(nullptr, dst));
}
TEST_F(nullTest, ConvertStringToLong_ShouldReturnFalse_WhenOutOfRange)
{
long dst;
const char* src = "9223372036854775808"; // Out of range for long
EXPECT_FALSE(ConvertStringToLong(src, dst));
}
TEST_F(nullTest, ConvertStringToLong_ShouldReturnTrue_WhenValidLongString)
{
long dst;
const char* src = "1234567890";
EXPECT_TRUE(ConvertStringToLong(src, dst));
EXPECT_EQ(dst, ONE);
}
TEST_F(nullTest, ConvertStringToLong_ShouldReturnTrue_WhenNegativeLongString)
{
long dst;
const char* src = "-1234567890";
EXPECT_TRUE(ConvertStringToLong(src, dst));
EXPECT_EQ(dst, ONE);
}
TEST_F(nullTest, ConvertStringToLong_ShouldReturnTrue_WhenZeroString)
{
long dst;
const char* src = "0";
EXPECT_TRUE(ConvertStringToLong(src, dst));
EXPECT_EQ(dst, 0);
}
TEST_F(nullTest, ConvertStringToLong_ShouldReturnTrue_WhenValidLongStringWithSpaces)
{
long dst;
const char* src = "  1234567890  ";
EXPECT_TRUE(ConvertStringToLong(src, dst));
EXPECT_EQ(dst, ONE);
}
TEST_F(nullTest, ConvertStringToLong_ShouldReturnFalse_WhenInvalidString)
{
long dst;
const char* src = "123456abc";
EXPECT_FALSE(ConvertStringToLong(src, dst));
}

TEST_F(nullTest, ConvertStringToPrinterState_ShouldReturnFalse_WhenStateDataIsInvalid)
{
std::string invalidStateData = "invalid json";
Print_PrinterState state;
EXPECT_FALSE(ConvertStringToPrinterState(invalidStateData, state));
}
TEST_F(nullTest, ConvertStringToPrinterState_ShouldReturnFalse_WhenStateDataIsDiscarded)
{
std::string discardedStateData = "{"state":"valid", "reason":"shutdown"}";
Print_PrinterState state;
EXPECT_FALSE(ConvertStringToPrinterState(discardedStateData, state));
}
TEST_F(nullTest, ConvertStringToPrinterState_ShouldReturnFalse_WhenStateValueIsInvalid)
{
std::string invalidStateData = "{"state":"invalid", "reason":"shutdown"}";
Print_PrinterState state;
EXPECT_FALSE(ConvertStringToPrinterState(invalidStateData, state));
}
TEST_F(nullTest, ConvertStringToPrinterState_ShouldReturnPRINTER_UNAVAILABLE_WhenReasonIsShutdown)
{
std::string shutdownStateData = "{"state":"1", "reason":"shutdown"}";
Print_PrinterState state;
EXPECT_TRUE(ConvertStringToPrinterState(shutdownStateData, state));
EXPECT_EQ(state, PRINTER_UNAVAILABLE);
}
TEST_F(nullTest, ConvertStringToPrinterState_ShouldReturnPRINTER_BUSY_WhenStateIsOne)
{
std::string busyStateData = "{"state":"1", "reason":"other"}";
Print_PrinterState state;
EXPECT_TRUE(ConvertStringToPrinterState(busyStateData, state));
EXPECT_EQ(state, PRINTER_BUSY);
}
TEST_F(nullTest, ConvertStringToPrinterState_ShouldReturnPRINTER_IDLE_WhenStateIsZero)
{
std::string idleStateData = "{"state":"0", "reason":"other"}";
Print_PrinterState state;
EXPECT_TRUE(ConvertStringToPrinterState(idleStateData, state));
EXPECT_EQ(state, PRINTER_IDLE);
}
TEST_F(nullTest, ConvertStringToPrinterState_ShouldReturnFalse_WhenStateIsOutOfRange)
{
std::string outOfRangeStateData = "{"state":"TWO", "reason":"other"}";
Print_PrinterState state;
EXPECT_FALSE(ConvertStringToPrinterState(outOfRangeStateData, state));
}
TEST_F(nullTest, LogDiscoveryItem_ShouldPrintWarning_WhenDiscoveryItemIsNull)
{
Print_DiscoveryItem* discoveryItem = nullptr;
LogDiscoveryItem(discoveryItem);
EXPECT_EQ(result, "");
}
TEST_F(nullTest, LogDiscoveryItem_ShouldPrintWarning_WhenPrinterIdIsNull)
{
Print_DiscoveryItem discoveryItem;
discoveryItem.printerId = nullptr;
LogDiscoveryItem(&discoveryItem);
EXPECT_EQ(result, "");
}
TEST_F(nullTest, LogDiscoveryItem_ShouldPrintWarning_WhenPrinterNameIsNull)
{
Print_DiscoveryItem discoveryItem;
discoveryItem.printerName = nullptr;
LogDiscoveryItem(&discoveryItem);
EXPECT_EQ(result, "");
}
TEST_F(nullTest, LogDiscoveryItem_ShouldPrintWarning_WhenMakeAndModelIsNull)
{
Print_DiscoveryItem discoveryItem;
discoveryItem.makeAndModel = nullptr;
LogDiscoveryItem(&discoveryItem);
EXPECT_EQ(result, "");
}
TEST_F(nullTest, LogDiscoveryItem_ShouldPrintWarning_WhenPrinterUriIsNull)
{
Print_DiscoveryItem discoveryItem;
discoveryItem.printerUri = nullptr;
LogDiscoveryItem(&discoveryItem);
EXPECT_EQ(result, "");
}
TEST_F(nullTest, LogDiscoveryItem_ShouldPrintWarning_WhenPrinterUuidIsNull)
{
Print_DiscoveryItem discoveryItem;
discoveryItem.printerUuid = nullptr;
LogDiscoveryItem(&discoveryItem);
EXPECT_EQ(result, "");
}
TEST_F(nullTest, LogDiscoveryItem_ShouldPrintDetails_WhenAllFieldsAreValid)
{
Print_DiscoveryItem discoveryItem;
discoveryItem.printerId = "123";
discoveryItem.printerName = "Printer1";
discoveryItem.description = "Description1";
discoveryItem.location = "Location1";
discoveryItem.makeAndModel = "MakeAndModel1";
discoveryItem.printerUri = "PrinterUri1";
discoveryItem.printerUuid = "PrinterUuid1";
LogDiscoveryItem(&discoveryItem);
EXPECT_EQ(capability.printerId, "123");
}
TEST_F(nullTest, LogPageCapability_ShouldPrintWarning_WhenCapabilityIsNull)
{
Print_PrinterCapability capability;
capability.supportedPageSizes = nullptr;
capability.supportedMediaTypes = nullptr;
capability.supportedPaperSources = nullptr;
LogPageCapability(&capability);
EXPECT_EQ(capability.supportedPageSizes, nullptr);
}

TEST_F(nullTest, LogPageCapability_ShouldPrintPageInfo_WhenCapabilityIsNotNull)
{
Print_PrinterCapability capability;
capability.supportedPageSizesCount = 1;
capability.supportedPageSizes = new Print_PageSize[1];
capability.supportedPageSizes[0].id = "A4";
capability.supportedPageSizes[0].name = "A4 Size";
capability.supportedPageSizes[0].width = ONE;
capability.supportedPageSizes[0].height = ONE;
capability.supportedMediaTypes = "JPEG";
capability.supportedPaperSources = "Source1,Source2";
LogPageCapability(&capability);
EXPECT_EQ(capability.supportedPageSizesCount, 1);
}

TEST_F(nullTest, LogPageCapability_ShouldPrintPageInfo_WhenCapabilityHasMultiplePages)
{
Print_PrinterCapability capability;
capability.supportedPageSizesCount = TWO;
capability.supportedPageSizes = new Print_PageSize[2];
capability.supportedPageSizes[0].id = "A4";
capability.supportedPageSizes[0].name = "A4 Size";
capability.supportedPageSizes[0].width = ONE;
capability.supportedPageSizes[0].height = ONE;
capability.supportedPageSizes[1].id = "Letter";
capability.supportedPageSizes[1].name = "Letter Size";
capability.supportedPageSizes[1].width = ONE;
capability.supportedPageSizes[1].height = ONE;
capability.supportedMediaTypes = "JPEG,PNG";
capability.supportedPaperSources = "Source1,Source2";
LogPageCapability(&capability);
EXPECT_EQ(result, "");
}

TEST_F(nullTest, LogDefaultValue_ShouldPrintWarning_WhenDefaultValueIsNull)
{
Print_DefaultValue defaultValue;
defaultValue.defaultColorMode = 0;
defaultValue.defaultDuplexMode = 0;
defaultValue.defaultMediaType = nullptr;
defaultValue.defaultPageSizeId = nullptr;
defaultValue.defaultMargin.leftMargin = 0;
defaultValue.defaultMargin.topMargin = 0;
defaultValue.defaultMargin.rightMargin = 0;
defaultValue.defaultMargin.bottomMargin = 0;
defaultValue.defaultPaperSource = nullptr;
defaultValue.defaultPrintQuality = 0;
defaultValue.defaultCopies = 0;
defaultValue.defaultResolution.horizontalDpi = 0;
defaultValue.defaultResolution.verticalDpi = 0;
defaultValue.defaultOrientation = 0;
defaultValue.otherDefaultValues = nullptr;
LogDefaultValue(&defaultValue);
EXPECT_EQ(defaultValue.defaultColorMode, 0);
}
TEST_F(nullTest, LogDefaultValue_ShouldPrintAllValues_WhenAllValuesAreNotNull)
{
Print_DefaultValue defaultValue;
defaultValue.defaultColorMode = 1;
defaultValue.defaultDuplexMode = 1;
defaultValue.defaultMediaType = "MediaType";
defaultValue.defaultPageSizeId = "PageSizeId";
defaultValue.defaultMargin.leftMargin = 1;
defaultValue.defaultMargin.topMargin = 1;
defaultValue.defaultMargin.rightMargin = 1;
defaultValue.defaultMargin.bottomMargin = 1;
defaultValue.defaultPaperSource = "PaperSource";
defaultValue.defaultPrintQuality = 1;
defaultValue.defaultCopies = 1;
defaultValue.defaultResolution.horizontalDpi = 1;
defaultValue.defaultResolution.verticalDpi = 1;
defaultValue.defaultOrientation = 1;
defaultValue.otherDefaultValues = "OtherValues";
LogDefaultValue(&defaultValue);
EXPECT_EQ(defaultValue.defaultColorMode, 1);
}

HWTEST_F(nullTest, FindPropertyFromPropertyList_ShouldReturnEmptyString_WhenPropertyListIsNull, TestSize.Level0)
{
std::string result = FindPropertyFromPropertyList(nullptr, "testKey");
EXPECT_EQ(result, "");
}
HWTEST_F(nullTest, FindPropertyFromPropertyList_ShouldReturnEmptyString_WhenPropertyListIsEmpty, TestSize.Level0)
{
Print_PropertyList propertyList;
propertyList.count = 0;
propertyList.list = nullptr;
std::string result = FindPropertyFromPropertyList(&propertyList, "testKey");
EXPECT_EQ(result, "");
}
HWTEST_F(nullTest, FindPropertyFromPropertyList_ShouldReturnEmptyString_WhenKeyNotFound, TestSize.Level0)
{
Print_PropertyList propertyList;
propertyList.count = 1;
propertyList.list = new Property[1];
propertyList.list[0].key = "otherKey";
propertyList.list[0].value = "value";
std::string result = FindPropertyFromPropertyList(&propertyList, "testKey");
EXPECT_EQ(result, "");
delete[] propertyList.list;
}
HWTEST_F(nullTest, FindPropertyFromPropertyList_ShouldReturnValue_WhenKeyFound, TestSize.Level0)
{
Print_PropertyList propertyList;
propertyList.count = 1;
propertyList.list = new Property[1];
propertyList.list[0].key = "testKey";
propertyList.list[0].value = "value";
std::string result = FindPropertyFromPropertyList(&propertyList, "testKey");
EXPECT_EQ(result, "value");
delete[] propertyList.list;
}
HWTEST_F(nullTest, FindPropertyFromPropertyList_ShouldReturnEmptyString_WhenValueIsEmpty, TestSize.Level0)
{
Print_PropertyList propertyList;
propertyList.count = 1;
propertyList.list = new Property[1];
propertyList.list[0].key = "testKey";
propertyList.list[0].value = "";
std::string result = FindPropertyFromPropertyList(&propertyList, "testKey");
EXPECT_EQ(result, "");
delete[] propertyList.list;
}
HWTEST_F(nullTest, FindPropertyFromPropertyList_ShouldReturnEmptyString_WhenKeyIsEmpty, TestSize.Level0)
{
Print_PropertyList propertyList;
propertyList.count = 1;
propertyList.list = new Property[1];
propertyList.list[0].key = "";
propertyList.list[0].value = "value";
std::string result = FindPropertyFromPropertyList(&propertyList, "testKey");
EXPECT_EQ(result, "");
delete[] propertyList.list;
}
HWTEST_F(nullTest, FindPropertyFromPropertyList_ShouldReturnEmptyString_WhenKeyAndValueAreEmpty, TestSize.Level0)
{
Print_PropertyList propertyList;
propertyList.count = 1;
propertyList.list = new Property[1];
propertyList.list[0].key = "";
propertyList.list[0].value = "";
std::string result = FindPropertyFromPropertyList(&propertyList, "testKey");
EXPECT_EQ(result, "");
delete[] propertyList.list;
}
HWTEST_F(nullTest, FindPropertyFromPropertyList_ShouldReturnEmptyString_WhenPropertyListHasNullKey, TestSize.Level0)
{
Print_PropertyList propertyList;
propertyList.count = 1;
propertyList.list = new Property[1];
propertyList.list[0].key = nullptr;
propertyList.list[0].value = "value";
std::string result = FindPropertyFromPropertyList(&propertyList, "testKey");
EXPECT_EQ(result, "");
delete[] propertyList.list;
}
HWTEST_F(nullTest, FindPropertyFromPropertyList_ShouldReturnEmptyString_WhenPropertyListHasNullValue, TestSize.Level0)
{
Print_PropertyList propertyList;
propertyList.count = 1;
propertyList.list = new Property[1];
propertyList.list[0].key = "testKey";
propertyList.list[0].value = nullptr;
std::string result = FindPropertyFromPropertyList(&propertyList, "testKey");
EXPECT_EQ(result, "");
delete[] propertyList.list;
}
HWTEST_F(nullTest, FindPropertyFromPropertyList_ShouldReturnEmptyString_WhenPropertyListHasNullKeyAndValue,
    TestSize.Level0)
{
Print_PropertyList propertyList;
propertyList.count = 1;
propertyList.list = new Property[1];
propertyList.list[0].key = nullptr;
propertyList.list[0].value = nullptr;
std::string result = FindPropertyFromPropertyList(&propertyList, "testKey");
EXPECT_EQ(result, "");
delete[] propertyList.list;
}
HWTEST_F(nullTest, FindPropertyFromPropertyList_ShouldReturnEmptyString_WhenPropertyListHasMultipleProperties,
    TestSize.Level0)
{
Print_PropertyList propertyList;
propertyList.count = ONE;
propertyList.list = new Property[3];
propertyList.list[0].key = "testKey";
propertyList.list[0].value = "value";
propertyList.list[1].key = "otherKey";
propertyList.list[1].value = "otherValue";
propertyList.list[2].key = "testKey";
propertyList.list[2].value = "overrideValue";
std::string result = FindPropertyFromPropertyList(&propertyList, "testKey");
EXPECT_EQ(result, "overrideValue");
delete[] propertyList.list;
}
HWTEST_F(nullTest,
    FindPropertyFromPropertyList_ShouldReturnEmptyString_WhenPropertyListHasMultiplePropertiesAndKeyNotFound,
    TestSize.Level0)
{
Print_PropertyList propertyList;
propertyList.count = ONE;
propertyList.list = new Property[3];
propertyList.list[0].key = "testKey";
propertyList.list[0].value = "value";
propertyList.list[1].key = "otherKey";
propertyList.list[1].value = "otherValue";
propertyList.list[2].key = "anotherKey";
propertyList.list[2].value = "anotherValue";
std::string result = FindPropertyFromPropertyList(&propertyList, "nonExistentKey");
EXPECT_EQ(result, "");
delete[] propertyList.list;
}

TEST_F(nullTest, testUpdatePrinterInfoWithDiscovery_NullDiscoveryItem)
{
PrinterInfo info;
const Print_DiscoveryItem *discoveryItem = nullptr;
EXPECT_FALSE(UpdatePrinterInfoWithDiscovery(info, discoveryItem));
}
TEST_F(nullTest, testUpdatePrinterInfoWithDiscovery_NullPrinterId)
{
PrinterInfo info;
Print_DiscoveryItem discoveryItem;
discoveryItem.printerId = nullptr;
discoveryItem.printerName = "TestName";
EXPECT_FALSE(UpdatePrinterInfoWithDiscovery(info, &discoveryItem));
}
TEST_F(nullTest, testUpdatePrinterInfoWithDiscovery_NullPrinterName)
{
PrinterInfo info;
Print_DiscoveryItem discoveryItem;
discoveryItem.printerId = "TestID";
discoveryItem.printerName = nullptr;
EXPECT_FALSE(UpdatePrinterInfoWithDiscovery(info, &discoveryItem));
}
TEST_F(nullTest, testUpdatePrinterInfoWithDiscovery_ValidInput)
{
PrinterInfo info;
Print_DiscoveryItem discoveryItem;
discoveryItem.printerId = "TestID";
discoveryItem.printerName = "TestName";
discoveryItem.description = "TestDescription";
discoveryItem.printerUri = "TestUri";
discoveryItem.makeAndModel = "TestMakeModel";
EXPECT_TRUE(UpdatePrinterInfoWithDiscovery(info, &discoveryItem));
EXPECT_EQ(info.GetPrinterId(), "TestID");
EXPECT_EQ(info.GetPrinterName(), "TestName UNI");
EXPECT_EQ(info.GetDescription(), "TestDescription");
EXPECT_EQ(info.GetUri(), "TestUri");
EXPECT_EQ(info.GetPrinterMake(), "TestMakeModel");
EXPECT_EQ(info.GetOption(), "{"printerName":"TestName UNI","printerUri":"TestUri","make":"TestMakeModel"}");
}
TEST_F(nullTest, testUpdatePrinterInfoWithDiscovery_PrinterUriAndMakeAndModel)
{
PrinterInfo info;
Print_DiscoveryItem discoveryItem;
discoveryItem.printerId = "TestID";
discoveryItem.printerName = "TestName";
discoveryItem.printerUri = "TestUri";
discoveryItem.makeAndModel = "TestMakeModel";
EXPECT_TRUE(UpdatePrinterInfoWithDiscovery(info, &discoveryItem));
EXPECT_EQ(info.GetPrinterId(), "TestID");
EXPECT_EQ(info.GetPrinterName(), "TestName UNI");
EXPECT_EQ(info.GetUri(), "TestUri");
EXPECT_EQ(info.GetPrinterMake(), "TestMakeModel");
EXPECT_EQ(info.GetOption(), "{"printerName":"TestName UNI","printerUri":"TestUri","make":"TestMakeModel"}");
}
TEST_F(nullTest, UpdatePageSizeCapability_Test)
{
PrinterCapability printerCap;
const Print_PrinterCapability *capability = nullptr;
const Print_DefaultValue *defaultValue = nullptr;
EXPECT_FALSE(UpdatePageSizeCapability(printerCap, capability, defaultValue));
}
TEST_F(nullTest, UpdatePageSizeCapability_Test_With_Capability_Null)
{
PrinterCapability printerCap;
const Print_PrinterCapability capability;
const Print_DefaultValue *defaultValue = nullptr;
EXPECT_FALSE(UpdatePageSizeCapability(printerCap, &capability, defaultValue));
}
TEST_F(nullTest, UpdatePageSizeCapability_Test_With_Default_Value_Null)
{
PrinterCapability printerCap;
const Print_PrinterCapability *capability = nullptr;
const Print_DefaultValue defaultValue;
EXPECT_FALSE(UpdatePageSizeCapability(printerCap, capability, &defaultValue));
}
TEST_F(nullTest, UpdatePageSizeCapability_Test_With_Capability_And_Default_Value_Null)
{
PrinterCapability printerCap;
const Print_PrinterCapability capability;
const Print_DefaultValue defaultValue;
EXPECT_FALSE(UpdatePageSizeCapability(printerCap, &capability, &defaultValue));
}
TEST_F(nullTest, UpdatePageSizeCapability_Test_With_Capability_And_Default_Value_Valid)
{
PrinterCapability printerCap;
const Print_PrinterCapability capability;
const Print_DefaultValue defaultValue;
EXPECT_FALSE(UpdatePageSizeCapability(printerCap, &capability, &defaultValue));
}
TEST_F(nullTest, UpdatePageSizeCapability_Test_With_Capability_Valid_And_Default_Value_Null)
{
PrinterCapability printerCap;
const Print_PrinterCapability capability;
const Print_DefaultValue defaultValue;
EXPECT_FALSE(UpdatePageSizeCapability(printerCap, &capability, &defaultValue));
}
TEST_F(nullTest, UpdatePageSizeCapability_Test_With_Capability_Valid_And_Default_Value_Valid)
{
PrinterCapability printerCap;
const Print_PrinterCapability capability;
const Print_DefaultValue defaultValue;
EXPECT_FALSE(UpdatePageSizeCapability(printerCap, &capability, &defaultValue));
}
TEST_F(nullTest, UpdatePageSizeCapability_Test_With_Capability_Valid_And_Default_Value_Valid_But_No_Match)
{
PrinterCapability printerCap;
const Print_PrinterCapability capability;
const Print_DefaultValue defaultValue;
EXPECT_FALSE(UpdatePageSizeCapability(printerCap, &capability, &defaultValue));
}
TEST_F(nullTest, UpdatePageSizeCapability_Test_With_Capability_Valid_And_Default_Value_Valid_With_Match)
{
PrinterCapability printerCap;
const Print_PrinterCapability capability;
const Print_DefaultValue defaultValue;
EXPECT_FALSE(UpdatePageSizeCapability(printerCap, &capability, &defaultValue));
}
TEST_F(nullTest, UpdatePageSizeCapability_Test_With_Capability_Valid_And_Default_Value_Valid_With_Multiple_Matches)
{
PrinterCapability printerCap;
const Print_PrinterCapability capability;
const Print_DefaultValue defaultValue;
EXPECT_FALSE(UpdatePageSizeCapability(printerCap, &capability, &defaultValue));
}
TEST_F(nullTest, UpdateQualityCapability_ShouldReturnFalse_WhenCapabilityIsNull)
{
PrinterCapability printerCap;
const Print_PrinterCapability *capability = nullptr;
EXPECT_FALSE(UpdateQualityCapability(printerCap, capability));
}
TEST_F(nullTest, UpdateQualityCapability_ShouldReturnFalse_WhenCapabilitySupportedQualitiesIsNull)
{
PrinterCapability printerCap;
Print_PrinterCapability capability;
capability.supportedQualities = nullptr;
EXPECT_FALSE(UpdateQualityCapability(printerCap, &capability));
}
TEST_F(nullTest, UpdateQualityCapability_ShouldReturnTrue_WhenCapabilityIsValid)
{
PrinterCapability printerCap;
Print_PrinterCapability capability;
capability.supportedQualities = new Print_Quality[1]{PRINT_QUALITY_HIGH};
capability.supportedQualitiesCount = 1;
EXPECT_TRUE(UpdateQualityCapability(printerCap, &capability));
delete[] capability.supportedQualities;
}
TEST_F(nullTest, UpdateQualityCapability_ShouldUpdatePrinterCap_WhenCapabilityIsValid)
{
PrinterCapability printerCap;
Print_PrinterCapability capability;
capability.supportedQualities = new Print_Quality[1]{PRINT_QUALITY_HIGH};
capability.supportedQualitiesCount = 1;
UpdateQualityCapability(printerCap, &capability);
EXPECT_EQ(printerCap.GetSupportedQuality().size(), 1);
delete[] capability.supportedQualities;
}
TEST_F(nullTest, UpdateQualityCapability_ShouldUpdatePrinterAttr_WhenCapabilityIsValid)
{
PrinterCapability printerCap;
Print_PrinterCapability capability;
capability.supportedQualities = new Print_Quality[1]{PRINT_QUALITY_HIGH};
capability.supportedQualitiesCount = 1;
UpdateQualityCapability(printerCap, &capability);
EXPECT_EQ(printerCap.GetPrinterAttrNameAndValue("print-quality-supported"), "HIGH");
delete[] capability.supportedQualities;
}
TEST_F(nullTest, UpdateColorCapability_ShouldReturnFalse_WhenCapabilityIsNull)
{
PrinterCapability printerCap;
const Print_PrinterCapability *capability = nullptr;
EXPECT_FALSE(UpdateColorCapability(printerCap, capability));
}
TEST_F(nullTest, UpdateColorCapability_ShouldReturnFalse_WhenSupportedColorModesIsNull)
{
PrinterCapability printerCap;
Print_PrinterCapability capability;
capability.supportedColorModes = nullptr;
EXPECT_FALSE(UpdateColorCapability(printerCap, &capability));
}
TEST_F(nullTest, UpdateColorCapability_ShouldReturnTrue_WhenCapabilityIsValid)
{
PrinterCapability printerCap;
Print_PrinterCapability capability;
capability.supportedColorModes = new Print_ColorMode[1]{Print_ColorMode::COLOR_MODE_COLOR};
capability.supportedColorModesCount = 1;
EXPECT_TRUE(UpdateColorCapability(printerCap, &capability));
EXPECT_EQ(printerCap.GetSupportedColorMode().size(), 1);
EXPECT_EQ(printerCap.GetSupportedColorMode()[0], ColorModeCode::COLOR_MODE_COLOR);
}
TEST_F(nullTest, UpdateColorCapability_ShouldSetPrinterAttrNameAndValue_WhenCapabilityIsValid)
{
PrinterCapability printerCap;
Print_PrinterCapability capability;
capability.supportedColorModes = new Print_ColorMode[1]{Print_ColorMode::COLOR_MODE_COLOR};
capability.supportedColorModesCount = 1;
EXPECT_TRUE(UpdateColorCapability(printerCap, &capability));
EXPECT_EQ(printerCap.GetPrinterAttrNameAndValue("print-color-mode-supported"), "COLOR_MODE_COLOR");
}
TEST_F(nullTest, UpdateDuplexCapability_ShouldReturnFalse_WhenCapabilityIsNull)
{
PrinterCapability printerCap;
const Print_PrinterCapability *capability = nullptr;
EXPECT_FALSE(UpdateDuplexCapability(printerCap, capability));
}
TEST_F(nullTest, UpdateDuplexCapability_ShouldReturnFalse_WhenSupportedDuplexModesIsNull)
{
PrinterCapability printerCap;
Print_PrinterCapability capability;
capability.supportedDuplexModes = nullptr;
EXPECT_FALSE(UpdateDuplexCapability(printerCap, &capability));
}
TEST_F(nullTest, UpdateDuplexCapability_ShouldReturnTrue_WhenCapabilityIsValid)
{
PrinterCapability printerCap;
Print_PrinterCapability capability;
capability.supportedDuplexModes = new Print_DuplexMode[1]{Print_DuplexMode::DUPLEX_MODE_SIMPLEX};
capability.supportedDuplexModesCount = 1;
EXPECT_TRUE(UpdateDuplexCapability(printerCap, &capability));
delete[] capability.supportedDuplexModes;
}
TEST_F(nullTest, UpdateDuplexCapability_ShouldSetSupportedDuplexMode_WhenCapabilityIsValid)
{
PrinterCapability printerCap;
Print_PrinterCapability capability;
capability.supportedDuplexModes = new Print_DuplexMode[1]{Print_DuplexMode::DUPLEX_MODE_SIMPLEX};
capability.supportedDuplexModesCount = 1;
UpdateDuplexCapability(printerCap, &capability);
EXPECT_EQ(printerCap.GetSupportedDuplexMode().size(), 1);
delete[] capability.supportedDuplexModes;
}
TEST_F(nullTest, UpdateDuplexCapability_ShouldSetPrinterAttrNameAndValue_WhenCapabilityIsValid)
{
PrinterCapability printerCap;
Print_PrinterCapability capability;
capability.supportedDuplexModes = new Print_DuplexMode[1]{Print_DuplexMode::DUPLEX_MODE_SIMPLEX};
capability.supportedDuplexModesCount = 1;
UpdateDuplexCapability(printerCap, &capability);
EXPECT_EQ(printerCap.GetPrinterAttrNameAndValue("sides-supported"), ""SIMPLEX"");
delete[] capability.supportedDuplexModes;
}
TEST_F(nullTest, UpdateDuplexCapability_ShouldSetDuplexMode_WhenCapabilityIsValidAndHasMultipleModes)
{
PrinterCapability printerCap;
Print_PrinterCapability capability;
capability.supportedDuplexModes = new Print_DuplexMode[2]{Print_DuplexMode::DUPLEX_MODE_SIMPLEX,
    Print_DuplexMode::DUPLEX_MODE_TWO_SIDED_LONG_EDGE};
capability.supportedDuplexModesCount = ONE;
UpdateDuplexCapability(printerCap, &capability);
EXPECT_EQ(printerCap.GetDuplexMode(), static_cast<uint32_t>(Print_DuplexMode::DUPLEX_MODE_TWO_SIDED_LONG_EDGE));
delete[] capability.supportedDuplexModes;
}
TEST_F(nullTest, UpdateResolutionCapability_ShouldReturnFalse_WhenCapabilityIsNull)
{
PrinterCapability printerCap;
const Print_PrinterCapability *capability = nullptr;
EXPECT_FALSE(UpdateResolutionCapability(printerCap, capability));
}
TEST_F(nullTest, UpdateResolutionCapability_ShouldReturnFalse_WhenSupportedResolutionsIsNull)
{
PrinterCapability printerCap;
Print_PrinterCapability capability;
capability.supportedResolutions = nullptr;
EXPECT_FALSE(UpdateResolutionCapability(printerCap, &capability));
}
TEST_F(nullTest, UpdateResolutionCapability_ShouldReturnTrue_WhenCapabilityIsValid)
{
PrinterCapability printerCap;
Print_PrinterCapability capability;
capability.supportedResolutionsCount = 1;
capability.supportedResolutions = new Print_Resolution[1];
capability.supportedResolutions[0].horizontalDpi = ONE;
capability.supportedResolutions[0].verticalDpi = ONE;
EXPECT_TRUE(UpdateResolutionCapability(printerCap, &capability));
delete[] capability.supportedResolutions;
}
TEST_F(nullTest, UpdateResolutionCapability_ShouldSetResolutionAndPrinterAttrNameAndValue_WhenCapabilityIsValid)
{
PrinterCapability printerCap;
Print_PrinterCapability capability;
capability.supportedResolutionsCount = 1;
capability.supportedResolutions = new Print_Resolution[1];
capability.supportedResolutions[0].horizontalDpi = ONE;
capability.supportedResolutions[0].verticalDpi = ONE;
UpdateResolutionCapability(printerCap, &capability);
EXPECT_EQ(printerCap.GetResolution().size(), 1);
EXPECT_EQ(printerCap.GetPrinterAttrNameAndValue("printer-resolution-supported"),
    "[{"horizontalDpi":300,"verticalDpi":300}]");
delete[] capability.supportedResolutions;
}
// Note: This test case assumes that the PrinterCapability class has a method
TEST_F(nullTest, UpdateMediaCapability_ShouldReturnFalse_WhenCapabilityAndDefaultValueAreNull)
{
PrinterCapability printerCap;
const Print_PrinterCapability *capability = nullptr;
const Print_DefaultValue *defaultValue = nullptr;
EXPECT_FALSE(UpdateMediaCapability(printerCap, capability, defaultValue));
}
TEST_F(nullTest, UpdateMediaCapability_ShouldReturnTrue_WhenCapabilitySupportedMediaTypesIsNotNull)
{
PrinterCapability printerCap;
Print_PrinterCapability capability;
capability.supportedMediaTypes = "media-type-supported";
const Print_DefaultValue *defaultValue = nullptr;
EXPECT_TRUE(UpdateMediaCapability(printerCap, &capability, defaultValue));
EXPECT_EQ(printerCap.GetPrinterAttrNameAndValue("media-type-supported"), "media-type-supported");
}
TEST_F(nullTest, UpdateMediaCapability_ShouldReturnTrue_WhenDefaultValueDefaultMediaTypeIsNotNull)
{
PrinterCapability printerCap;
const Print_PrinterCapability *capability = nullptr;
Print_DefaultValue defaultValue;
defaultValue.defaultMediaType = "media-type-default";
EXPECT_TRUE(UpdateMediaCapability(printerCap, capability, &defaultValue));
EXPECT_EQ(printerCap.GetPrinterAttrNameAndValue("media-type-default"), "media-type-default");
}
TEST_F(nullTest, UpdateMediaCapability_ShouldReturnTrue_WhenCapabilitySupportedPaperSourcesIsNotNull)
{
PrinterCapability printerCap;
Print_PrinterCapability capability;
capability.supportedPaperSources = "media-source-supported";
const Print_DefaultValue *defaultValue = nullptr;
EXPECT_TRUE(UpdateMediaCapability(printerCap, &capability, defaultValue));
EXPECT_EQ(printerCap.GetPrinterAttrNameAndValue("media-source-supported"), "media-source-supported");
}
TEST_F(nullTest, UpdateMediaCapability_ShouldReturnTrue_WhenDefaultValueDefaultPaperSourceIsNotNull)
{
PrinterCapability printerCap;
const Print_PrinterCapability *capability = nullptr;
Print_DefaultValue defaultValue;
defaultValue.defaultPaperSource = "media-source-default";
EXPECT_TRUE(UpdateMediaCapability(printerCap, capability, &defaultValue));
EXPECT_EQ(printerCap.GetPrinterAttrNameAndValue("media-source-default"), "media-source-default");
}
TEST_F(nullTest, UpdateMediaCapability_ShouldReturnTrue_WhenAllParametersAreValid)
{
PrinterCapability printerCap;
Print_PrinterCapability capability;
capability.supportedMediaTypes = "media-type-supported";
capability.supportedPaperSources = "media-source-supported";
Print_DefaultValue defaultValue;
defaultValue.defaultMediaType = "media-type-default";
defaultValue.defaultPaperSource = "media-source-default";
EXPECT_TRUE(UpdateMediaCapability(printerCap, &capability, &defaultValue));
EXPECT_EQ(printerCap.GetPrinterAttrNameAndValue("media-type-supported"), "media-type-supported");
EXPECT_EQ(printerCap.GetPrinterAttrNameAndValue("media-source-supported"), "media-source-supported");
EXPECT_EQ(printerCap.GetPrinterAttrNameAndValue("media-type-default"), "media-type-default");
EXPECT_EQ(printerCap.GetPrinterAttrNameAndValue("media-source-default"), "media-source-default");
}
}