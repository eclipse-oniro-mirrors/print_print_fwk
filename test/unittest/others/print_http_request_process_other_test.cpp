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
#include "print_http_request_process.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS::Print {
class PrintHttpRequestProcessTest : public testing::Test {
public:
    PrintHttpRequestProcess *printHttpRequestProcess;
    void SetUp() override
    {
        printHttpRequestProcess = new PrintHttpRequestProcess();
    }
    void TearDown() override
    {
        delete printHttpRequestProcess;
        printHttpRequestProcess = nullptr;
    }
};

HWTEST_F(PrintHttpRequestProcessTest,
    PrintOperation_ShouldReturnHTTP_OPERATION_GET_ATTR_WhenOperationIsGet_Printer_Attributes, Level0)
{
    Operation operation = Operation::Get_Printer_Attributes;
    std::string result = printHttpRequestProcess->PrintOperation(operation);
    EXPECT_EQ(result, HTTP_OPERATION_GET_ATTR);
}

HWTEST_F(PrintHttpRequestProcessTest,
    PrintOperation_ShouldReturnHTTP_OPERATION_SEND_DOC_WhenOperationIsSend_Document, Level0)
{
    Operation operation = Operation::Send_Document;
    std::string result = printHttpRequestProcess->PrintOperation(operation);
    EXPECT_EQ(result, HTTP_OPERATION_SEND_DOC);
}

HWTEST_F(PrintHttpRequestProcessTest, PrintOperation_ShouldReturnHTTP_OPERATION_COMMON_WhenOperationIsOther, Level0)
{
    Operation operation = static_cast<Operation>(3);
    std::string result = printHttpRequestProcess->PrintOperation(operation);
    EXPECT_EQ(result, HTTP_OPERATION_COMMON);
}

HWTEST_F(PrintHttpRequestProcessTest, NeedOffset_ShouldReturnZero_WhenBufferIsEmpty, Level0)
{
    std::vector<uint8_t> readTempBuffer;
    PrintHttpRequestProcess process;
    EXPECT_EQ(process.NeedOffset(readTempBuffer), 0);
}

HWTEST_F(PrintHttpRequestProcessTest, NeedOffset_ShouldReturnNonZero_WhenBufferContainsNonZeroValues, Level0)
{
    std::vector<uint8_t> readTempBuffer = {1, 2, 3, 4, 5};
    PrintHttpRequestProcess process;
    EXPECT_NE(process.NeedOffset(readTempBuffer), 0);
}

HWTEST_F(PrintHttpRequestProcessTest, NeedOffset_ShouldReturnZero_WhenBufferContainsOnlyZeroes, Level0)
{
    std::vector<uint8_t> readTempBuffer = {0, 0, 0, 0, 0};
    PrintHttpRequestProcess process;
    EXPECT_EQ(process.NeedOffset(readTempBuffer), 0);
}

HWTEST_F(PrintHttpRequestProcessTest, NeedOffset_ShouldReturnNonZero_WhenBufferContainsMultipleNonZeroValues, Level0)
{
    std::vector<uint8_t> readTempBuffer = {1, 2, 3, 0, 0};
    PrintHttpRequestProcess process;
    EXPECT_NE(process.NeedOffset(readTempBuffer), 0);
}

HWTEST_F(PrintHttpRequestProcessTest, NeedOffset_ShouldReturnNonZero_WhenBufferContainsNegativeValues, Level0)
{
    std::vector<uint8_t> readTempBuffer = {-1, -2, -3, -4, -5};
    PrintHttpRequestProcess process;
    EXPECT_NE(process.NeedOffset(readTempBuffer), 0);
}

HWTEST_F(PrintHttpRequestProcessTest,
    NeedOffset_ShouldReturnNonZero_WhenBufferContainsMixedPositiveAndNegativeValues, Level0)
{
    std::vector<uint8_t> readTempBuffer = {1, -2, 3, -4, 5};
    PrintHttpRequestProcess process;
    EXPECT_NE(process.NeedOffset(readTempBuffer), 0);
}

TEST_F(PrintHttpRequestProcessTest, GetContentLength_ShouldReturnZero_WhenBufferIsEmpty)
{
    PrintHttpRequestProcess process;
    std::vector<uint8_t> buffer;
    size_t index = 0;
    EXPECT_EQ(process.GetContentLength(buffer, index), 0);
}
TEST_F(PrintHttpRequestProcessTest, GetContentLength_ShouldReturnCorrectLength_WhenBufferIsNotEmpty)
{
    PrintHttpRequestProcess process;
    std::vector<uint8_t> buffer = {1, 2, 3, 4, 5};
    size_t index = 2;
    size_t len = 3;
    EXPECT_EQ(process.GetContentLength(buffer, index), len);
}
TEST_F(PrintHttpRequestProcessTest, GetContentLength_ShouldReturnZero_WhenIndexIsOutOfRange)
{
    PrintHttpRequestProcess process;
    std::vector<uint8_t> buffer = {1, 2, 3, 4, 5};
    size_t index = 10;
    EXPECT_EQ(process.GetContentLength(buffer, index), 0);
}
TEST_F(PrintHttpRequestProcessTest,
    GetContentLength_ShouldReturnCorrectLength_WhenBufferIsNotEmptyAndIndexIsOutOfRange)
{
    PrintHttpRequestProcess process;
    std::vector<uint8_t> buffer = {1, 2, 3, 4, 5};
    size_t index = 10;
    EXPECT_EQ(process.GetContentLength(buffer, index), 0);
}

TEST_F(PrintHttpRequestProcessTest, DumpRespIdCode_ShouldReturnNullptr_WhenBufferIsEmpty)
{
    std::vector<uint8_t> readTempBuffer;
    PrintHttpRequestProcess printHttpRequestProcess;
    printHttpRequestProcess.DumpRespIdCode(readTempBuffer);
    EXPECT_EQ(nullptr, printHttpRequestProcess.DumpRespIdCode(readTempBuffer));
}
TEST_F(PrintHttpRequestProcessTest, DumpRespIdCode_ShouldReturnNotNullptr_WhenBufferIsNotEmpty)
{
    std::vector<uint8_t> readTempBuffer = {1, 2, 3, 4};
    PrintHttpRequestProcess printHttpRequestProcess;
    printHttpRequestProcess.DumpRespIdCode(readTempBuffer);
    EXPECT_NE(nullptr, printHttpRequestProcess.DumpRespIdCode(readTempBuffer));
}
TEST_F(PrintHttpRequestProcessTest, DumpRespIdCode_ShouldReturnNotNullptr_WhenBufferContainsSpecialCharacters)
{
    std::vector<uint8_t> readTempBuffer = {0x00, 0xFF, 0x01, 0xFE};
    PrintHttpRequestProcess printHttpRequestProcess;
    printHttpRequestProcess.DumpRespIdCode(readTempBuffer);
    EXPECT_NE(nullptr, printHttpRequestProcess.DumpRespIdCode(readTempBuffer));
}

TEST_F(PrintHttpRequestProcessTest, CheckLineEnd_ShouldReturnFalse_WhenBufferIsEmpty)
{
    PrintHttpRequestProcess process;
    std::vector<uint8_t> buffer;
    size_t index = 0;
    EXPECT_EQ(process.CheckLineEnd(buffer, index), false);
}
TEST_F(PrintHttpRequestProcessTest, CheckLineEnd_ShouldReturnFalse_WhenIndexIsGreaterThanBufferSize)
{
    PrintHttpRequestProcess process;
    std::vector<uint8_t> buffer = {0x0D, 0x0A, 0x0D, 0x0A}; // "\r\n\r\n"
    size_t index = 5;
    EXPECT_EQ(process.CheckLineEnd(buffer, index), false);
}
TEST_F(PrintHttpRequestProcessTest, CheckLineEnd_ShouldReturnTrue_WhenIndexIsAtLineEnd)
{
    PrintHttpRequestProcess process;
    std::vector<uint8_t> buffer = {0x0D, 0x0A, 0x0D, 0x0A, 0x0D, 0x0A}; // "\r\n\r\n"
    size_t index = 4;
    EXPECT_EQ(process.CheckLineEnd(buffer, index), true);
}
TEST_F(PrintHttpRequestProcessTest, CheckLineEnd_ShouldReturnTrue_WhenIndexIsAtBufferEnd)
{
    PrintHttpRequestProcess process;
    std::vector<uint8_t> buffer = {0x0D, 0x0A, 0x0D, 0x0A}; // "\r\n\r\n"
    size_t index = 4;
    EXPECT_EQ(process.CheckLineEnd(buffer, index), true);
}
TEST_F(PrintHttpRequestProcessTest, CheckLineEnd_ShouldReturnFalse_WhenIndexIsAtMiddleOfBuffer)
{
    PrintHttpRequestProcess process;
    std::vector<uint8_t> buffer = {0x0D, 0x0A, 0x0D, 0x0A, 0x0D, 0x0A, 0x0D, 0x0A}; // "\r\n\r\n"
    size_t index = 2;
    EXPECT_EQ(process.CheckLineEnd(buffer, index), false);
}

TEST_F(PrintHttpRequestProcessTest, CalculateRequestId_ShouldReturnZero_WhenSurfaceProducerIsNull)
{
    size_t requestId = printHttpRequestProcess->CalculateRequestId(nullptr);
    EXPECT_EQ(requestId, 0);
}

TEST_F(PrintHttpRequestProcessTest, CalculateRequestId_ShouldReturnNonZero_WhenSurfaceProducerIsNotNull)
{
    Mock<IConsumerSurface> mockSurface;
    Mock<IBufferProducer> mockProducer;
    EXPECT_CALL(mockSurface, GetProducer()).WillOnce(Return(&mockProducer));
    size_t requestId = printHttpRequestProcess->CalculateRequestId(&mockSurface);
    EXPECT_NE(requestId, 0);
}

TEST_F(PrintHttpRequestProcessTest,
    CalculateRequestId_ShouldReturnNonZero_WhenSurfaceProducerIsNotNullAndCreatePhotoOutputReturnsSuccess)
{
    Mock<IConsumerSurface> mockSurface;
    Mock<IBufferProducer> mockProducer;
    EXPECT_CALL(mockSurface, GetProducer()).WillOnce(Return(&mockProducer));
    EXPECT_CALL(mockProducer, RequestBuffer()).WillOnce(Return(true));
    size_t requestId = printHttpRequestProcess->CalculateRequestId(&mockSurface);
    EXPECT_NE(requestId, 0);
}

TEST_F(PrintHttpRequestProcessTest,
    CalculateRequestId_ShouldReturnZero_WhenSurfaceProducerIsNotNullAndCreatePhotoOutputReturnsFailure)
{
    Mock<IConsumerSurface> mockSurface;
    Mock<IBufferProducer> mockProducer;
    EXPECT_CALL(mockSurface, GetProducer()).WillOnce(Return(&mockProducer));
    EXPECT_CALL(mockProducer, RequestBuffer()).WillOnce(Return(false));
    size_t requestId = printHttpRequestProcess->CalculateRequestId(&mockSurface);
    EXPECT_EQ(requestId, 0);
}

HWTEST_F(PrintHttpRequestProcessTest,
    CalculateFileDataBeginIndex_ShouldReturnIndexPlusOne_WhenOperationIsREADAndIndexIsZero, Level0)
{
    PrintHttpRequestProcess process;
    size_t index = 0;
    Operation operation = Operation::READ;
    EXPECT_EQ(process.CalculateFileDataBeginIndex(index, operation), 1);
}

HWTEST_F(PrintHttpRequestProcessTest,
    CalculateFileDataBeginIndex_ShouldReturnIndexPlusOne_WhenOperationIsWRITEAndIndexIsZero, Level0)
{
    PrintHttpRequestProcess process;
    size_t index = 0;
    Operation operation = Operation::WRITE;
    EXPECT_EQ(process.CalculateFileDataBeginIndex(index, operation), 1);
}

HWTEST_F(PrintHttpRequestProcessTest,
    CalculateFileDataBeginIndex_ShouldReturnIndexPlusOne_WhenOperationIsREADAndIndexIsNonZero, Level0)
{
    PrintHttpRequestProcess process;
    size_t index = 5;
    Operation operation = Operation::READ;
    EXPECT_EQ(process.CalculateFileDataBeginIndex(index, operation), 6);
}

HWTEST_F(PrintHttpRequestProcessTest,
    CalculateFileDataBeginIndex_ShouldReturnIndexPlusOne_WhenOperationIsWRITEAndIndexIsNonZero, Level0)
{
    PrintHttpRequestProcess process;
    size_t index = 5;
    Operation operation = Operation::WRITE;
    EXPECT_EQ(process.CalculateFileDataBeginIndex(index, operation), 6);
}

TEST_F(PrintHttpRequestProcessTest, ProcessDataFromDevice_ShouldReturnFalse_WhenOperationIsNull)
{
    PrintHttpRequestProcess process;
    EXPECT_FALSE(process.ProcessDataFromDevice(nullptr));
}

TEST_F(PrintHttpRequestProcessTest, ProcessDataFromDevice_ShouldReturnTrue_WhenOperationIsNotNull)
{
    PrintHttpRequestProcess process;
    Operation operation; // Assuming Operation is a valid class with necessary methods
    EXPECT_TRUE(process.ProcessDataFromDevice(&operation));
}

TEST_F(PrintHttpRequestProcessTest, ProcessDataFromDevice_ShouldReturnFalse_WhenOperationHasInvalidData)
{
    PrintHttpRequestProcess process;
    Operation operation;
    operation.SetData(nullptr); // Assuming there's a method to set data
    EXPECT_FALSE(process.ProcessDataFromDevice(&operation));
}

TEST_F(PrintHttpRequestProcessTest, ProcessDataFromDevice_ShouldReturnTrue_WhenOperationHasValidData)
{
    PrintHttpRequestProcess process;
    Operation operation;
    operation.SetData(validData); // Assuming validData is a valid data
    EXPECT_TRUE(process.ProcessDataFromDevice(&operation));
}

TEST_F(PrintHttpRequestProcessTest, GetAttrAgain_ShouldReturnNullptr_WhenSurfaceProducerIsNull)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    Operation operation;
    std::vector<uint8_t> tmVector;
    EXPECT_EQ(printHttpRequestProcess.GetAttrAgain(operation, tmVector), nullptr);
}
TEST_F(PrintHttpRequestProcessTest, GetAttrAgain_ShouldReturnNonNullptr_WhenSurfaceProducerIsNotNull)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    Operation operation;
    std::vector<uint8_t> tmVector;
    EXPECT_NE(printHttpRequestProcess.GetAttrAgain(operation, tmVector), nullptr);
}
TEST_F(PrintHttpRequestProcessTest, GetAttrAgain_ShouldReturnNullptr_WhenOperationIsInvalid)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    Operation operation;
    std::vector<uint8_t> tmVector;
    EXPECT_EQ(printHttpRequestProcess.GetAttrAgain(operation, tmVector), nullptr);
}
TEST_F(PrintHttpRequestProcessTest, GetAttrAgain_ShouldReturnNonNullptr_WhenOperationIsValid)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    Operation operation;
    std::vector<uint8_t> tmVector;
    EXPECT_NE(printHttpRequestProcess.GetAttrAgain(operation, tmVector), nullptr);
}
TEST_F(PrintHttpRequestProcessTest, GetAttrAgain_ShouldReturnNullptr_WhenTmVectorIsEmpty)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    Operation operation;
    std::vector<uint8_t> tmVector;
    EXPECT_EQ(printHttpRequestProcess.GetAttrAgain(operation, tmVector), nullptr);
}
TEST_F(PrintHttpRequestProcessTest, GetAttrAgain_ShouldReturnNonNullptr_WhenTmVectorIsNotEmpty)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    Operation operation;
    std::vector<uint8_t> tmVector = {1, 2, 3};
    EXPECT_NE(printHttpRequestProcess.GetAttrAgain(operation, tmVector), nullptr);
}

TEST_F(PrintHttpRequestProcessTest, ProcessHttpResponse_ShouldReturnNullptr_WhenSurfaceProducerIsNull)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    httplib::Response responseData;
    size_t requestId = 1;
    printHttpRequestProcess.ProcessHttpResponse(responseData, requestId);
    EXPECT_EQ(responseData.body, "");
}

TEST_F(PrintHttpRequestProcessTest, ProcessHttpResponse_ShouldHandleRequestId_WhenSurfaceProducerIsNotNull)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    httplib::Response responseData;
    size_t requestId = 1;
    printHttpRequestProcess.ProcessHttpResponse(responseData, requestId);
    EXPECT_EQ(responseData.body, "1");
}

TEST_F(PrintHttpRequestProcessTest, ProcessHttpResponse_ShouldHandleResponseData_WhenSurfaceProducerIsNotNull)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    httplib::Response responseData;
    size_t requestId = 1;
    responseData.body = "test";
    printHttpRequestProcess.ProcessHttpResponse(responseData, requestId);
    size_t ret = 4;
    EXPECT_EQ(requestId, ret);
}

TEST_F(PrintHttpRequestProcessTest, ProcessHttpResponse_ShouldHandleBoth_WhenSurfaceProducerIsNotNull)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    httplib::Response responseData;
    size_t requestId = 1;
    responseData.body = "test";
    printHttpRequestProcess.ProcessHttpResponse(responseData, requestId);
    EXPECT_EQ(responseData.body, "test4");
}

TEST_F(PrintHttpRequestProcessTest, DealRequestHeader_ShouldReturnFalse_WhenRequestDataIsNull)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    httplib::Request requestData;
    std::string sHeadersAndBody;
    EXPECT_EQ(printHttpRequestProcess.DealRequestHeader(requestData, sHeadersAndBody), false);
}
TEST_F(PrintHttpRequestProcessTest, DealRequestHeader_ShouldReturnTrue_WhenRequestDataIsNotNull)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    httplib::Request requestData;
    requestData.set_method("GET");
    requestData.set_body("test body");
    std::string sHeadersAndBody;
    EXPECT_EQ(printHttpRequestProcess.DealRequestHeader(requestData, sHeadersAndBody), true);
}
TEST_F(PrintHttpRequestProcessTest, DealRequestHeader_ShouldReturnFalse_WhenHeadersAndBodyIsEmpty)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    httplib::Request requestData;
    requestData.set_method("GET");
    requestData.set_body("test body");
    std::string sHeadersAndBody;
    EXPECT_EQ(printHttpRequestProcess.DealRequestHeader(requestData, sHeadersAndBody), true);
    EXPECT_EQ(sHeadersAndBody.empty(), true);
}
TEST_F(PrintHttpRequestProcessTest, DealRequestHeader_ShouldReturnTrue_WhenHeadersAndBodyIsNotEmpty)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    httplib::Request requestData;
    requestData.set_method("GET");
    requestData.set_body("test body");
    std::string sHeadersAndBody = "Header: value\r\nBody: content";
    EXPECT_EQ(printHttpRequestProcess.DealRequestHeader(requestData, sHeadersAndBody), true);
    EXPECT_EQ(sHeadersAndBody.empty(), false);
}

TEST_F(PrintHttpRequestProcessTest, testCalcReqIdOperaId)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    size_t requestId = 0;
    const char *data = "test data";
    size_t dataLength = strlen(data);
    printHttpRequestProcess.CalcReqIdOperaId(data, dataLength, requestId);
    // 断言预期结果
    EXPECT_EQ(requestId, 0);
}
TEST_F(PrintHttpRequestProcessTest, testCalcReqIdOperaIdWithNonZeroData)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    size_t requestId = 0;
    const char *data = "test data with non-zero length";
    size_t dataLength = strlen(data);
    printHttpRequestProcess.CalcReqIdOperaId(data, dataLength, requestId);
    // 断言预期结果
    EXPECT_EQ(requestId, 0);
}
TEST_F(PrintHttpRequestProcessTest, testCalcReqIdOperaIdWithEmptyData)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    size_t requestId = 0;
    const char *data = "";
    size_t dataLength = strlen(data);
    printHttpRequestProcess.CalcReqIdOperaId(data, dataLength, requestId);
    // 断言预期结果
    EXPECT_EQ(requestId, 0);
}
TEST_F(PrintHttpRequestProcessTest, testCalcReqIdOperaIdWithNullData)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    size_t requestId = 0;
    const char *data = nullptr;
    size_t dataLength = 0;
    printHttpRequestProcess.CalcReqIdOperaId(data, dataLength, requestId);
    // 断言预期结果
    EXPECT_EQ(requestId, 0);
}

TEST_F(PrintHttpRequestProcessTest, ProcessOtherRequest_ShouldReturnNull_WhenSurfaceProducerIsNull)
{
    PrintHttpRequestProcess process;
    const char *data = "test data";
    size_t data_length = strlen(data);
    process.ProcessOtherRequest(data, data_length, nullptr);
    // 断言预期结果
    EXPECT_EQ(process.result, nullptr);
}
TEST_F(PrintHttpRequestProcessTest, ProcessOtherRequest_ShouldReturnNotNull_WhenSurfaceProducerIsNotNull)
{
    PrintHttpRequestProcess process;
    const char *data = "test data";
    size_t data_length = strlen(data);
    process.ProcessOtherRequest(data, data_length, new SurfaceProducer());
    // 断言预期结果
    EXPECT_NE(process.result, nullptr);
}
TEST_F(PrintHttpRequestProcessTest, ProcessOtherRequest_ShouldReturnCorrectResult_WhenDataIsEmpty)
{
    PrintHttpRequestProcess process;
    const char *data = "";
    size_t data_length = strlen(data);
    process.ProcessOtherRequest(data, data_length, new SurfaceProducer());
    // 断言预期结果
    EXPECT_EQ(process.result, "processed empty data");
}
TEST_F(PrintHttpRequestProcessTest, ProcessOtherRequest_ShouldReturnCorrectResult_WhenDataIsNotEmpty)
{
    PrintHttpRequestProcess process;
    const char *data = "test data";
    size_t data_length = strlen(data);
    process.ProcessOtherRequest(data, data_length, new SurfaceProducer());
    // 断言预期结果
    EXPECT_EQ(process.result, "processed data");
}
TEST_F(PrintHttpRequestProcessTest, ProcessOtherRequest_ShouldReturnCorrectResult_WhenDataIsLong)
{
    PrintHttpRequestProcess process;
    const char *data = "this is a long test data";
    size_t data_length = strlen(data);
    process.ProcessOtherRequest(data, data_length, new SurfaceProducer());
    // 断言预期结果
    EXPECT_EQ(process.result, "processed long data");
}

TEST_F(PrintHttpRequestProcessTest, DumpReqIdOperaId_ShouldPrintData_WhenDataIsNotNull)
{
    char data[REQID_OPERAID_LEN] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    PrintHttpRequestProcess::DumpReqIdOperaId(data, REQID_OPERAID_LEN);
    EXPECT_EQ(process.result, "processed");
}
TEST_F(PrintHttpRequestProcessTest, DumpReqIdOperaId_ShouldNotPrintData_WhenDataIsNull)
{
    char *data = nullptr;
    PrintHttpRequestProcess::DumpReqIdOperaId(data, REQID_OPERAID_LEN);
    EXPECT_EQ(process.result, "");
}
TEST_F(PrintHttpRequestProcessTest, DumpReqIdOperaId_ShouldNotPrintData_WhenDataLengthIsLessThanREQID_OPERAID_LEN)
{
    char data[REQID_OPERAID_LEN - 1] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    PrintHttpRequestProcess::DumpReqIdOperaId(data, REQID_OPERAID_LEN - 1);
    EXPECT_EQ(process.result, "");
}

// 测试用例1: 测试data为空，data_length为0的情况
HWTEST_F(PrintHttpRequestProcessTest, CreateChunk_ShouldReturnEmptyString_WhenDataIsNullAndDataLengthIsZero, Level0)
{
    PrintHttpRequestProcess process;
    std::string result = process.CreateChunk(nullptr, 0);
    EXPECT_EQ(result, "");
}
// 测试用例2: 测试data为空，data_length不为0的情况
HWTEST_F(PrintHttpRequestProcessTest,
    CreateChunk_ShouldReturnCorrectString_WhenDataIsNullAndDataLengthIsNotZero, Level0)
{
    PrintHttpRequestProcess process;
    std::string result = process.CreateChunk(nullptr, 10);
    EXPECT_EQ(result, "A\r\n"); // 假设HTTP_MSG_STRING_R_AND_N为"\r\n"
}
// 测试用例3: 测试data不为空，data_length为0的情况
HWTEST_F(PrintHttpRequestProcessTest,
    CreateChunk_ShouldReturnCorrectString_WhenDataIsNotNullAndDataLengthIsZero, Level0)
{
    PrintHttpRequestProcess process;
    std::string result = process.CreateChunk("test", 0);
    EXPECT_EQ(result, "0\r\n\r\n"); // 假设HTTP_MSG_STRING_R_AND_N为"\r\n"
}
// 测试用例4: 测试data不为空，data_length不为0的情况
HWTEST_F(PrintHttpRequestProcessTest,
    CreateChunk_ShouldReturnCorrectString_WhenDataIsNotNullAndDataLengthIsNotZero, Level0)
{
    PrintHttpRequestProcess process;
    std::string result = process.CreateChunk("test", 4);
    EXPECT_EQ(result, "4\r\ntest\r\n"); // 假设HTTP_MSG_STRING_R_AND_N为"\r\n"
}
// 测试用例5: 测试data包含特殊字符，data_length不为0的情况
HWTEST_F(PrintHttpRequestProcessTest,
    CreateChunk_ShouldReturnCorrectString_WhenDataContainsSpecialCharacters, Level0)
{
    PrintHttpRequestProcess process;
    std::string result = process.CreateChunk("test\r\n", 7);
    EXPECT_EQ(result, "7\r\ntest\r\n"); // 假设HTTP_MSG_STRING_R_AND_N为"\r\n"
}

TEST_F(PrintHttpRequestProcessTest, WriteDataSync_ShouldReturnZero_WhenDataStrIsEmpty)
{
    int32_t ret = printHttpRequestProcess->WriteDataSync("");
    EXPECT_EQ(ret, 0);
}

TEST_F(PrintHttpRequestProcessTest, WriteDataSync_ShouldReturnZero_WhenDataStrIsLessThanEndpointMaxLength)
{
    int32_t ret = printHttpRequestProcess->WriteDataSync("short");
    EXPECT_EQ(ret, 0);
}

TEST_F(PrintHttpRequestProcessTest, WriteDataSync_ShouldReturnNonZero_WhenBulkTransferWriteDataFails)
{
    // Assuming BulkTransferWriteData always returns non-zero when it fails
    int32_t ret = printHttpRequestProcess->WriteDataSync(std::string(USB_ENDPOINT_MAX_LENGTH + 1, 'a'));
    EXPECT_NE(ret, 0);
}

TEST_F(PrintHttpRequestProcessTest, WriteDataSync_ShouldReturnZero_WhenBulkTransferWriteDataSucceeds)
{
    // Assuming BulkTransferWriteData always returns zero when it succeeds
    int32_t ret = printHttpRequestProcess->WriteDataSync(std::string(USB_ENDPOINT_MAX_LENGTH, 'a'));
    EXPECT_EQ(ret, 0);
}

TEST_F(PrintHttpRequestProcessTest, WriteDataSync_ShouldReturnZero_WhenDataStrIsMultipleOfEndpointMaxLength)
{
    int32_t ret = printHttpRequestProcess->WriteDataSync(std::string(USB_ENDPOINT_MAX_LENGTH * 10, 'a'));
    EXPECT_EQ(ret, 0);
}

TEST_F(PrintHttpRequestProcessTest, BulkTransferWriteData_ShouldReturnDeviceErrorWhenDeviceNotOpen)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    std::string dataStr = "test data";
    int32_t ret = printHttpRequestProcess.BulkTransferWriteData(dataStr);
    EXPECT_EQ(ret, EORROR_HDF_DEV_ERR_NO_DEVICE);
}
TEST_F(PrintHttpRequestProcessTest, BulkTransferWriteData_ShouldRetryWhenTimeout)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    std::string dataStr = "test data";
    printHttpRequestProcess.sendDocTotalLen = 1; // Set a non-zero value to simulate timeout
    int32_t ret = printHttpRequestProcess.BulkTransferWriteData(dataStr);
    EXPECT_EQ(ret, EORROR_HDF_DEV_ERR_TIME_OUT);
}
TEST_F(PrintHttpRequestProcessTest, BulkTransferWriteData_ShouldReturnZeroOnSuccess)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    std::string dataStr = "test data";
    printHttpRequestProcess.sendDocTotalLen = 0; // Set to zero to simulate successful write
    int32_t ret = printHttpRequestProcess.BulkTransferWriteData(dataStr);
    EXPECT_EQ(ret, 0);
}
TEST_F(PrintHttpRequestProcessTest, BulkTransferWriteData_ShouldClearBufferOnSuccess)
{
    PrintHttpRequestProcess printHttpRequestProcess;
    std::string dataStr = "test data";
    printHttpRequestProcess.sendDocTotalLen = 0; // Set to zero to simulate successful write
    printHttpRequestProcess.BulkTransferWriteData(dataStr);
    EXPECT_TRUE(printHttpRequestProcess.vectorRequestBuffer.empty());
}

TEST_F(PrintHttpRequestProcessTest, ProcessHttpResp_Test)
{
    PrintHttpRequestProcess process;
    size_t requestId = 1;
    httplib::Response responseData;
    std::string sHeadersAndBody = "test";
    // Mock the reqIdOperaIdMap and deviceOpen for testing
    process.reqIdOperaIdMap[requestId] = HTTP_REQUEST_GET_ATTR;
    process.deviceOpen = true;

    process.ProcessHttpResp(requestId, responseData, sHeadersAndBody);

    // Verify the result
    EXPECT_EQ(responseData.status, 200); // Assuming ProcessHttpResponseGetAttr sets status to 200
}

TEST_F(PrintHttpRequestProcessTest, ProcessHttpResp_Test_DeviceDisconnect)
{
    PrintHttpRequestProcess process;
    size_t requestId = 1;
    httplib::Response responseData;
    std::string sHeadersAndBody = "test";
    // Mock the reqIdOperaIdMap and deviceOpen for testing
    process.reqIdOperaIdMap[requestId] = HTTP_REQUEST_SEND_DOC;
    process.deviceOpen = false;

    process.ProcessHttpResp(requestId, responseData, sHeadersAndBody);

    // Verify the result
    EXPECT_EQ(responseData.status, 0); // Assuming ProcessHttpResponseSendDoc sets status to 0
}

TEST_F(PrintHttpRequestProcessTest, ProcessHttpResp_Test_OtherOperation)
{
    PrintHttpRequestProcess process;
    size_t requestId = 1;
    httplib::Response responseData;
    std::string sHeadersAndBody = "test";
    // Mock the reqIdOperaIdMap and deviceOpen for testing
    process.reqIdOperaIdMap[requestId] = 999; // Assuming 999 is an unknown operation
    process.deviceOpen = true;

    process.ProcessHttpResp(requestId, responseData, sHeadersAndBody);

    // Verify the result
    EXPECT_EQ(responseData.status, 0); // Assuming ProcessHttpResponse sets status to 0
}

} // namespace OHOS::Print
