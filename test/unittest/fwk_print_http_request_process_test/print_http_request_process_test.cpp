/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifdef IPPOVERUSB_ENABLE
#include <gtest/gtest.h>
#define private public
#include "print_http_request_process.h"
#undef private
#include "print_ipp_over_usb_constant.h"
#include "print_log.h"

using namespace testing::ext;

static const std::string HTTP_RESP_CONTINUE = "HTTP/1.1 100 CONTINUE\r\n\r\nContent-Length: 122\r\n";
static const std::string HTTP_RESP_OK = "HTTP/1.1 200 OK\r\n";
static const std::string HTTP_RESP_CONNECTION = "Connection:close\r\n";
static const std::string HTTP_RESP_DATE = "Date:Tue 20 Feb 2024 02:57:06 GMT";
static const std::string HTTP_RESP_CACHE_CONTROL = "Cache-Control: no-cache\r\n";
static const std::string HTTP_RESP_SERVER = "Server: bsa/1.2\r\n";
static const std::string HTTP_RESP_CONTENT_TYPE = "Content-Type: application/ipp\r\n";
static const std::string HTTP_RESP_CONTENT_LENGTH = "Content-Length: 11616\r\n";
static const std::string HTTP_RESP_IPP = "\x02\x00\x00\x00\x00\x00\x00\x01";
static const std::string HTTP_RESP_DATA =
    R"(\x01G\x00\x12attributes-charset\x00\x05utf-8H\x00\x1b\x61\x74\x74\x72\x69\x62)"\
    R"(\x75\x74\x65\x73\x2d\x6e\x61\x74\x75\x72\x61\x6c\x2d\x6c\x61\x6e\x67\x75\x61\x67)"\
    R"(\x65\x00\x05\x65\x6e\x2d\x75\x73)";
static const std::string HTTP_REQ_DATA =
    R"(\x02\x00\x00\x0b\x00\x00\x00\x01\x01G\x00\x12attributes-charset\x00\x05utf-8H\x00\x1)"\
    R"(battributes-natural-language\x00\x05en-usE\x00\x0bprinter-uri\x00!ipp://192.168.186.1:631/ipp/printD\x00\x14)"\
    R"(requested-attributes\x00\x15compression-supportedD\x00\x00\x00\x10copies-supportedD\x00\x00\x00\x0ccups-versi)"\
    R"(onD\x00\x00\x00\x19document-format-supportedD\x00\x00\x00!job-password-encryption-supportedD\x00\x00\x00\x0d)"\
    R"(marker-colorsD\x00\x00\x00\x12marker-high-levelsD\x00\x00\x00\x0dmarker-levelsD\x00\x00\x00\x11marker-low-le)"\
    R"(velsD\x00\x00\x00\x0emarker-messageD\x00\x00\x00\x0cmarker-namesD\x00\x00\x00\x0cmarker-typesD\x00\x00\x00)"\
    R"(\x13media-col-supportedD\x00\x00\x00$multiple-document-handling-supportedD\x00\x00\x00\x14operations-support)"\
    R"(edD\x00\x00\x00\x1aprint-color-mode-supportedD\x00\x00\x00\x0dprinter-alertD\x00\x00\x00\x19printer-alert-d)"\
    R"(escriptionD\x00\x00\x00\x19printer-is-accepting-jobsD\x00\x00\x00 printer-mandatory-job-attributesD\x00\x00)"\
    R"(\x00\x0dprinter-stateD\x00\x00\x00\x15printer-state-messageD\x00\x00\x00\x15printer-state-reasons\x03")";

namespace OHOS {
namespace Print {
class PrintHttpRequestProcessTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PrintHttpRequestProcessTest::SetUpTestCase(void)
{}

void PrintHttpRequestProcessTest::TearDownTestCase(void)
{}

void PrintHttpRequestProcessTest::SetUp(void)
{
    static int32_t testNo = 0;
    PRINT_HILOGI("PrintHttpRequestProcessTest_%{public}d", ++testNo);
}

void PrintHttpRequestProcessTest::TearDown(void)
{}

/**
 * @tc.name: PrintHttpRequestProcessTest_001
 * @tc.desc: Verify the PrintOperation function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_001, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string str = printHttpRequestProcess.PrintOperation(Operation::Common);
    EXPECT_EQ(str, HTTP_OPERATION_COMMON);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_002
 * @tc.desc: Verify the PrintOperation function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_002, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string str = printHttpRequestProcess.PrintOperation(Operation::Get_Printer_Attributes);
    EXPECT_EQ(str, HTTP_OPERATION_GET_ATTR);
}
/**
 * @tc.name: PrintHttpRequestProcessTest_003
 * @tc.desc: Verify the PrintOperation function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_003, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string str = printHttpRequestProcess.PrintOperation(Operation::Send_Document);
    EXPECT_EQ(str, HTTP_OPERATION_SEND_DOC);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_004
 * @tc.desc: Verify the NeedOffset function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_004, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::vector<uint8_t> readTempBuffer;
    readTempBuffer.assign(HTTP_RESP_CONTINUE.begin(), HTTP_RESP_CONTINUE.end());
    size_t reqindex = printHttpRequestProcess.NeedOffset(readTempBuffer);
    size_t expect = HTTP_COMMON_CONST_VALUE_25;
    EXPECT_EQ(reqindex, expect);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_005
 * @tc.desc: Verify the NeedOffset function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_005, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::vector<uint8_t> readTempBuffer;
    size_t reqindex = printHttpRequestProcess.NeedOffset(readTempBuffer);
    size_t expect = 0;
    EXPECT_EQ(reqindex, expect);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_006
 * @tc.desc: Verify the RecordBufByOperation function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_006, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    size_t requestId = 1;
    std::string tempStr = HTTP_RESP_OK;
    tempStr += HTTP_RESP_CONNECTION;
    tempStr += HTTP_RESP_DATE;
    tempStr += HTTP_RESP_CACHE_CONTROL;
    tempStr += HTTP_RESP_SERVER;
    tempStr += HTTP_RESP_CONTENT_TYPE;
    tempStr += HTTP_RESP_CONTENT_LENGTH;
    tempStr += HTTP_MSG_STRING_R_AND_N;
    tempStr += HTTP_RESP_IPP;
    tempStr += HTTP_RESP_DATA;
    std::vector<uint8_t> tmVector;
    tmVector.assign(tempStr.begin(), tempStr.end());
    printHttpRequestProcess.reqIdOperaIdMap[requestId] = HTTP_REQUEST_GET_ATTR;
    printHttpRequestProcess.RecordBufByOperation(Operation::Get_Printer_Attributes, requestId, tmVector);
    size_t expect = 1;
    EXPECT_EQ(expect, printHttpRequestProcess.readGetAttrBufMap.size());
}

/**
 * @tc.name: PrintHttpRequestProcessTest_007
 * @tc.desc: Verify the RecordBufByOperation function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_007, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    size_t requestId = 1;
    std::string tempStr = HTTP_RESP_OK;
    tempStr += HTTP_RESP_CONNECTION;
    tempStr += HTTP_RESP_DATE;
    tempStr += HTTP_RESP_CACHE_CONTROL;
    tempStr += HTTP_RESP_SERVER;
    tempStr += HTTP_RESP_CONTENT_TYPE;
    tempStr += HTTP_RESP_CONTENT_LENGTH;
    tempStr += HTTP_MSG_STRING_R_AND_N;
    tempStr += HTTP_RESP_IPP;
    tempStr += HTTP_RESP_DATA;
    std::vector<uint8_t> tmVector;
    tmVector.assign(tempStr.begin(), tempStr.end());
    printHttpRequestProcess.reqIdOperaIdMap[requestId] = HTTP_REQUEST_GET_ATTR;
    printHttpRequestProcess.readGetAttrBufMap[requestId] = tmVector;
    printHttpRequestProcess.RecordBufByOperation(Operation::Get_Printer_Attributes, requestId, tmVector);
    size_t expect = 1;
    EXPECT_EQ(expect, printHttpRequestProcess.readGetAttrBufMap.size());
}

/**
 * @tc.name: PrintHttpRequestProcessTest_008
 * @tc.desc: Verify the RecordBufByOperation function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_008, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    size_t requestId = 1;
    std::string tempStr = HTTP_RESP_OK;
    tempStr += HTTP_RESP_CONNECTION;
    tempStr += HTTP_RESP_DATE;
    tempStr += HTTP_RESP_CACHE_CONTROL;
    tempStr += HTTP_RESP_SERVER;
    tempStr += HTTP_RESP_CONTENT_TYPE;
    tempStr += HTTP_RESP_CONTENT_LENGTH;
    tempStr += HTTP_MSG_STRING_R_AND_N;
    tempStr += HTTP_RESP_IPP;
    tempStr += HTTP_RESP_DATA;
    std::vector<uint8_t> tmVector;
    tmVector.assign(tempStr.begin(), tempStr.end());
    size_t expect = 1;
    printHttpRequestProcess.RecordBufByOperation(Operation::Send_Document, requestId, tmVector);
    EXPECT_EQ(expect, printHttpRequestProcess.readSendDocBufMap.size());
}

/**
 * @tc.name: PrintHttpRequestProcessTest_009
 * @tc.desc: Verify the RecordBufByOperation function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_009, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    size_t requestId = 1;
    std::string tempStr = HTTP_RESP_OK;
    tempStr += HTTP_RESP_CONNECTION;
    tempStr += HTTP_RESP_DATE;
    tempStr += HTTP_RESP_CACHE_CONTROL;
    tempStr += HTTP_RESP_SERVER;
    tempStr += HTTP_RESP_CONTENT_TYPE;
    tempStr += HTTP_RESP_CONTENT_LENGTH;
    tempStr += HTTP_MSG_STRING_R_AND_N;
    tempStr += HTTP_RESP_IPP;
    tempStr += HTTP_RESP_DATA;
    std::vector<uint8_t> tmVector;
    tmVector.assign(tempStr.begin(), tempStr.end());
    size_t expect = 1;
    printHttpRequestProcess.readSendDocBufMap[requestId] = tmVector;
    printHttpRequestProcess.RecordBufByOperation(Operation::Send_Document, requestId, tmVector);
    EXPECT_EQ(expect, printHttpRequestProcess.readSendDocBufMap.size());
}

/**
 * @tc.name: PrintHttpRequestProcessTest_010
 * @tc.desc: Verify the RecordBufByOperation function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_010, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    size_t requestId = 1;
    std::string tempStr = HTTP_RESP_OK;
    tempStr += HTTP_RESP_CONNECTION;
    tempStr += HTTP_RESP_DATE;
    tempStr += HTTP_RESP_CACHE_CONTROL;
    tempStr += HTTP_RESP_SERVER;
    tempStr += HTTP_RESP_CONTENT_TYPE;
    tempStr += HTTP_RESP_CONTENT_LENGTH;
    tempStr += HTTP_MSG_STRING_R_AND_N;
    tempStr += HTTP_RESP_IPP;
    tempStr += HTTP_RESP_DATA;
    std::vector<uint8_t> tmVector;
    tmVector.assign(tempStr.begin(), tempStr.end());
    size_t expect = 1;
    printHttpRequestProcess.RecordBufByOperation(Operation::Common, requestId, tmVector);
    EXPECT_EQ(expect, printHttpRequestProcess.readBufMap.size());
}

/**
 * @tc.name: PrintHttpRequestProcessTest_011
 * @tc.desc: Verify the RecordBufByOperation function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_011, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    size_t requestId = 1;
    std::string tempStr = HTTP_RESP_OK;
    tempStr += HTTP_RESP_CONNECTION;
    tempStr += HTTP_RESP_DATE;
    tempStr += HTTP_RESP_CACHE_CONTROL;
    tempStr += HTTP_RESP_SERVER;
    tempStr += HTTP_RESP_CONTENT_TYPE;
    tempStr += HTTP_RESP_CONTENT_LENGTH;
    tempStr += HTTP_MSG_STRING_R_AND_N;
    tempStr += HTTP_RESP_IPP;
    tempStr += HTTP_RESP_DATA;
    std::vector<uint8_t> tmVector;
    tmVector.assign(tempStr.begin(), tempStr.end());
    size_t expect = 1;
    printHttpRequestProcess.readBufMap[requestId] = tmVector;
    printHttpRequestProcess.RecordBufByOperation(Operation::Common, requestId, tmVector);
    EXPECT_EQ(expect, printHttpRequestProcess.readBufMap.size());
}

/**
 * @tc.name: PrintHttpRequestProcessTest_012
 * @tc.desc: Verify the GetContentLength function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_012, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string tempStr = HTTP_RESP_OK;
    tempStr += HTTP_RESP_CONNECTION;
    tempStr += HTTP_RESP_DATE;
    tempStr += HTTP_RESP_CACHE_CONTROL;
    tempStr += HTTP_RESP_SERVER;
    tempStr += HTTP_RESP_CONTENT_TYPE;
    tempStr += HTTP_RESP_CONTENT_LENGTH;
    tempStr += HTTP_MSG_STRING_R_AND_N;
    tempStr += HTTP_RESP_IPP;
    tempStr += HTTP_RESP_DATA;
    size_t index = 0;
    bool findContentLength = false;
    size_t contentLength = 0;
    std::vector<uint8_t> readTempBuffer;
    printHttpRequestProcess.GetContentLength(readTempBuffer, index, findContentLength, contentLength);
    EXPECT_EQ(contentLength, 0);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_013
 * @tc.desc: Verify the GetContentLength function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_013, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string tempStr = HTTP_RESP_OK;
    tempStr += HTTP_RESP_CONNECTION;
    tempStr += HTTP_RESP_DATE;
    tempStr += HTTP_RESP_CACHE_CONTROL;
    tempStr += HTTP_RESP_SERVER;
    tempStr += HTTP_RESP_CONTENT_TYPE;
    tempStr += HTTP_RESP_CONTENT_LENGTH;
    tempStr += HTTP_MSG_STRING_R_AND_N;
    tempStr += HTTP_RESP_IPP;
    tempStr += HTTP_RESP_DATA;
    size_t index = 0;
    bool findContentLength = false;
    size_t contentLength = 0;
    std::vector<uint8_t> readTempBuffer;
    readTempBuffer.assign(tempStr.begin(), tempStr.end());
    printHttpRequestProcess.GetContentLength(readTempBuffer, index, findContentLength, contentLength);
    EXPECT_EQ(contentLength, 0);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_014
 * @tc.desc: Verify the GetContentLength function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_014, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string tempStr = HTTP_RESP_CONTENT_LENGTH;
    tempStr += HTTP_MSG_STRING_R_AND_N;
    tempStr += HTTP_RESP_IPP;
    tempStr += HTTP_RESP_DATA;
    size_t index = 0;
    bool findContentLength = false;
    size_t contentLength = 0;
    std::vector<uint8_t> readTempBuffer;
    readTempBuffer.assign(tempStr.begin(), tempStr.end());
    printHttpRequestProcess.GetContentLength(readTempBuffer, index, findContentLength, contentLength);
    EXPECT_EQ(contentLength, 11616);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_015
 * @tc.desc: Verify the DumpRespIdCode function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_015, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::vector<uint8_t> readTempBuffer;
    readTempBuffer.assign(HTTP_RESP_IPP.begin(), HTTP_RESP_IPP.end());
    size_t begin = 0;
    size_t maxSize = 30;
    printHttpRequestProcess.DumpRespIdCode(readTempBuffer, Operation::Get_Printer_Attributes, begin, maxSize);
    EXPECT_EQ(printHttpRequestProcess.PrintOperation(Operation::Get_Printer_Attributes), HTTP_OPERATION_GET_ATTR);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_016
 * @tc.desc: Verify the CheckLineEnd function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_016, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string tempStr = "\r\n\r\n";
    tempStr += HTTP_RESP_OK;
    tempStr += HTTP_RESP_CONNECTION;
    tempStr += HTTP_RESP_DATE;
    tempStr += HTTP_RESP_CACHE_CONTROL;
    tempStr += HTTP_RESP_SERVER;
    tempStr += HTTP_RESP_CONTENT_TYPE;
    tempStr += HTTP_RESP_CONTENT_LENGTH;
    tempStr += HTTP_MSG_STRING_R_AND_N;
    tempStr += HTTP_RESP_IPP;
    tempStr += HTTP_RESP_DATA;
    std::vector<uint8_t> readTempBuffer;
    readTempBuffer.assign(tempStr.begin(), tempStr.end());
    size_t index = 0;
    bool ret = printHttpRequestProcess.CheckLineEnd(readTempBuffer, index);
    EXPECT_EQ(true, ret);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_017
 * @tc.desc: Verify the CheckLineEnd function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_017, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string tempStr = "\r\n\r";
    tempStr += HTTP_RESP_OK;
    tempStr += HTTP_RESP_CONNECTION;
    tempStr += HTTP_RESP_DATE;
    tempStr += HTTP_RESP_CACHE_CONTROL;
    tempStr += HTTP_RESP_SERVER;
    tempStr += HTTP_RESP_CONTENT_TYPE;
    tempStr += HTTP_RESP_CONTENT_LENGTH;
    tempStr += HTTP_MSG_STRING_R_AND_N;
    tempStr += HTTP_RESP_IPP;
    tempStr += HTTP_RESP_DATA;
    std::vector<uint8_t> readTempBuffer;
    readTempBuffer.assign(tempStr.begin(), tempStr.end());
    size_t index = 0;
    bool ret = printHttpRequestProcess.CheckLineEnd(readTempBuffer, index);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_018
 * @tc.desc: Verify the CheckLineEnd function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_018, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string tempStr = "\r\n";
    tempStr += HTTP_RESP_OK;
    tempStr += HTTP_RESP_CONNECTION;
    tempStr += HTTP_RESP_DATE;
    tempStr += HTTP_RESP_CACHE_CONTROL;
    tempStr += HTTP_RESP_SERVER;
    tempStr += HTTP_RESP_CONTENT_TYPE;
    tempStr += HTTP_RESP_CONTENT_LENGTH;
    tempStr += HTTP_MSG_STRING_R_AND_N;
    tempStr += HTTP_RESP_IPP;
    tempStr += HTTP_RESP_DATA;
    std::vector<uint8_t> readTempBuffer;
    readTempBuffer.assign(tempStr.begin(), tempStr.end());
    size_t index = 0;
    bool ret = printHttpRequestProcess.CheckLineEnd(readTempBuffer, index);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_019
 * @tc.desc: Verify the CheckLineEnd function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_019, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string tempStr = "\r";
    tempStr += HTTP_RESP_OK;
    tempStr += HTTP_RESP_CONNECTION;
    tempStr += HTTP_RESP_DATE;
    tempStr += HTTP_RESP_CACHE_CONTROL;
    tempStr += HTTP_RESP_SERVER;
    tempStr += HTTP_RESP_CONTENT_TYPE;
    tempStr += HTTP_RESP_CONTENT_LENGTH;
    tempStr += HTTP_MSG_STRING_R_AND_N;
    tempStr += HTTP_RESP_IPP;
    tempStr += HTTP_RESP_DATA;
    std::vector<uint8_t> readTempBuffer;
    readTempBuffer.assign(tempStr.begin(), tempStr.end());
    size_t index = 0;
    bool ret = printHttpRequestProcess.CheckLineEnd(readTempBuffer, index);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_020
 * @tc.desc: Verify the CheckLineEnd function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_020, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string tempStr = HTTP_RESP_OK;
    tempStr += HTTP_RESP_CONNECTION;
    tempStr += HTTP_RESP_DATE;
    tempStr += HTTP_RESP_CACHE_CONTROL;
    tempStr += HTTP_RESP_SERVER;
    tempStr += HTTP_RESP_CONTENT_TYPE;
    tempStr += HTTP_RESP_CONTENT_LENGTH;
    tempStr += HTTP_MSG_STRING_R_AND_N;
    tempStr += HTTP_RESP_IPP;
    tempStr += HTTP_RESP_DATA;
    std::vector<uint8_t> readTempBuffer;
    readTempBuffer.assign(tempStr.begin(), tempStr.end());
    size_t index = 0;
    bool ret = printHttpRequestProcess.CheckLineEnd(readTempBuffer, index);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_021
 * @tc.desc: Verify the CheckLineEnd function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_021, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string tempStr = "HTTP/1.1";
    std::vector<uint8_t> readTempBuffer;
    readTempBuffer.assign(tempStr.begin(), tempStr.end());
    size_t index = 0;
    bool ret = printHttpRequestProcess.CheckLineEnd(readTempBuffer, index);
    EXPECT_EQ(false, ret);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_022
 * @tc.desc: Verify the CalculateRequestId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_022, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string tempStr = HTTP_MSG_STRING_R_AND_N;
    tempStr += HTTP_RESP_IPP;
    std::vector<uint8_t> readTempBuffer;
    readTempBuffer.assign(tempStr.begin(), tempStr.end());
    size_t index = 0;
    size_t ret = printHttpRequestProcess.CalculateRequestId(readTempBuffer, index, Operation::Get_Printer_Attributes);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_023
 * @tc.desc: Verify the CalculateFileDataBeginIndex function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_023, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    size_t index = 0;
    size_t ret = printHttpRequestProcess.CalculateFileDataBeginIndex(index, Operation::Get_Printer_Attributes);
    EXPECT_EQ(ret, index + INDEX_4);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_025
 * @tc.desc: Verify the ProcessDataFromDevice function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_025, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    bool ret = printHttpRequestProcess.ProcessDataFromDevice(Operation::Get_Printer_Attributes);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_026
 * @tc.desc: Verify the GetAttrAgain function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_026, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::vector<uint8_t> readTempBuffer;
    printHttpRequestProcess.GetAttrAgain(Operation::Get_Printer_Attributes, readTempBuffer);
    EXPECT_EQ(readTempBuffer, std::vector<uint8_t>{});
}

/**
 * @tc.name: PrintHttpRequestProcessTest_028
 * @tc.desc: Verify the ProcessHttpResponse function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_028, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    httplib::Response responseData;
    size_t requestId = 1;
    printHttpRequestProcess.ProcessHttpResponse(responseData, requestId);
    EXPECT_EQ(printHttpRequestProcess.needReadSendDoc, false);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_029
 * @tc.desc: Verify the ProcessHttpResponse function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_029, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    httplib::Response responseData;
    size_t requestId = 1;
    std::string tempStr = HTTP_RESP_OK;
    tempStr += HTTP_RESP_CONNECTION;
    tempStr += HTTP_RESP_DATE;
    tempStr += HTTP_RESP_CACHE_CONTROL;
    tempStr += HTTP_RESP_SERVER;
    tempStr += HTTP_RESP_CONTENT_TYPE;
    tempStr += HTTP_RESP_CONTENT_LENGTH;
    tempStr += HTTP_MSG_STRING_R_AND_N;
    tempStr += HTTP_RESP_IPP;
    tempStr += HTTP_RESP_DATA;
    std::vector<uint8_t> readTempBuffer;
    readTempBuffer.assign(tempStr.begin(), tempStr.end());
    printHttpRequestProcess.readBufMap[requestId] = readTempBuffer;
    printHttpRequestProcess.ProcessHttpResponse(responseData, requestId);
    EXPECT_EQ(printHttpRequestProcess.needReadSendDoc, false);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_030
 * @tc.desc: Verify the ProcessHttpResponseGetAttr function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_030, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    httplib::Response responseData;
    size_t requestId = 1;
    printHttpRequestProcess.ProcessHttpResponseGetAttr(responseData, requestId);
    EXPECT_EQ(requestId, 1);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_031
 * @tc.desc: Verify the ProcessHttpResponseGetAttr function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_031, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    httplib::Response responseData;
    size_t requestId = 1;
    std::string tempStr = HTTP_RESP_OK;
    tempStr += HTTP_RESP_CONNECTION;
    tempStr += HTTP_RESP_DATE;
    tempStr += HTTP_RESP_CACHE_CONTROL;
    tempStr += HTTP_RESP_SERVER;
    tempStr += HTTP_RESP_CONTENT_TYPE;
    tempStr += HTTP_RESP_CONTENT_LENGTH;
    tempStr += HTTP_MSG_STRING_R_AND_N;
    tempStr += HTTP_RESP_IPP;
    tempStr += HTTP_RESP_DATA;
    std::vector<uint8_t> readTempBuffer;
    readTempBuffer.assign(tempStr.begin(), tempStr.end());
    printHttpRequestProcess.readGetAttrBufMap[requestId] = readTempBuffer;
    printHttpRequestProcess.ProcessHttpResponseGetAttr(responseData, requestId);
    EXPECT_EQ(requestId, 1);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_032
 * @tc.desc: Verify the ProcessHttpResponseSendDoc function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_032, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    httplib::Response responseData;
    size_t requestId = 1;
    printHttpRequestProcess.ProcessHttpResponseSendDoc(responseData, requestId);
    EXPECT_EQ(printHttpRequestProcess.needReadSendDoc, false);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_033
 * @tc.desc: Verify the ProcessHttpResponseSendDoc function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_033, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    httplib::Response responseData;
    size_t requestId = 1;
    std::string tempStr = HTTP_RESP_OK;
    tempStr += HTTP_RESP_CONNECTION;
    tempStr += HTTP_RESP_DATE;
    tempStr += HTTP_RESP_CACHE_CONTROL;
    tempStr += HTTP_RESP_SERVER;
    tempStr += HTTP_RESP_CONTENT_TYPE;
    tempStr += HTTP_RESP_CONTENT_LENGTH;
    tempStr += HTTP_MSG_STRING_R_AND_N;
    tempStr += HTTP_RESP_IPP;
    tempStr += HTTP_RESP_DATA;
    std::vector<uint8_t> readTempBuffer;
    readTempBuffer.assign(tempStr.begin(), tempStr.end());
    printHttpRequestProcess.readSendDocBufMap[requestId] = readTempBuffer;
    printHttpRequestProcess.ProcessHttpResponseSendDoc(responseData, requestId);
    EXPECT_EQ(printHttpRequestProcess.needReadSendDoc, false);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_034
 * @tc.desc: Verify the DealRequestHeader function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_034, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    httplib::Request requestData;
    requestData.set_header("Content-Length", "745");
    requestData.set_header("Content-Type", "application/ipp");
    requestData.set_header("Expect", "100-continue");
    requestData.set_header("Host", "localhost:60000");
    requestData.set_header("LOCAL_ADDR", "127.0.0.1");
    requestData.set_header("LOCAL_PORT", "60000");
    requestData.set_header("REMOTE_ADDR", "127.0.0.1");
    requestData.set_header("REMOTE_PORT", "39470");
    requestData.set_header("User-Agent", "CUPS/2.4.0 (Linux 5.10.97+; aarch64) IPP/2.0");
    std::string str = "";
    bool ret = printHttpRequestProcess.DealRequestHeader(requestData, str);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_035
 * @tc.desc: Verify the DealRequestHeader function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_035, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    httplib::Request requestData;
    requestData.set_header("Content-Length", "745");
    requestData.set_header("Content-Type", "application/ipp");
    requestData.set_header("Transfer-Encoding", "chunked");
    requestData.set_header("Host", "localhost:60000");
    requestData.set_header("LOCAL_ADDR", "127.0.0.1");
    requestData.set_header("LOCAL_PORT", "60000");
    requestData.set_header("REMOTE_ADDR", "127.0.0.1");
    requestData.set_header("REMOTE_PORT", "39470");
    requestData.set_header("User-Agent", "CUPS/2.4.0 (Linux 5.10.97+; aarch64) IPP/2.0");
    std::string str = "";
    bool ret = printHttpRequestProcess.DealRequestHeader(requestData, str);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_036
 * @tc.desc: Verify the CalcReqIdOperaId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_036, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    httplib::Response responseData;
    size_t requestId = 0;
    std::string reqData = HTTP_REQ_DATA;
    size_t data_length = 716;
    printHttpRequestProcess.CalcReqIdOperaId(reqData.c_str(), data_length, requestId);

    const char *data = reqData.c_str();
    size_t expectedRequestId = (uint8_t)(*(data + INDEX_4)) * HTTP_COMMON_CONST_VALUE_1000 +
        (uint8_t)(*(data + INDEX_5)) * HTTP_COMMON_CONST_VALUE_100 +
            (uint8_t)(*(data + INDEX_6)) * HTTP_COMMON_CONST_VALUE_10 + (uint8_t)(*(data + INDEX_7));
    EXPECT_EQ(requestId, expectedRequestId);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_037
 * @tc.desc: Verify the CalcReqIdOperaId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_037, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    httplib::Response responseData;
    size_t requestId = 0;
    std::string reqData = HTTP_REQ_DATA;
    size_t data_length = 1;
    printHttpRequestProcess.CalcReqIdOperaId(reqData.c_str(), data_length, requestId);
    EXPECT_EQ(printHttpRequestProcess.needWriteData, false);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_038
 * @tc.desc: Verify the CreatWriteDataTask function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_038, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    printHttpRequestProcess.needWriteData = false;
    printHttpRequestProcess.CreatWriteDataTask();
    EXPECT_EQ(printHttpRequestProcess.needWriteData, true);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_040
 * @tc.desc: Verify the ProcessOtherRequest function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_040, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    const char *data = "test";
    size_t data_length = 4;
    std::string sHeadersAndBody = "";
    size_t requestId = 0;
    printHttpRequestProcess.needWriteData = true;
    printHttpRequestProcess.ProcessOtherRequest(data, data_length, sHeadersAndBody, requestId);
    EXPECT_STREQ(data, "test");
}

/**
 * @tc.name: PrintHttpRequestProcessTest_041
 * @tc.desc: Verify the DumpReqIdOperaId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_041, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string reqData = "t";
    size_t data_length = 1;
    EXPECT_LT(data_length, REQID_OPERAID_LEN);
    printHttpRequestProcess.DumpReqIdOperaId(reqData.c_str(), data_length);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_042
 * @tc.desc: Verify the DumpReqIdOperaId function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_042, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string reqData = "test request data";
    size_t data_length = 15;
    EXPECT_GT(data_length, REQID_OPERAID_LEN);
    printHttpRequestProcess.DumpReqIdOperaId(reqData.c_str(), data_length);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_044
 * @tc.desc: Verify the CreatReadSendDocTask function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_044, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    printHttpRequestProcess.needReadSendDoc = true;
    printHttpRequestProcess.CreatReadSendDocTask();
    EXPECT_EQ(true, printHttpRequestProcess.needReadSendDoc);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_045
 * @tc.desc: Verify the CreateChunk function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_045, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string reqData = HTTP_REQ_DATA;
    size_t data_length = 721;
    std::string ret = printHttpRequestProcess.CreateChunk(reqData.c_str(), data_length);
    EXPECT_EQ(ret, "2d1\r\n\\x02\\x00\\x00\\x0b\\x00\\x00\\x00\\x01\\x01G\\x00\\"
                "x12attributes-charset\\x00\\x05utf-8H\\x00\\x1battributes-natural-language\\x00\\"
                "x05en-usE\\x00\\x0bprinter-uri\\x00!ipp://192.168.186.1:631/ipp/printD\\x00\\"
                "x14requested-attributes\\x00\\x15compression-supportedD\\x00\\x00\\x00\\"
                "x10copies-supportedD\\x00\\x00\\x00\\x0ccups-versionD\\x00\\x00\\x00\\"
                "x19document-format-supportedD\\x00\\x00\\x00!job-password-encryption-supportedD\\"
                "x00\\x00\\x00\\x0dmarker-colorsD\\x00\\x00\\x00\\x12marker-high-levelsD\\x00\\x00\\"
                "x00\\x0dmarker-levelsD\\x00\\x00\\x00\\x11marker-low-levelsD\\x00\\x00\\x00\\"
                "x0emarker-messageD\\x00\\x00\\x00\\x0cmarker-namesD\\x00\\x00\\x00\\x0cmarker-typesD\\"
                "x00\\x00\\x00\\x13media-col-supportedD\\x00\\x00\\x00$multiple-document-handling-supportedD\\"
                "x00\\x00\\x00\\x14operatio\r\n");
}

/**
 * @tc.name: PrintHttpRequestProcessTest_046
 * @tc.desc: Verify the WriteDataSync function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_046, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string sHeadersAndBody = "test";
    auto ret = printHttpRequestProcess.WriteDataSync(sHeadersAndBody);
    EXPECT_EQ(INVAILD_VALUE, ret);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_047
 * @tc.desc: Verify the WriteDataSync function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_047, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string sHeadersAndBody = "";
    auto ret = printHttpRequestProcess.WriteDataSync(sHeadersAndBody);
    EXPECT_EQ(0, ret);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_048
 * @tc.desc: Verify the BulkTransferWriteData function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_048, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string name = "usb";
    printHttpRequestProcess.SetDeviceName(name);
    std::string reqData = HTTP_REQ_DATA;
    size_t data_length = 716;
    httplib::Request requestData;
    requestData.set_header("Content-Length", "745");
    requestData.set_header("Content-Type", "application/ipp");
    requestData.set_header("Expect", "100-continue");
    requestData.set_header("Host", "localhost:60000");
    requestData.set_header("LOCAL_ADDR", "127.0.0.1");
    requestData.set_header("LOCAL_PORT", "60000");
    requestData.set_header("REMOTE_ADDR", "127.0.0.1");
    requestData.set_header("REMOTE_PORT", "39470");
    requestData.set_header("User-Agent", "CUPS/2.4.0 (Linux 5.10.97+; aarch64) IPP/2.0");
    std::string sHeadersAndBody = "";
    printHttpRequestProcess.DealRequestHeader(requestData, sHeadersAndBody);
    sHeadersAndBody += printHttpRequestProcess.CreateChunk(reqData.c_str(), data_length);
    auto ret = printHttpRequestProcess.BulkTransferWriteData(sHeadersAndBody);
    EXPECT_EQ(INVAILD_VALUE, ret);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_049
 * @tc.desc: Verify the ProcessHttpResp function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_049, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    size_t requestId = 1;
    httplib::Response responseData;
    printHttpRequestProcess.reqIdOperaIdMap[requestId] = HTTP_REQUEST_GET_ATTR;
    std::string sHeadersAndBody = "";
    printHttpRequestProcess.ProcessHttpResp(requestId, responseData, sHeadersAndBody);
    EXPECT_EQ(printHttpRequestProcess.needReadSendDoc, false);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_050
 * @tc.desc: Verify the ProcessHttpResp function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_050, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    size_t requestId = 1;
    httplib::Response responseData;
    printHttpRequestProcess.reqIdOperaIdMap[requestId] = HTTP_REQUEST_SEND_DOC;
    printHttpRequestProcess.deviceOpen = false;
    std::string sHeadersAndBody = "";
    printHttpRequestProcess.ProcessHttpResp(requestId, responseData, sHeadersAndBody);
    EXPECT_EQ(printHttpRequestProcess.needReadSendDoc, false);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_051
 * @tc.desc: Verify the ProcessHttpResp function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_051, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    size_t requestId = 1;
    httplib::Response responseData;
    printHttpRequestProcess.reqIdOperaIdMap[requestId] = HTTP_REQUEST_SEND_DOC;
    printHttpRequestProcess.deviceOpen = true;
    std::string sHeadersAndBody = "";
    printHttpRequestProcess.ProcessHttpResp(requestId, responseData, sHeadersAndBody);
    EXPECT_EQ(printHttpRequestProcess.needReadSendDoc, false);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_052
 * @tc.desc: Verify the ProcessHttpResp function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_052, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    size_t requestId = 1;
    httplib::Response responseData;
    int testOperationId = 10;
    printHttpRequestProcess.reqIdOperaIdMap[requestId] = testOperationId;
    std::string sHeadersAndBody = "";
    printHttpRequestProcess.ProcessHttpResp(requestId, responseData, sHeadersAndBody);
    EXPECT_EQ(printHttpRequestProcess.needReadSendDoc, false);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_053
 * @tc.desc: Verify the SetDeviceName function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_053, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    std::string name = "usb";
    printHttpRequestProcess.SetDeviceName(name);
    EXPECT_EQ("usb", printHttpRequestProcess.GetDeviceName());
}

/**
 * @tc.name: PrintHttpRequestProcessTest_054
 * @tc.desc: Verify the Stop function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_054, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    printHttpRequestProcess.Stop();
    EXPECT_EQ(false, printHttpRequestProcess.needWriteData);
    EXPECT_EQ(false, printHttpRequestProcess.needReadSendDoc);
    EXPECT_EQ(false, printHttpRequestProcess.needWriteSendDoc);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_055
 * @tc.desc: Verify the ProcessDataFromDevice function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_055, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    printHttpRequestProcess.StartWriteDataToPrinterLooper();
    EXPECT_EQ(printHttpRequestProcess.needReadSendDoc, false);
}

/**
 * @tc.name: PrintHttpRequestProcessTest_056
 * @tc.desc: Verify the ProcessDataFromDevice function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrintHttpRequestProcessTest, PrintHttpRequestProcessTest_056, TestSize.Level1)
{
    OHOS::Print::PrintHttpRequestProcess printHttpRequestProcess;
    printHttpRequestProcess.StartReadSendDocDataFromPrinterLooper();
    EXPECT_EQ(printHttpRequestProcess.needReadSendDoc, false);
}

}  // namespace Print
}  // namespace OHOS

#endif // IPPOVERUSB_ENABLE