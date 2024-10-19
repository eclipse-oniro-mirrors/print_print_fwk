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

#ifdef IPPOVERUSB_ENABLE
#include "print_http_request_process.h"
#include <cmath>
#include "print_log.h"
#include "print_ipp_over_usb_util.h"
#include "usb_errors.h"

namespace OHOS::Print {
using namespace std;
using namespace OHOS;
using namespace OHOS::USB;
using namespace httplib;

PrintHttpRequestProcess::PrintHttpRequestProcess()
{}

PrintHttpRequestProcess::~PrintHttpRequestProcess()
{}

std::string PrintHttpRequestProcess::PrintOperation(Operation operation)
{
    if (operation == Operation::Get_Printer_Attributes) {
        return HTTP_OPERATION_GET_ATTR;
    } else if (operation == Operation::Send_Document) {
        return HTTP_OPERATION_SEND_DOC;
    } else {
        return HTTP_OPERATION_COMMON;
    }
}

size_t PrintHttpRequestProcess::NeedOffset(const std::vector<uint8_t> &readTempBuffer)
{
    size_t readSize = readTempBuffer.size();
    size_t reqindex = 0;
    bool checkNeedOffset = (readSize > HTTP_COMMON_CONST_VALUE_25 && readTempBuffer[INDEX_0] == HTTP_RESPONSE_H &&
        readTempBuffer[INDEX_1] == HTTP_RESPONSE_T && readTempBuffer[INDEX_2] == HTTP_RESPONSE_T &&
        readTempBuffer[INDEX_3] == HTTP_RESPONSE_P &&
        readTempBuffer[INDEX_4] == HTTP_RESPONSE_VERSION_SPLIT_GANG &&
        readTempBuffer[INDEX_5] == HTTP_MSG_CHAR_1 &&
        readTempBuffer[INDEX_6] == HTTP_MSG_CHAR_2E &&
        readTempBuffer[INDEX_7] == HTTP_MSG_CHAR_1 &&
        readTempBuffer[INDEX_8] == HTTP_MSG_CHAR_20 &&
        readTempBuffer[INDEX_9] == HTTP_MSG_CHAR_1 &&
        readTempBuffer[INDEX_10] == HTTP_MSG_CHAR_0 &&
        readTempBuffer[INDEX_11] == HTTP_MSG_CHAR_0);
    if (checkNeedOffset) {
        PRINT_HILOGD("include HTTP/1.1 100");
        reqindex = HTTP_COMMON_CONST_VALUE_25;
    }
    return reqindex;
}

void PrintHttpRequestProcess::RecordBufByOperation(Operation operation, size_t requestId,
    const std::vector<uint8_t> &tmVector)
{
    if (operation == Operation::Send_Document) {
        std::lock_guard<std::mutex> mtx_locker(mutexSendDoc);
        if (readSendDocBufMap.find(requestId) == readSendDocBufMap.end()) {
            readSendDocBufMap[requestId] = tmVector;
        }
    } else {
        if (reqIdOperaIdMap[requestId] == HTTP_REQUEST_GET_ATTR)  {
            std::lock_guard<std::mutex> mtx_locker(mutexGetAttr);
            if (readGetAttrBufMap.find(requestId) == readGetAttrBufMap.end()) {
                readGetAttrBufMap[requestId] = tmVector;
            }
        } else {
            std::lock_guard<std::mutex> mtx_locker(mutexCommon);
            if (readBufMap.find(requestId) == readBufMap.end()) {
                readBufMap[requestId] = tmVector;
            }
        }
    }
}

void PrintHttpRequestProcess::GetContentLength(const std::vector<uint8_t> &readTempBuffer, size_t index,
    bool &findContentLength, size_t &contentLength)
{
    size_t readSize = readTempBuffer.size();
    if ((index + HTTP_COMMON_CONST_VALUE_14) < readSize) {
        std::string tmpStr = "";
        for (size_t offset = 0; offset < HTTP_COMMON_CONST_VALUE_14; offset++) {
            tmpStr += readTempBuffer[index + offset];
        }
        if (tmpStr == HTTP_CONTENT_LENGTH) {
            findContentLength = true;
            std::string lenStr = "";
            size_t lenIndex = index + HTTP_COMMON_CONST_VALUE_14 + HTTP_COMMON_CONST_VALUE_2;
            while (lenIndex < readSize - 1 && (!(readTempBuffer[lenIndex] == HTTP_SPLIT_R_CODE &&
                                                  readTempBuffer[lenIndex + INDEX_1] == HTTP_SPLIT_N_CODE))) {
                lenStr += readTempBuffer[lenIndex];
                lenIndex++;
            }
            try {
                contentLength = static_cast<size_t>(std::stoi(lenStr));
            } catch (std::invalid_argument &e) {
                PRINT_HILOGE("invalid_argument error: %s", e.what());
            } catch (std::out_of_range &e) {
                PRINT_HILOGE("out_of_range error: %s", e.what());
            }
            PRINT_HILOGD("contentLength = %{public}s,  %{public}lu", lenStr.c_str(), contentLength);
        }
    }
}

void PrintHttpRequestProcess::DumpRespIdCode(const std::vector<uint8_t> &readTempBuffer,
    Operation operation, size_t begin, size_t maxSize)
{
    for (size_t i = begin; i < (begin + HTTP_COMMON_CONST_VALUE_8) && i < maxSize; i++) {
        PRINT_HILOGD("operation:%{public}s, readTempBuffer: %{public}x",
            PrintOperation(operation).c_str(), readTempBuffer[i]);
    }
}

bool PrintHttpRequestProcess::CheckLineEnd(std::vector<uint8_t> &readTempBuffer, size_t index)
{
    size_t readSize = readTempBuffer.size();
    if ((index + HTTP_COMMON_CONST_VALUE_3) < readSize && readTempBuffer[index] == HTTP_SPLIT_R_CODE &&
        readTempBuffer[index + INDEX_1] == HTTP_SPLIT_N_CODE && readTempBuffer[index + INDEX_2] == HTTP_SPLIT_R_CODE &&
        readTempBuffer[index + INDEX_3] == HTTP_SPLIT_N_CODE) {
        return true;
    }
    return false;
}

size_t PrintHttpRequestProcess::CalculateRequestId(
    std::vector<uint8_t> &readTempBuffer, size_t index, Operation operation)
{
    size_t readSize = readTempBuffer.size();
    if ((index + HTTP_COMMON_CONST_VALUE_8) < readSize &&
        (index + HTTP_COMMON_CONST_VALUE_9) < readSize &&
        (index + HTTP_COMMON_CONST_VALUE_10) < readSize &&
        (index + HTTP_COMMON_CONST_VALUE_11) < readSize) {
        DumpRespIdCode(readTempBuffer, operation, index + HTTP_COMMON_CONST_VALUE_4, readSize);
        return readTempBuffer[index + HTTP_COMMON_CONST_VALUE_8] *
                pow(HTTP_COMMON_CONST_VALUE_10, HTTP_COMMON_CONST_VALUE_3) +
            readTempBuffer[index + HTTP_COMMON_CONST_VALUE_9] *
                pow(HTTP_COMMON_CONST_VALUE_10, HTTP_COMMON_CONST_VALUE_2) +
            readTempBuffer[index + HTTP_COMMON_CONST_VALUE_10] * HTTP_COMMON_CONST_VALUE_10 +
            readTempBuffer[index + HTTP_COMMON_CONST_VALUE_11];
    }
    PRINT_HILOGE("Invalid index");
    return 0;
}

size_t PrintHttpRequestProcess::CalculateFileDataBeginIndex(size_t index, Operation operation)
{
    size_t fileDataBeginIndex = index + INDEX_4;
    PRINT_HILOGD("operation:%{public}s, fileDataBeginIndex = %{public}lu",
        PrintOperation(operation).c_str(), fileDataBeginIndex);
    return fileDataBeginIndex;
}

bool PrintHttpRequestProcess::ProcessDataFromDevice(Operation operation)
{
    std::vector<uint8_t> readTempBuffer;
    int32_t readFromUsbRes =
        DelayedSingleton<PrintUsbManager>::GetInstance()->BulkTransferRead(devName, operation, readTempBuffer);
    if (readFromUsbRes == EORROR_HDF_DEV_ERR_NO_DEVICE) {
        PRINT_HILOGE("HDF_DEV_ERR_NO_DEVICE, The device module has no device");
        deviceOpen = false;
        return true;
    }
    size_t readSize = readTempBuffer.size();
    if (readSize > 0 && readFromUsbRes == UEC_OK) {
        PRINT_HILOGD("operation:%{public}s, readSize = %{public}lu", PrintOperation(operation).c_str(), readSize);
        size_t reqindex = NeedOffset(readTempBuffer);
        size_t requestId = 0;
        std::vector<uint8_t> tmVector;
        bool findRequestId = false;
        bool findContentLength = false;
        size_t contentLength = 0;
        size_t fileDataBeginIndex = 0;
        // 解析出报文中的RequestId 和 Content-Length
        for (size_t index = reqindex; index < readSize; index++) {
            bool findLineEnd = (!findRequestId && CheckLineEnd(readTempBuffer, index));
            if (findLineEnd) {
                fileDataBeginIndex = CalculateFileDataBeginIndex(index, operation);
                findRequestId = true;
            }
            if (!findContentLength) {
                GetContentLength(readTempBuffer, index, findContentLength, contentLength);
            }
            tmVector.push_back(readTempBuffer[index]);
        }
        int count = 0;
        int maxCount = 50;
        // 一次读取的报文长度小于 Content-Length字段的值则需再读取一次
        while (tmVector.size() < readSize + contentLength && count < maxCount) {
            GetAttrAgain(operation, tmVector);
            count++;
        }
        if (fileDataBeginIndex > HTTP_COMMON_CONST_VALUE_4) {
            requestId = CalculateRequestId(tmVector, fileDataBeginIndex - HTTP_COMMON_CONST_VALUE_4, operation);
        }
        PRINT_HILOGD("operation:%{public}s requestId: %{public}lu ", PrintOperation(operation).c_str(), requestId);
        RecordBufByOperation(operation, requestId, tmVector);
        return true;
    }
    return false;
}

void PrintHttpRequestProcess::GetAttrAgain(Operation operation, std::vector<uint8_t> &tmVector)
{
    PRINT_HILOGD("GetAttr again");
    std::vector<uint8_t> readBuffer;
    int32_t readFromUsbRes =
        DelayedSingleton<PrintUsbManager>::GetInstance()->BulkTransferRead(devName, operation, readBuffer);
    size_t readSize = readBuffer.size();
    if (readSize > 0 && readFromUsbRes == UEC_OK) {
        PRINT_HILOGD("GetAttr again readSize = %{public}lu", readSize);
        for (size_t index = 0; index < readSize; index++) {
            tmVector.push_back(readBuffer[index]);
        }
    }
}

void PrintHttpRequestProcess::StartReadSendDocDataFromPrinterLooper()
{
    PRINT_HILOGD("StartReadSendDocDataFromPrinterLooper");
    while (deviceOpen && needReadSendDoc) {
        if (ProcessDataFromDevice(Operation::Send_Document)) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(USB_READ_INTERVAL));
    }
    PRINT_HILOGD("EndReadSendDocDataFromPrinterLooper");
}

void PrintHttpRequestProcess::ProcessHttpResponse(httplib::Response &responseData, size_t requestId)
{
    PRINT_HILOGD("processHttpResponse enter");
    int retryCount = 0;
    // cups timeout is 30 seconds
    while (retryCount < RESPONSE_RETRY_MAX_TIMES && deviceOpen) {
        std::this_thread::sleep_for(std::chrono::milliseconds(RESPONSE_RETRY_INTERVAL));
        retryCount++;
        std::lock_guard<std::mutex> mtx_locker(mutexCommon);
        if (readBufMap.find(requestId) != readBufMap.end()) {
            size_t totalSize = readBufMap[requestId].size();
            PRINT_HILOGD("Response totalSize:%{public}lu, retryCout = %{public}d", totalSize, retryCount);
            PrintIppOverUsbUtil::ConstructHttpResponse(&readBufMap[requestId][0], totalSize, responseData);
            readBufMap.erase(requestId);
            break;
        } else {
            continue;
        }
    }
    // 超时错误
    if (retryCount >= RESPONSE_RETRY_MAX_TIMES) {
        PRINT_HILOGE("process_http_response time out retryCout: %{public}d", retryCount);
    }
    PRINT_HILOGD("process_http_response out");
}

void PrintHttpRequestProcess::ProcessHttpResponseGetAttr(httplib::Response &responseData, size_t requestId)
{
    PRINT_HILOGD("processHttpResponseGetAttr enter");
    int retryCount = 0;
    while (retryCount < RESPONSE_RETRY_MAX_TIMES && deviceOpen) {
        std::this_thread::sleep_for(std::chrono::milliseconds(RESPONSE_RETRY_INTERVAL));
        retryCount++;
        std::lock_guard<std::mutex> mtx_locker(mutexGetAttr);
        if (readGetAttrBufMap.find(requestId) != readGetAttrBufMap.end()) {
            size_t totalSize = readGetAttrBufMap[requestId].size();
            PRINT_HILOGD("Response GetAttr totalSize:%{public}lu, retryCout = %{public}d", totalSize, retryCount);
            PrintIppOverUsbUtil::ConstructHttpResponse(&readGetAttrBufMap[requestId][0], totalSize, responseData);
            readGetAttrBufMap.erase(requestId);
            break;
        } else {
            continue;
        }
    }
    // 超时错误
    if (retryCount >= RESPONSE_RETRY_MAX_TIMES) {
        PRINT_HILOGE("process_http_response_get_attr time out retryCout: %{public}d", retryCount);
    }
    PRINT_HILOGD("process_http_response_get_attr out");
}

void PrintHttpRequestProcess::ProcessHttpResponseSendDoc(httplib::Response &responseData, size_t requestId)
{
    PRINT_HILOGD("ProcessHttpResponseSendDoc enter");
    int retryCount = 0;
    while (retryCount < RESPONSE_RETRY_MAX_TIMES && deviceOpen) {
        std::this_thread::sleep_for(std::chrono::milliseconds(RESPONSE_RETRY_INTERVAL));
        retryCount++;
        std::lock_guard<std::mutex> mtx_locker(mutexSendDoc);
        if (readSendDocBufMap.find(requestId) != readSendDocBufMap.end()) {
            size_t totalSize = readSendDocBufMap[requestId].size();
            PRINT_HILOGD("Response SendDoc totalSize:%{public}lu, retryCout = %{public}d", totalSize, retryCount);
            PrintIppOverUsbUtil::ConstructHttpResponse(&readSendDocBufMap[requestId][0], totalSize, responseData);
            readSendDocBufMap.erase(requestId);
            break;
        } else {
            continue;
        }
    }
    // 超时错误
    if (retryCount >= RESPONSE_RETRY_MAX_TIMES) {
        PRINT_HILOGE("ProcessHttpResponseSendDoc time out retryCout: %{public}d", retryCount);
        needReadSendDoc = false;
    }
    PRINT_HILOGD("ProcessHttpResponseSendDoc out");
}

bool PrintHttpRequestProcess::DealRequestHeader(const httplib::Request &requestData, std::string &sHeadersAndBody)
{
    bool ischunked = false;
    for (const auto &x : requestData.headers) {
        PRINT_HILOGD("requestData.headers first: %{public}s, second : %{public}s", x.first.c_str(), x.second.c_str());
        if (x.first == HTTP_TRANSFER_ENCODING && x.second == HTTP_CHUNKED) {
            ischunked = true;
        }
        if (x.first == HTTP_EXPECT) {
            continue;
        }
        sHeadersAndBody += x.first;
        sHeadersAndBody += SPLIT_VALUE_COLON;
        sHeadersAndBody += x.second;
        sHeadersAndBody += HTTP_MSG_STRING_R_AND_N;
    }
    sHeadersAndBody += HTTP_MSG_STRING_R_AND_N;
    return ischunked;
}

void PrintHttpRequestProcess::CalcReqIdOperaId(const char *data, size_t dataLength, size_t &requestId)
{
    if (data == nullptr) {
        return;
    }
    if (dataLength < HTTP_COMMON_CONST_VALUE_8) {
        return;
    }
    DumpReqIdOperaId(data, dataLength);
    size_t operationId = (uint8_t)(*(data + INDEX_2)) * HTTP_COMMON_CONST_VALUE_10 + (uint8_t)(*(data + INDEX_3));
    requestId = (uint8_t)(*(data + INDEX_4)) * HTTP_COMMON_CONST_VALUE_1000 +
        (uint8_t)(*(data + INDEX_5)) * HTTP_COMMON_CONST_VALUE_100 +
         (uint8_t)(*(data + INDEX_6)) * HTTP_COMMON_CONST_VALUE_10 + (uint8_t)(*(data + INDEX_7));
    reqIdOperaIdMap[requestId] = operationId;
}

void PrintHttpRequestProcess::StartWriteDataToPrinterLooper()
{
    PRINT_HILOGD("StartWriteDataToPrinterLooper");
    std::vector<uint8_t> vectorRequestBuffer;
    while (deviceOpen && needWriteData) {
        std::string str = "";
        if (!ippDataQue.pop(str)) {
            continue;
        }

        vectorRequestBuffer.assign(str.begin(), str.end());
        int32_t ret = 0;
        int32_t writeDataRetryCount = 0;
        do {
            ret = DelayedSingleton<PrintUsbManager>::GetInstance()->BulkTransferWrite(
                devName, Operation::Common, vectorRequestBuffer);
            PRINT_HILOGD("writeBody ret: %{public}d", ret);
            if (ret == EORROR_HDF_DEV_ERR_TIME_OUT) {
                std::this_thread::sleep_for(std::chrono::milliseconds(USB_WRITE_INTERVAL));
                writeDataRetryCount++;
                PRINT_HILOGE(
                    "StartWriteDataToPrinterLooper, retrwriteDataRetryCounty = %{public}d", writeDataRetryCount);
            }
        } while (ret == EORROR_HDF_DEV_ERR_TIME_OUT && writeDataRetryCount < WRITE_RETRY_MAX_TIMES);

        if (ret == EORROR_HDF_DEV_ERR_NO_DEVICE) {
            PRINT_HILOGE("WriteData HDF_DEV_ERR_NO_DEVICE, The device module has no device");
            needWriteData = false;
            break;
        }
        vectorRequestBuffer.clear();
        int retryCount = 0;
        while (retryCount < READ_RETRY_MAX_TIMES) {
            retryCount++;
            if (ProcessDataFromDevice(Operation::Common)) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(USB_READ_INTERVAL));
        }
        // 读超时错误
        if (retryCount >= READ_RETRY_MAX_TIMES) {
            PRINT_HILOGE("read data time out retryCout: %{public}d", retryCount);
        }
    }
    PRINT_HILOGD("endtWriteDataToPrinterLooper");
}

void PrintHttpRequestProcess::CreatWriteDataTask()
{
    PRINT_HILOGD("CreatWriteDataTask needWriteData: %{public}d", needWriteData);
    if (!needWriteData) {
        needWriteData = true;
        std::thread writeDataTask([this] {this->StartWriteDataToPrinterLooper();});
        writeDataTask.detach();
    }
}

void PrintHttpRequestProcess::ProcessOtherRequest(const char *data, size_t data_length,
    std::string &sHeadersAndBody, size_t requestId)
{
    CreatWriteDataTask();

    sHeadersAndBody.append(data, data_length);
    ippDataQue.push(sHeadersAndBody);
}

void PrintHttpRequestProcess::DumpReqIdOperaId(const char *data, size_t data_length)
{
    if (data_length < REQID_OPERAID_LEN) {
        return;
    }
    for (size_t i = 0; i < REQID_OPERAID_LEN; i++) {
        PRINT_HILOGD("ipp: %{public}x", *(data + i));
    }
}

void PrintHttpRequestProcess::CreatReadSendDocTask()
{
    PRINT_HILOGD("CreatReadSendDocTask needReadSendDoc: %{public}d", needReadSendDoc);
    if (!needReadSendDoc) {
        needReadSendDoc = true;
        std::thread readSendDocTask([this] {this->StartReadSendDocDataFromPrinterLooper();});
        readSendDocTask.detach();
    }
}

std::string PrintHttpRequestProcess::CreateChunk(const char *data, size_t data_length)
{
    std::string chunkStr = PrintIppOverUsbUtil::IntToHexString(static_cast<unsigned int>(data_length));
    chunkStr += HTTP_MSG_STRING_R_AND_N;
    chunkStr.append(data, data_length);
    chunkStr += HTTP_MSG_STRING_R_AND_N;
    return chunkStr;
}

int32_t PrintHttpRequestProcess::WriteDataSync(const std::string &dataStr)
{
    std::string sHeadersAndBody = dataStr;
    int32_t ret = 0;
    while (sHeadersAndBody.length() > USB_ENDPOINT_MAX_LENGTH) {
        std::string send = sHeadersAndBody.substr(0, USB_ENDPOINT_MAX_LENGTH);
        ret = BulkTransferWriteData(send);
        if (ret != 0) {
            return ret;
        }
        sHeadersAndBody = sHeadersAndBody.substr(USB_ENDPOINT_MAX_LENGTH);
    }
    if (!sHeadersAndBody.empty()) {
        ret = BulkTransferWriteData(sHeadersAndBody);
    }
    return ret;
}

int32_t PrintHttpRequestProcess::BulkTransferWriteData(const std::string &dataStr)
{
    std::vector<uint8_t> vectorRequestBuffer;
    size_t len = dataStr.length();
    sendDocTotalLen += len;
    vectorRequestBuffer.assign(dataStr.begin(), dataStr.end());
    uint32_t retryNum = 0;
    int32_t ret = 0;
    do {
        ret = DelayedSingleton<PrintUsbManager>::GetInstance()->BulkTransferWrite(devName,
            Operation::Send_Document, vectorRequestBuffer);
        PRINT_HILOGD("writeBody chunk, ret: %{public}d, len: %{public}lu, sendDocTotalLen: %{public}lu",
            ret, len, sendDocTotalLen);
        if (ret == EORROR_HDF_DEV_ERR_NO_DEVICE) {
            sendDocTotalLen = 0;
            deviceOpen = false;
            return ret;
        }
        if (ret == EORROR_HDF_DEV_ERR_TIME_OUT) {
            std::this_thread::sleep_for(std::chrono::milliseconds(USB_BULKTRANSFER_WRITE_SLEEP));
            retryNum++;
        }
    } while (ret == EORROR_HDF_DEV_ERR_TIME_OUT && retryNum < WRITE_RETRY_MAX_TIMES);
    if (ret != 0) {
        sendDocTotalLen = 0;
        PRINT_HILOGD("Write data fail");
        return ret;
    }
    vectorRequestBuffer.clear();
    return ret;
}

void PrintHttpRequestProcess::ProcessHttpResp(size_t requestId, httplib::Response &responseData,
    const std::string &sHeadersAndBody)
{
    if (reqIdOperaIdMap[requestId] == HTTP_REQUEST_GET_ATTR) {
        ProcessHttpResponseGetAttr(responseData, requestId);
    } else if (reqIdOperaIdMap[requestId] == HTTP_REQUEST_SEND_DOC) {
        if (!deviceOpen) {
            PRINT_HILOGE("Device disconnect, return");
            return;
        }
        PRINT_HILOGD("writeBody chunk end sHeadersAndBody len: %{public}lu", sHeadersAndBody.length());
        std::string dataStr = sHeadersAndBody + HTTP_MSG_STRING_CHUNK_END;
        auto ret = WriteDataSync(dataStr);
        sendDocTotalLen = 0;
        if (ret != 0) {
            PRINT_HILOGE("writeBody chunk end fail");
            return;
        }
        PRINT_HILOGD("writeBody chunk end");
        ProcessHttpResponseSendDoc(responseData, requestId);
    } else {
        ProcessHttpResponse(responseData, requestId);
    }
}

uint32_t PrintHttpRequestProcess::ProcessRequest(const httplib::Request &requestData, httplib::Response &responseData,
    const httplib::ContentReader &content_reader)
{
    PRINT_HILOGI("ProcessRequest devName: %{public}s", devName.c_str());
    std::string sHeadersAndBody = HTTP_POST;
    bool isChunked = DealRequestHeader(requestData, sHeadersAndBody);
    size_t requestId = 0;
    bool isFirstRead = true;
    content_reader([&](const char *data, size_t data_length) {
        if (isChunked) {
            if (isFirstRead) {
                isFirstRead = false;
                CalcReqIdOperaId(data, data_length, requestId);
                CreatReadSendDocTask();
                sHeadersAndBody += CreateChunk(data, data_length);
                return CPP_HTTP_OK;
            }
        } else {
            CalcReqIdOperaId(data, data_length, requestId);
        }

        if (reqIdOperaIdMap[requestId] == HTTP_REQUEST_SEND_DOC) {
            std::string dataChunk = CreateChunk(data, data_length);
            if ((sHeadersAndBody.length() + dataChunk.length()) < USB_DATA_MAX_LENGTH) {
                sHeadersAndBody += dataChunk;
                return CPP_HTTP_OK;
            }
            auto ret = WriteDataSync(sHeadersAndBody);
            if (ret != 0) {
                return CPP_HTTP_FAIL;
            }
            sHeadersAndBody = dataChunk;
            return CPP_HTTP_OK;
        }

        ProcessOtherRequest(data, data_length, sHeadersAndBody, requestId);
        return CPP_HTTP_OK;
    });
    ProcessHttpResp(requestId, responseData, sHeadersAndBody);
    PRINT_HILOGD("processRequest path: %{public}s end", requestData.path.c_str());
    return 0;
}

void PrintHttpRequestProcess::SetDeviceName(std::string name)
{
    devName = name;
}

std::string PrintHttpRequestProcess::GetDeviceName()
{
    return devName;
}

void PrintHttpRequestProcess::Stop()
{
    PRINT_HILOGD("stop read data looper");
    needReadSendDoc = false;
    needWriteSendDoc = false;
    needWriteData = false;
}

}

#endif // IPPOVERUSB_ENABLE