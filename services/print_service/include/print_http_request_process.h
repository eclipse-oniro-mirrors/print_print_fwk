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
 

#ifndef PRINT_HTTP_REQUEST_PROCESS_H_
#define PRINT_HTTP_REQUEST_PROCESS_H_
#ifdef IPPOVERUSB_ENABLE

#include <string>
#include <queue>
#include <mutex>
#include "singleton.h"
#include "httplib.h"
#include "print_usb_manager.h"

namespace OHOS::Print {
template<class T>
class DoubleBufQue {
public:
    void push(T& val)
    {
        std::lock_guard<std::mutex> mtx_locker(mutexSwap);
        writeQueue.emplace(val);
    }

    bool pop(T& val)
    {
        if (readQueue.empty()) {
            std::lock_guard<std::mutex> mtx_locker(mutexSwap);
            if (writeQueue.empty()) {
                return false;
            }
            readQueue.swap(writeQueue);
        }
        val = readQueue.front();
        readQueue.pop();
        return true;
    }

private:
    std::queue<T> writeQueue;
    std::queue<T> readQueue;
    std::mutex mutexSwap;
};

class PrintHttpRequestProcess {
public:
    PrintHttpRequestProcess();
    virtual ~PrintHttpRequestProcess();

    uint32_t ProcessRequest(const httplib::Request &requestData, httplib::Response &responseData,
        const httplib::ContentReader &content_reader);

    void SetDeviceName(std::string name);
    std::string GetDeviceName();

    void Stop();

private:
    std::string PrintOperation(Operation operation);
    size_t NeedOffset(const std::vector<uint8_t> &readTempBuffer);
    void RecordBufByOperation(Operation operation, size_t requestId, const std::vector<uint8_t> &tmVector);
    void GetContentLength(const std::vector<uint8_t> &readTempBuffer, size_t index, bool &findContentLength,
        size_t &contentLength);
    void DumpRespIdCode(const std::vector<uint8_t> &readTempBuffer, Operation operation, size_t begin, size_t maxSize);
    bool ProcessDataFromDevice(Operation operation);
    void StartWriteDataToPrinterLooper();
    void StartReadSendDocDataFromPrinterLooper();
    void ProcessHttpResponse(httplib::Response &responseData, size_t requestId);
    void ProcessHttpResponseGetAttr(httplib::Response &responseData, size_t requestId);
    void ProcessHttpResponseSendDoc(httplib::Response &responseData, size_t requestId);
    bool DealRequestHeader(const httplib::Request &requestData, std::string &sHeadersAndBody);
    void CalcReqIdOperaId(const char *data, size_t dataLength, size_t &requestId);
    void ProcessOtherRequest(const char *data, size_t data_length, std::string &sHeadersAndBody, size_t requestId);
    void DumpReqIdOperaId(const char *data, size_t data_length);
    std::string CreateChunk(const char *data, size_t data_length);
    void CreatWriteDataTask();
    void CreatReadSendDocTask();
    bool CheckLineEnd(std::vector<uint8_t> &readTempBuffer, size_t index);
    size_t CalculateRequestId(std::vector<uint8_t> &readTempBuffer, size_t index, Operation operation);
    size_t CalculateFileDataBeginIndex(size_t index, Operation operation);
    int32_t WriteDataSync(const std::string &dataStr);
    int32_t BulkTransferWriteData(const std::string &dataStr);
    void ProcessHttpResp(size_t requestId, httplib::Response &responseData, const std::string &sHeadersAndBody);
    void GetAttrAgain(Operation operation, std::vector<uint8_t> &tmVector);

private:
    bool needWriteData = false;
    bool needReadSendDoc = false;
    bool needWriteSendDoc = false;
    bool deviceOpen = true;

    std::map<size_t, size_t> reqIdOperaIdMap;  // requestId + operationId
    std::map<size_t, std::vector<uint8_t>> readBufMap; // requestId + buffer
    std::map<size_t, std::vector<uint8_t>> readSendDocBufMap; // requestId + buffer
    std::map<size_t, std::vector<uint8_t>> readGetAttrBufMap; // requestId + buffer

    std::string devName;

    std::mutex mutexCommon;
    std::mutex mutexGetAttr;
    std::mutex mutexSendDoc;

    DoubleBufQue<std::string> sendDocDataQue;
    DoubleBufQue<std::string> ippDataQue;
    size_t sendDocTotalLen = 0;
};

}

#endif // PRINT_HTTP_REQUEST_PROCESS_H_
#endif // IPPOVERUSB_ENABLE