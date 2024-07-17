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
#include "print_http_server_manager.h"
#include "print_http_request_process.h"
#include "print_usb_manager.h"
#include "print_log.h"
#include "nlohmann/json.hpp"
#include "cJSON.h"

namespace OHOS::Print {
using namespace std;
using namespace OHOS;
using namespace httplib;

using json = nlohmann::json;

PrintHttpServerManager::PrintHttpServerManager()
{}

PrintHttpServerManager::~PrintHttpServerManager()
{
}

bool PrintHttpServerManager::AllocatePort(std::shared_ptr<httplib::Server> svr, int32_t &port)
{
    for (int allocPort = HTTP_MIN_PORT; allocPort <= HTTP_MAX_PORT; allocPort++) {
        bool isPortUse = false;
        for (const auto& pair : printHttpPortMap) {
            if (pair.second == allocPort) {
                isPortUse = true;
                break;
            }
        }
        if (isPortUse) {
            PRINT_HILOGD("port : %{public}d is using", allocPort);
            continue;
        }
        if (svr != nullptr && svr->bind_to_port(LOCAL_HOST, allocPort)) {
            PRINT_HILOGD("bind to port : %{public}d success", allocPort);
            port = allocPort;
            return true;
        }
    }
    return false;
}

void PrintHttpServerManager::StartServer(std::shared_ptr<httplib::Server> svr,
    std::shared_ptr<PrintHttpRequestProcess> process)
{
    PRINT_HILOGD("startServer");
    if (svr == nullptr) {
        PRINT_HILOGE("svr is null");
        return;
    }
    svr->set_payload_max_length(HTTP_SERVER_MAX_LENGTH);
    PRINT_HILOGD("post /");
    svr->Post("^/.*", [process](const httplib::Request &req, httplib::Response &res,
                              const httplib::ContentReader &content_reader) {
        PRINT_HILOGD("listen path: %{public}s", req.path.c_str());
        if (process != nullptr) {
            process->ProcessRequest(req, res, content_reader);
        }
    });

    PRINT_HILOGD("after post");
    svr->listen_after_bind();
    PRINT_HILOGD("after listen");
}

bool PrintHttpServerManager::CreateServer(std::string printerName, int32_t &port)
{
    PRINT_HILOGD("PrintHttpServerManager init printerName: %{public}s, port: %{public}d", printerName.c_str(), port);
    if (printHttpServerMap.find(printerName) != printHttpServerMap.end()) {
        PRINT_HILOGI("printerName: %{public}s has server", printerName.c_str());
        if (printHttpPortMap.find(printerName) != printHttpPortMap.end()) {
            port = printHttpPortMap[printerName];
            return true;
        }
        PRINT_HILOGE("printerName: %{public}s has server, but do not has port", printerName.c_str());
        return false;
    }

    std::shared_ptr<httplib::Server> newServer = std::make_shared<httplib::Server>();
    int32_t allocPort = HTTP_MIN_PORT;
    if (!AllocatePort(newServer, allocPort)) {
        PRINT_HILOGE("AllocatePort fail, return!");
        return false;
    }
    port = allocPort;
    printHttpServerMap[printerName] = newServer;
    printHttpPortMap[printerName] = port;
    std::shared_ptr<PrintHttpRequestProcess> newProcess = std::make_shared<PrintHttpRequestProcess>();
    printHttpProcessMap[printerName] = newProcess;
    newProcess->SetDeviceName(printerName);

    std::thread tServer = std::thread([this, printerName] {
        this->StartServer(this->printHttpServerMap[printerName], this->printHttpProcessMap[printerName]);
    });
    tServer.detach();
    return true;
}

void PrintHttpServerManager::StopServer(std::string printerName)
{
    PRINT_HILOGD("stopServer printerName: %{public}s", printerName.c_str());
    if (printHttpServerMap.find(printerName) != printHttpServerMap.end()) {
        if (printHttpServerMap[printerName]->is_running()) {
            printHttpServerMap[printerName]->stop();
            printHttpServerMap.erase(printerName);
        }
    }
    if (printHttpPortMap.find(printerName) != printHttpPortMap.end()) {
        printHttpPortMap.erase(printerName);
    }
    if (printHttpProcessMap.find(printerName) != printHttpProcessMap.end()) {
        printHttpProcessMap[printerName]->Stop();
        printHttpProcessMap.erase(printerName);
    }
}

void PrintHttpServerManager::DealUsbDevDetach(const std::string &devStr)
{
    PRINT_HILOGD("devStr: %{public}s", devStr.c_str());
    cJSON *devJson = cJSON_Parse(devStr.c_str());
    if (!devJson) {
        PRINT_HILOGE("Create devJson error");
    }
    cJSON *jsonTemp = cJSON_GetObjectItem(devJson, "name");
    if (jsonTemp == nullptr || jsonTemp->valuestring  == NULL) {
        PRINT_HILOGE("The devJson does not have a necessary attribute.");
        cJSON_Delete(devJson);
        return;
    }
    string name = jsonTemp->valuestring;
    string printerName = DelayedSingleton<PrintUsbManager>::GetInstance()->GetPrinterName(name);
    PRINT_HILOGD("DealUsbDevDetach name: %{public}s, printerName: %{public}s", name.c_str(), printerName.c_str());
    if (printerName.empty()) {
        cJSON_Delete(devJson);
        return;
    }
    StopServer(printerName);
    cJSON_Delete(devJson);
}
}
#endif // IPPOVERUSB_ENABLE