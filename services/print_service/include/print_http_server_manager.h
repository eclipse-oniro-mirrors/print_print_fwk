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
 

#ifndef PRINT_HTTP_SERVER_MANAGER_H_
#define PRINT_HTTP_SERVER_MANAGER_H_
#ifdef IPPOVERUSB_ENABLE

#include <string>
#include <map>
#include "singleton.h"
#include "httplib.h"
#include "print_ipp_over_usb_constant.h"
#include "print_http_request_process.h"

namespace OHOS::Print {

class PrintHttpServerManager final : public DelayedSingleton<PrintHttpServerManager> {
public:
    PrintHttpServerManager();
    ~PrintHttpServerManager();

    bool CreateServer(std::string printerName, int32_t &port);
    static void StartServer(std::shared_ptr<httplib::Server> svr,
        std::shared_ptr<PrintHttpRequestProcess> process);
    void StopServer(std::string printerName);
    void DealUsbDevDetach(const std::string &devStr);

private:
    bool AllocatePort(std::shared_ptr<httplib::Server> svr, int32_t &port);

private:
    std::map<std::string, std::shared_ptr<httplib::Server>> printHttpServerMap;
    std::map<std::string, int32_t> printHttpPortMap;
    std::map<std::string, std::shared_ptr<PrintHttpRequestProcess>> printHttpProcessMap;
};

}

#endif // IPPOVERUSB_ENABLE
#endif // PRINT_HTTP_SERVER_MANAGER_H_