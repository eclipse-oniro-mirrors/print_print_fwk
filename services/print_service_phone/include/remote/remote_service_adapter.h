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

#ifndef REMOTE_SERVICE_CLIENT_H
#define REMOTE_SERVICE_CLIENT_H

#include <string>
#include <mutex>
#include <atomic>
#include <functional>
#include "print_ipc_connection.h"
#include "remote_callback_stub.h"
#include "noncopyable.h"
#include "print_log.h"
#include "refbase.h"

namespace OHOS::Print {

class RemoteServiceAdapter : public NoCopyable, public RefBase {
public:
    RemoteServiceAdapter();
    ~RemoteServiceAdapter();

    static RemoteServiceAdapter& GetInstance();
    
    bool BindService();
    
    bool IsConnected();
    
    int32_t SendData(uint32_t code, const std::string &msg);
    
    int32_t RequestPrinterStatus(const std::string &devId);
    
    int32_t RequestPrinterList();
    
    void SetOnServiceDiedCallback(std::function<void()> cb);
    
    void OnRemoteServiceDied();

private:
    sptr<PrintIpcConnection> connection_;
    sptr<RemoteCallbackStub> callbackStub_;
    std::function<void()> onServiceDiedCb_;
    std::mutex bindMutex_;
};

} // namespace OHOS::Print

#endif // REMOTE_SERVICE_CLIENT_H