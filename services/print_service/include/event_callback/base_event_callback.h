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

#ifndef PRINT_BASE_EVENT_CALLBACK_H
#define PRINT_BASE_EVENT_CALLBACK_H

#include "iremote_object.h"
#include "print_job.h"
#include "printer_info.h"
#include "print_constant.h"

namespace OHOS {
namespace Print {

enum CallbackEventType {
    // printer
    PRINTER_STATE_CHANGE = 0,
    PRINTER_JOB_STATE_CHANGE,
    PRINTER_INFO_QUERY,
    PRINTER_DISCOVER,
    PRINTER_CHANGE,
    PRINTER_EXT_INFO_CHANGE,
    // extension
    EXTCB_START_DISCOVERY,
    EXTCB_STOP_DISCOVERY,
    EXTCB_CONNECT_PRINTER,
    EXTCB_DISCONNECT_PRINTER,
    EXTCB_START_PRINT,
    EXTCB_CANCEL_PRINT,
    EXTCB_REQUEST_CAP,
    EXTCB_REQUEST_PREVIEW,
    EXTCB_DESTROY_EXTENSION,
    // job
    PRINT_JOB_BLOCK,
    PRINT_JOB_SUCCESS,
    PRINT_JOB_FAIL,
    PRINT_JOB_CANCEL,
    PRINT_JOB_STATE_CALLBACK,
    // job for adapter
    PRINT_JOB_CALLBACK_ADAPTER,
    PRINT_JOB_FILE_GET_ADAPTER,
    // unknown
    UNKNOWN_TYPE
};

struct CallbackInfo {
    CallbackEventType cbEventType = CallbackEventType::UNKNOWN_TYPE;
    int32_t userId = -1;
    std::string extensionId;
    std::string extInfo;
    std::string printerId;
    std::string jobId;
    PrinterEvent printerEvent;
    std::vector<PpdInfo> ppdInfos;
    std::shared_ptr<PrintJob> printJobInfo = nullptr;
    std::shared_ptr<PrinterInfo> printerInfo = nullptr;
    // adapter callback param
    uint32_t fd = 0;
    PrintJobState jobState;
    PrintDocumentAdapterState adapterState;
    uint32_t fileCompletedState;
    std::shared_ptr<PrintAttributes> oldAttrs = nullptr;
    std::shared_ptr<PrintAttributes> newAttrs = nullptr;
};

class BaseEventCallback {
public:
    BaseEventCallback(
        int32_t userId, pid_t pid, CallbackEventType eventType, sptr<IRemoteObject::DeathRecipient> deathRecipient)
        : userId_(userId), pid_(pid), eventType_(eventType), deathRecipient_(deathRecipient)
    {}

    virtual ~BaseEventCallback() = default;

    virtual bool Execute(const CallbackInfo &info) = 0;
    virtual bool IsRemoteDied(const sptr<IRemoteObject> &listener) = 0;
    virtual uint32_t Clear() = 0;
    virtual pid_t GetPid()
    {
        return pid_;
    }

protected:
    bool AddDeathRecipient(const sptr<IRemoteObject> &remoteObject)
    {
        if (!remoteObject) {
            return false;
        }
        remoteObject->AddDeathRecipient(deathRecipient_);
        return true;
    }

    bool RemoveDeathRecipient(const sptr<IRemoteObject> &remoteObject)
    {
        if (!remoteObject) {
            return false;
        }
        remoteObject->RemoveDeathRecipient(deathRecipient_);
        return true;
    }

    int32_t userId_ = -1;
    pid_t pid_ = -1;
    CallbackEventType eventType_ = CallbackEventType::UNKNOWN_TYPE;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ = nullptr;
};
}  // namespace Print
}  // namespace OHOS
#endif  // PRINT_BASE_EVENT_CALLBACK_H