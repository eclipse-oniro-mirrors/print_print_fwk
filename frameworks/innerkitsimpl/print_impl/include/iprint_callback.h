/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef IPRINT_CALLBACK_H
#define IPRINT_CALLBACK_H

#include "iremote_broker.h"
#include "iremote_object.h"
#include "print_job.h"
#include "printer_info.h"

namespace OHOS::Print {
class IPrintCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Print.IPrintCallback");
    virtual bool OnCallback() = 0;
    virtual bool OnCallback(uint32_t state, const PrinterInfo &info) = 0;
    virtual bool OnCallback(uint32_t state, const PrintJob &info) = 0;
    virtual bool OnCallback(const std::string &extensionId, const std::string &info) = 0;
    virtual bool OnCallbackAdapterLayout(const std::string &jobId, const PrintAttributes &oldAttrs,
        const PrintAttributes &newAttrs, uint32_t fd) = 0;
    virtual bool onCallbackAdapterJobStateChanged(const std::string jobId, const uint32_t state,
        const uint32_t subState) = 0;
    virtual bool OnCallbackAdapterGetFile(uint32_t state) = 0;
};

enum {
    PRINT_CALLBACK_TASK,
    PRINT_CALLBACK_PRINTER,
    PRINT_CALLBACK_PRINT_JOB,
    PRINT_CALLBACK_EXTINFO,
    PRINT_CALLBACK_PRINT_JOB_ADAPTER,
    PRINT_CALLBACK_PRINT_JOB_ADAPTER_TEST,
    PRINT_CALLBACK_PRINT_JOB_CHANGED_ADAPTER,
    PRINT_CALLBACK_PRINT_GET_FILE_ADAPTER,
};
} // namespace OHOS::Print
#endif // IPRINT_CALLBACK_H