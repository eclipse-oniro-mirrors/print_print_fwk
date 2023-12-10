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

#ifndef IPRINT_EXTENSION_CALLBACK_H
#define IPRINT_EXTENSION_CALLBACK_H

#include "iremote_broker.h"
#include "iremote_object.h"
#include "print_job.h"
#include "printer_capability.h"

namespace OHOS::Print {
class IPrintExtensionCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.Print.IPrintExtensionCallback");
    virtual bool OnCallback() = 0;
    virtual bool OnCallback(const std::string &printerId) = 0;
    virtual bool OnCallback(const PrintJob &job) = 0;
    virtual bool OnCallback(const std::string &printerId, PrinterCapability &cap) = 0;
};

enum {
    PRINT_EXTCB,
    PRINT_EXTCB_PRINTER,
    PRINT_EXTCB_PRINTJOB,
    PRINT_EXTCB_PRINTCAPABILITY,
};

enum {
    PRINT_EXTCB_START_DISCOVERY,
    PRINT_EXTCB_STOP_DISCOVERY,
    PRINT_EXTCB_CONNECT_PRINTER,
    PRINT_EXTCB_DISCONNECT_PRINTER,
    PRINT_EXTCB_START_PRINT,
    PRINT_EXTCB_CANCEL_PRINT,
    PRINT_EXTCB_REQUEST_CAP,
    PRINT_EXTCB_REQUEST_PREVIEW,
    PRINT_EXTCB_DESTROY_EXTENSION,
    PRINT_EXTCB_MAX,
};
} // namespace OHOS::Print
#endif // IPRINT_EXTCB_H