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

#ifndef PRINT_IPP_OVER_USB_MANAGER_H_
#define PRINT_IPP_OVER_USB_MANAGER_H_
#ifdef IPPOVERUSB_ENABLE

#include "singleton.h"
#include <string>
#include "print_event_subscriber.h"

namespace OHOS::Print {
class PrintIppOverUsbManager final : public DelayedSingleton<PrintIppOverUsbManager> {
public:
    PrintIppOverUsbManager();
    ~PrintIppOverUsbManager();

    void Init();
    bool ConnectPrinter(const std::string printerId, int32_t &port);
    void DisConnectPrinter(const std::string printerId);

private:
    std::shared_ptr<PrintEventSubscriber> usbDevStatusListener;
    bool isInit = false;
};

}

#endif // IPPOVERUSB_ENABLE
#endif // PRINT_IPP_OVER_USB_MANAGER_H_