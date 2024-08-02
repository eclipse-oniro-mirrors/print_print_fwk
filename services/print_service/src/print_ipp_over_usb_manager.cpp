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
#include "print_ipp_over_usb_manager.h"
#include "print_log.h"
#include "print_usb_manager.h"
#include "print_http_server_manager.h"
#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"

namespace OHOS::Print {
using namespace std;
using namespace OHOS;
using namespace OHOS::USB;
using namespace httplib;

static const std::string SPOOLER_BUNDLE_NAME = "com.ohos.spooler";

PrintIppOverUsbManager::PrintIppOverUsbManager()
{}

PrintIppOverUsbManager::~PrintIppOverUsbManager()
{}

void PrintIppOverUsbManager::Init()
{
    if (isInit) {
        return;
    }
    isInit = true;
    PRINT_HILOGD("listen usb device attach detach");
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USB_DEVICE_ATTACHED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USB_DEVICE_DETACHED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);

    usbDevStatusListener = std::make_shared<PrintEventSubscriber>(subscribeInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(usbDevStatusListener)) {
        PRINT_HILOGE("subscribe common event failed");
    }
    DelayedSingleton<PrintUsbManager>::GetInstance()->Init();
}

bool PrintIppOverUsbManager::ConnectPrinter(const std::string printerId, int32_t &port)
{
    PRINT_HILOGD("ConnectPrinter printerId = %{public}s", printerId.c_str());
    // printerId: com.ohos.spooler:USB-XXXXX
    auto posColon = printerId.find_first_of(SPLIT_VALUE_COLON);
    if (posColon == std::string::npos) {
        PRINT_HILOGE("can not find : , return!");
        return false;
    }
    std::string extensionId = printerId.substr(0, posColon);
    PRINT_HILOGD("ConnectPrinter extensionId = %{public}s", extensionId.c_str());
    if (extensionId != SPOOLER_BUNDLE_NAME) {
        PRINT_HILOGE("not system spooler, return!");
        return false;
    }
    std::string tmp = printerId.substr(posColon + INDEX_1);
    PRINT_HILOGD("ConnectPrinter tmp = %{public}s", tmp.c_str());
    if (tmp.length() > INDEX_4 && (tmp.substr(0, INDEX_4) == PRINTER_ID_PREFIX)) {
        std::string printerName = tmp.substr(INDEX_4);
        PRINT_HILOGI("ConnectPrinter printerName = %{public}s", printerName.c_str());
        if (DelayedSingleton<PrintUsbManager>::GetInstance()->isExistIppOverUsbPrinter(printerName)) {
            if (DelayedSingleton<PrintUsbManager>::GetInstance()->ConnectUsbPinter(printerName)) {
                auto ret = DelayedSingleton<PrintHttpServerManager>::GetInstance()->CreateServer(printerName, port);
                PRINT_HILOGI("printerName = %{public}s CreateServer ret: %{public}d ", printerName.c_str(), ret);
                return ret;
            }
            PRINT_HILOGE("usb connect printerName = %{public}s fail", printerName.c_str());
        }
        PRINT_HILOGE("printerName = %{public}s not Exist", printerName.c_str());
    }
    return false;
}

void PrintIppOverUsbManager::DisConnectPrinter(const std::string printerId)
{
    PRINT_HILOGD("DisConnectPrinter printerId = %{public}s", printerId.c_str());
    auto posColon = printerId.find_first_of(SPLIT_VALUE_COLON);
    if (posColon == std::string::npos) {
        PRINT_HILOGE("can not find : , return!");
        return;
    }
    std::string extensionId = printerId.substr(0, posColon);
    PRINT_HILOGD("DisConnectPrinter extensionId = %{public}s", extensionId.c_str());
    if (extensionId != SPOOLER_BUNDLE_NAME) {
        PRINT_HILOGE("not system spooler, return!");
        return;
    }
    std::string tmp = printerId.substr(posColon + INDEX_1);
    PRINT_HILOGD("DisConnectPrinter tmp = %{public}s", tmp.c_str());
    if (tmp.length() > INDEX_4 && (tmp.substr(0, INDEX_4) == PRINTER_ID_PREFIX)) {
        std::string printerName = tmp.substr(INDEX_4);
        PRINT_HILOGD("DisConnectPrinter printerName = %{public}s", printerName.c_str());
        if (DelayedSingleton<PrintUsbManager>::GetInstance()->isExistIppOverUsbPrinter(printerName)) {
            DelayedSingleton<PrintHttpServerManager>::GetInstance()->StopServer(printerName);
            DelayedSingleton<PrintUsbManager>::GetInstance()->DisConnectUsbPinter(printerName);
        }
    }
}
}
#endif // IPPOVERUSB_ENABLE