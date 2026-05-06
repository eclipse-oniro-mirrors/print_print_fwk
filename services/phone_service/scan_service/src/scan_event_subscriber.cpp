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

#include "scan_event_subscriber.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "scan_usb_manager.h"
#include "scan_log.h"

namespace OHOS {
namespace Scan {
ScanEventSubscriber::ScanEventSubscriber(
    const EventFwk::CommonEventSubscribeInfo &subscribeInfo) : EventFwk::CommonEventSubscriber(subscribeInfo)
{}

ScanEventSubscriber::~ScanEventSubscriber()
{}

void ScanEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USB_DEVICE_ATTACHED) {
        SCAN_HILOGI("OnReceiveEvent attached start");
        std::string devStr = data.GetData();
        SCAN_HILOGD("OnReceiveEvent attached devStr = %{public}s", devStr.c_str());
        DelayedSingleton<ScanUsbManager>::GetInstance()->DealUsbDevStatusChange(devStr, true);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USB_DEVICE_DETACHED) {
        SCAN_HILOGI("OnReceiveEvent detached start");
        std::string devStr = data.GetData();
        DelayedSingleton<ScanUsbManager>::GetInstance()->DealUsbDevStatusChange(devStr, false);
        SCAN_HILOGD("OnReceiveEvent detached devStr = %{public}s end", devStr.c_str());
    }
}

}  // namespace Scan
}  // namespace OHOS