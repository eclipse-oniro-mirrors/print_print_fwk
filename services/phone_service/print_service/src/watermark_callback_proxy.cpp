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

#include "watermark_callback_proxy.h"
#include "print_constant.h"
#include "print_log.h"

namespace OHOS::Print {
WatermarkCallbackProxy::WatermarkCallbackProxy(const sptr<IRemoteObject> &object)
    : IRemoteProxy<IWatermarkCallback>(object)
{
}

void WatermarkCallbackProxy::OnCallback(const std::string &jobId, uint32_t fd)
{
    PRINT_HILOGI("WatermarkCallbackProxy OnCallback jobId:%{public}s, fd:%{public}u",
        jobId.c_str(), fd);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        PRINT_HILOGE("Write descriptor failed");
        return;
    }

    if (!data.WriteString(jobId)) {
        PRINT_HILOGE("Write jobId failed");
        return;
    }

    if (!data.WriteFileDescriptor(fd)) {
        PRINT_HILOGE("Write fd failed");
        return;
    }

    auto remote = Remote();
    if (remote == nullptr) {
        PRINT_HILOGE("Remote is null");
        return;
    }

    int32_t ret = remote->SendRequest(WATERMARK_CALLBACK_ADD, data, reply, option);
    if (ret != E_PRINT_NONE) {
        PRINT_HILOGE("SendRequest failed, ret = %{public}d", ret);
        return;
    }

    PRINT_HILOGI("WatermarkCallbackProxy OnCallback done");
}
} // namespace OHOS::Print
