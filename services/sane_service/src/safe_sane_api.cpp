/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "safe_sane_api.h"
#include "sane/sane.h"
#include "sane/saneopts.h"

namespace OHOS {
namespace Scan {

SafeSANEAPI& SafeSANEAPI::GetInstance()
{
    static SafeSANEAPI instance;
    return instance;
}

SANE_Status SafeSANEAPI::SaneInit(SANE_Int* version, SANE_Auth_Callback authorize)
{
    std::lock_guard<std::mutex> autoLock(initLock_);
    return sane_init(version, authorize);
}

void SafeSANEAPI::SaneExit()
{
    std::lock_guard<std::mutex> autoLock(initLock_);
    sane_exit();
}

SANE_Status SafeSANEAPI::SaneGetDevices(const SANE_Device*** deviceList, SANE_Bool localOnly)
{
    std::unique_lock<std::mutex> lock(initLock_);
    return sane_get_devices(deviceList, localOnly);
}

SANE_Status SafeSANEAPI::SaneOpen(const char* device_name, SANE_Handle* handle)
{
    std::unique_lock<std::shared_mutex> lock(handleLock_);
    return sane_open(device_name, handle);
}

void SafeSANEAPI::SaneClose(SANE_Handle handle)
{
    std::unique_lock<std::shared_mutex> lock(handleLock_);
    sane_close(handle);
}

SANE_Status SafeSANEAPI::SaneStart(SANE_Handle handle)
{
    std::shared_lock<std::shared_mutex> lock(handleLock_);
    return sane_start(handle);
}

void SafeSANEAPI::SaneCancel(SANE_Handle handle)
{
    std::shared_lock<std::shared_mutex> lock(handleLock_);
    sane_cancel(handle);
}

const SANE_Option_Descriptor* SafeSANEAPI::SaneGetOptionDescriptor(SANE_Handle handle, SANE_Int option)
{
    std::shared_lock<std::shared_mutex> lock(handleLock_);
    return sane_get_option_descriptor(handle, option);
}

SANE_Status SafeSANEAPI::SaneGetParameters(SANE_Handle handle, SANE_Parameters* params)
{
    std::shared_lock<std::shared_mutex> lock(handleLock_);
    return sane_get_parameters(handle, params);
}

SANE_Status SafeSANEAPI::SaneControlOption(SANE_Handle handle, SANE_Int option,
    SANE_Action action, void* value, SANE_Int* info)
{
    std::shared_lock<std::shared_mutex> lock(handleLock_);
    return sane_control_option(handle, option, action, value, info);
}

SANE_Status SafeSANEAPI::SaneRead(SANE_Handle handle, SANE_Byte* data,
    SANE_Int maxLength, SANE_Int* length)
{
    std::shared_lock<std::shared_mutex> lock(handleLock_);
    return sane_read(handle, data, maxLength, length);
}

} // namespace Scan
} // namespace OHOS