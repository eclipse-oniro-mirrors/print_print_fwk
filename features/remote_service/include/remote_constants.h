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

#ifndef REMOTE_CONSTANTS_H
#define REMOTE_CONSTANTS_H

#include <cstdint>

namespace OHOS::Print {

constexpr const char* REMOTE_SERVICE_BUNDLE_NAME = "com.ohos.remotesvc";
constexpr const char* REMOTE_EXT_BUNDLE_NAME = "com.ohos.remote";
constexpr const char* REMOTE_EXT_BUNDLE_ID = "***";
constexpr const char* REMOTE_ABILITY_NAME = "RemoteServiceExtAbility";
constexpr const char* REMOTE_DEVICE_TYPE_PRINTER = "A09";

constexpr const char* REMOTE_STATUS_ONLINE = "online";
constexpr const char* REMOTE_STATUS_OFFLINE = "offline";

constexpr int64_t REMOTE_MAX_RAW_DATA_SIZE = 64 * 1024; // 64KB

enum class RemoteRequestCode {
    COMMAND_REQUEST_PRINTER_STATUS = 2010,
    COMMAND_REQUEST_PRINTER_LIST = 2011,
};

} // namespace OHOS::Print

#endif // REMOTE_CONSTANTS_H