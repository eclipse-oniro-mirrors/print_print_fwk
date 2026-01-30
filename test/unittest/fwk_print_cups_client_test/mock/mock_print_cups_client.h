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

#ifndef MOCK_PRINT_CUPS_CLIENT_H
#define MOCK_PRINT_CUPS_CLIENT_H

#include <gmock/gmock.h>
#include "print_cups_client.h"

namespace OHOS {
namespace Print {

    uint32_t g_httpFd = 1;

    extern "C"
    {
        int httpGetFd(http_t *http)
        {
            return g_httpFd;
        }
    }

    void SetFdReturnValue(uint32_t value)
    {
        g_httpFd = value;
    }
}
}

#endif  // MOCK_PRINT_CUPS_CLIENT_H