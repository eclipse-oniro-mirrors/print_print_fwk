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

#include "printservice_fuzzer.h"

#include "print_constant.h"
#include "print_log.h"
#include "print_service_ability.h"

namespace OHOS {
namespace Print {
    constexpr size_t FOO_MAX_LEN = 1024;
    constexpr size_t U32_AT_SIZE = 4;
    const std::u16string PRINT_SERVICE_INTERFACE_TOKEN = u"OHOS.Print.IPrintService";

    uint32_t GetU32Data(const char* ptr)
    {
        // 将第0个数字左移24位，将第1个数字左移16位，将第2个数字左移8位，第3个数字不左移
        return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | (ptr[3]);
    }

    bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
    {
        uint32_t code = GetU32Data(data);
        MessageParcel datas;
        datas.WriteInterfaceToken(PRINT_SERVICE_INTERFACE_TOKEN);
        datas.WriteBuffer(data, size);
        datas.RewindRead(0);
        MessageParcel reply;
        MessageOption option;
        PrintServiceAbility::GetInstance()->OnRemoteRequest(code, datas, reply, option);
        return true;
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::Print::U32_AT_SIZE) {
        return 0;
    }

    /* Validate the length of size */
    if (size == 0 || size > OHOS::Print::FOO_MAX_LEN) {
        return 0;
    }

    char* ch = (char *)malloc(size + 1);
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::Print::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}

