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

#ifndef REMOTESERVICE_FUZZER_H
#define REMOTESERVICE_FUZZER_H

#include "fuzzer/FuzzedDataProvider.h"
#include "remote_service_adapter.h"
#include "remote_printer_manager.h"
#include "remote_callback_stub.h"
#include "print_ipc_connection.h"

namespace OHOS::Print {

class RemoteServiceFuzzer {
public:
    static void TestRemoteServiceAdapter(const uint8_t *data, size_t size);
    static void TestRemotePrinterManager(const uint8_t *data, size_t size);
    static void TestRemoteCallbackStub(const uint8_t *data, size_t size);
    static void TestPrintIpcConnection(const uint8_t *data, size_t size);
};

} // namespace OHOS::Print

#endif // REMOTESERVICE_FUZZER_H