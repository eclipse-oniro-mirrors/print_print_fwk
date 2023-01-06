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

#include "native_engine/native_engine.h"

extern const char BINARY_PRINT_EXTENSION_JS_START[];
extern const char BINARY_PRINT_EXTENSION_JS_END[];
extern const char BINARY_PRINT_EXTENSION_ABC_START[];
extern const char BINARY_PRINT_EXTENSION_ABC_END[];

extern "C" __attribute__((constructor)) void NAPIPrintExtensionAutoRegister()
{
    auto moduleManager = NativeModuleManager::GetInstance();
    NativeModule newModuleInfo = {
        .name = "PrintExtension",
        .fileName = "libprintextension_napi.so/PrintExtension.js",
    };

    moduleManager->Register(&newModuleInfo);
}

extern "C" __attribute__((visibility("default"))) void NapiPrintExtensionGetJsCode(const char **buf, int *bufLen)
{
    if (buf != nullptr) {
        *buf = BINARY_PRINT_EXTENSION_JS_START;
    }

    if (bufLen != nullptr) {
        *bufLen = BINARY_PRINT_EXTENSION_JS_END - BINARY_PRINT_EXTENSION_JS_START;
    }
}

// print_extension JS register
extern "C" __attribute__((visibility("default"))) void NapiPrintExtensionGetAbcCode(const char **buf, int *buflen)
{
    if (buf != nullptr) {
        *buf = BINARY_PRINT_EXTENSION_ABC_START;
    }
    if (buflen != nullptr) {
        *buflen = BINARY_PRINT_EXTENSION_ABC_END - BINARY_PRINT_EXTENSION_ABC_START;
    }
}