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
#ifndef NATIVE_PRINT_CONVERTER_H
#define NATIVE_PRINT_CONVERTER_H

#include <vector>
#include <string>

#include "ohprint.h"

namespace OHOS::Print {
#define SAFE_DELETE(address)        \
    {                               \
        if ((address) != nullptr) { \
            delete (address);       \
            (address) = nullptr;    \
        }                           \
    }

#define SAFE_DELETE_ARRAY(address)  \
    {                               \
        if ((address) != nullptr) { \
            delete[] (address);     \
            (address) = nullptr;    \
        }                           \
    }

inline bool IsValidString(const char *address)
{
    if (address == nullptr || address[0] == '\0') {
        return false;
    }
    return true;
}

template <typename T>
T *CopyArray(const std::vector<T> &list, uint32_t &count)
{
    count = 0;
    size_t len = list.size();
    if (len == 0) {
        return nullptr;
    }
    T *dest = new (std::nothrow) T[len];
    if (dest == nullptr) {
        return nullptr;
    }
    if (memset_s(dest, len * sizeof(T), 0, len * sizeof(T)) != 0) {
        delete[] dest;
        dest = nullptr;
        return nullptr;
    }
    for (size_t i = 0; i < len; i++) {
        *(dest + i) = list[i];
    }
    count = len;
    return dest;
}

template <typename T1, typename T2>
T2 *CopyArray(const std::vector<T1> &list, uint32_t &count, bool (*ConvertFunction)(const T1 &src, T2 &dst))
{
    count = 0;
    size_t len = list.size();
    if (len == 0) {
        return nullptr;
    }
    T2 *dest = new (std::nothrow) T2[len];
    if (dest == nullptr) {
        return nullptr;
    }
    if (memset_s(dest, len * sizeof(T2), 0, len * sizeof(T2)) != 0) {
        delete[] dest;
        dest = nullptr;
        return nullptr;
    }
    for (size_t i = 0; i < len; i++) {
        if (ConvertFunction(list[i], *(dest + count))) {
            count++;
        }
    }
    return dest;
}

Print_ErrorCode ConvertToNativeErrorCode(int32_t errorCode);
Print_PrinterState ConvertPrinterState(uint32_t state);
bool ConvertStringToInt(const char *src, int &dst);
bool ConvertOrientationMode(const uint32_t &src, Print_OrientationMode &dst);
bool ConvertColorMode(const uint32_t &src, Print_ColorMode &dst);
bool ConvertDuplexMode(const uint32_t &src, Print_DuplexMode &dst);
bool ConvertQuality(const uint32_t &src, Print_Quality &dst);
std::string GetDocumentFormatString(Print_DocumentFormat format);
std::string GetResolutionString(Print_Resolution resolution);
}  // namespace OHOS::Print
#endif  // NATIVE_PRINT_CONVERTER_H