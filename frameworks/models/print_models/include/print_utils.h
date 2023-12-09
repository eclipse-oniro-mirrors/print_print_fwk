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

#ifndef PRINT_UTILS_H
#define PRINT_UTILS_H

#include <string>

namespace OHOS::Print {
class PrintUtils {
public:
    static std::string ToLower(const std::string &s);
    static std::string GetExtensionId(const std::string &globalId);
    static std::string GetGlobalId(const std::string& extensionId, const std::string& localId);
    static std::string GetLocalId(const std::string& globalId, const std::string& extensionId);
    static std::string EncodeExtensionCid(const std::string &extensionId, uint32_t callbackId);
    static bool DecodeExtensionCid(const std::string &cid, std::string &extensionId, uint32_t &callbackId);
    static std::string GetTaskEventId(const std::string &taskId, const std::string &type);
    static int32_t OpenFile(const std::string &filePath);
    static bool IsPathValid(const std::string &filePath);
    static uint32_t GetIdFromFdPath(const std::string &fdPath);
    static std::string GetJobStateChar(const uint32_t state);
};
}  // namespace OHOS::Print
#endif  // PRINT_UTILS_H
