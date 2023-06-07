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

#ifndef PRINT_SECURITY_GUARD_UTIL_H
#define PRINT_SECURITY_GUARD_UTIL_H

#include "print_util.h"

namespace OHOS::Print {
enum PrinterFoundType {
    FROM_P2P = 0,
    FROM_EPRINT = 1,
    FROM_LOCAL_NET = 2,
    FROM_USB = 3
};

class PrintSecurityGuardUtil {
public:
    static int32_t GetPrinterType(const std::string& des);
};

inline int32_t PrintSecurityGuardUtil::GetPrinterType(const std::string& des)
{
    std::string upper = PrintUtil::ToUpper(des);
    std::map<std::string, int32_t> typeMap;
    typeMap.insert({"P2P", FROM_P2P});
    typeMap.insert({"EPRINT", FROM_EPRINT});
    typeMap.insert({"USB", FROM_USB});

    for (auto iter = typeMap.begin(); iter != typeMap.end(); iter++) {
        std::string key = iter->first;
        if (PrintUtil::CheckContains(upper, key)) {
            return iter->second;
        }
    }
    return FROM_LOCAL_NET;
}
} // namespace OHOS::Print

#endif // PRINT_SECURITY_GUARD_UTIL_H