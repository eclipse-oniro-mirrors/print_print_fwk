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
#ifndef PRINT_CAP_ABILITY_H
#define PRINT_CAP_ABILITY_H

#include <mutex>
#include <string>
#include <vector>
#include "print_margin.h"
#include "print_page_size.h"
#include "print_resolution.h"

namespace OHOS::Print {
class PrinterCapability  {
public:
    PrinterCapability ();

    void SetMinMargin(PrintMargin &minMargin);

    void SetPageSize(PrinterPageSize pageSize);

    void SetResolution(PrinterResolution resolution);

    void SetColorMode(uint32_t colorMode);

    void SetDuplexMode(uint32_t duplexMode);

    [[nodiscard]] PrintMargin &GetMinMargin();

    [[nodiscard]] std::vector<PrinterPageSize> &GetPageSize();

    [[nodiscard]] std::vector<PrinterResolution> &GetResolution();

    [[nodiscard]] uint32_t GetColorMode();

    [[nodiscard]] uint32_t GetDuplexMode();
    
    void Dump();

    ~PrinterCapability();
    
private:
    PrintMargin minMargin_;
    std::vector<PrinterPageSize> pageSize_;
    std::vector<PrinterResolution> resolution_;
    uint32_t colorMode_;
    uint32_t duplexMode_;
};
} // namespace OHOS::Print
#endif // PRINT_CAP_ABILITY_H
