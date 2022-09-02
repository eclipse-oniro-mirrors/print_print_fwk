/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef PRINT_INFO_H
#define PRINT_INFO_H

#include <iosfwd>
#include <stdint.h>
#include <string>

#include "print_constant.h"
#include "printer_capability.h"

namespace OHOS::Print {
class PrinterInfo final {
public:
    explicit PrinterInfo();
    PrinterInfo(const PrinterInfo &right);
    PrinterInfo &operator=(PrinterInfo &PrinterInfo);
    ~PrinterInfo();

    void SetPrinterId(uint32_t printerId);

    void SetPrinterName(std::string printerName);

    void SetPrinterIcon(uint32_t printIcon);

    void SetPrinterState(uint32_t printerState);

    void SetDescription(std::string description);

    void SetCapability(PrinterCapability capability);

    [[nodiscard]] uint32_t GetPrintId() const;

    [[nodiscard]] const std::string &GetPrinterName() const;

    [[nodiscard]] uint32_t GetPrinterIcon() const;

    [[nodiscard]] uint32_t GetPrinterState() const;

    [[nodiscard]] const std::string &GetDescription() const;

    void GetCapability(PrinterCapability &cap) const;

    void Dump();

private:
    uint32_t printerId_;

    std::string printerName_;

    uint32_t printerIcon_;

    uint32_t printerState_;

    std::string description_;

    PrinterCapability capability_;
};
} // namespace OHOS::Print
#endif /* PRINT_INFO_H */
