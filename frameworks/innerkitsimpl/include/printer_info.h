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

#ifndef PRINTER_INFO_H
#define PRINTER_INFO_H
#define TDD_ENABLE 1

#include "napi/native_api.h"
#include "parcel.h"
#include "printer_capability.h"

namespace OHOS::Print {
class PrinterInfo final : public Parcelable {
public:
    explicit PrinterInfo();

    PrinterInfo(const PrinterInfo &right);

    PrinterInfo &operator=(const PrinterInfo &PrinterInfo);

    virtual ~PrinterInfo();

    void SetPrinterId(const std::string &printerId);

    void SetPrinterName(std::string printerName);

    void SetPrinterIcon(uint32_t printIcon);

    void SetPrinterState(uint32_t printerState);

    void SetDescription(std::string description);

    void SetCapability(const PrinterCapability &capability);

    void SetOption(const std::string &option);

    [[nodiscard]] const std::string &GetPrinterId() const;

    [[nodiscard]] const std::string &GetPrinterName() const;

    [[nodiscard]] uint32_t GetPrinterIcon() const;

    [[nodiscard]] uint32_t GetPrinterState() const;

    [[nodiscard]] const std::string &GetDescription() const;

    void GetCapability(PrinterCapability &cap) const;

    [[nodiscard]] std::string GetOption() const;

    virtual bool Marshalling(Parcel &parcel) const override;

    static std::shared_ptr<PrinterInfo> Unmarshalling(Parcel &parcel);

    napi_value ToJsObject(napi_env env) const;

    static std::shared_ptr<PrinterInfo> BuildFromJs(napi_env env, napi_value jsValue);

    void Dump();

#ifndef TDD_ENABLE
private:
#endif
    bool ReadFromParcel(Parcel &parcel);

    static bool ValidateProperty(napi_env env, napi_value object);

#ifndef TDD_ENABLE
private:
#endif
    std::string printerId_;

    std::string printerName_;

    uint32_t printerState_;

    uint32_t printerIcon_;

    std::string description_;

    bool hasCapability_;

    PrinterCapability capability_;

    bool hasOption_;

    std::string option_;
};
} // namespace OHOS::Print
#endif // PRINTER_INFO_H
