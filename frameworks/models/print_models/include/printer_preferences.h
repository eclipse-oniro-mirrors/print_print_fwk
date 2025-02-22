/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef PRINTER_PREFERENCES_H
#define PRINTER_PREFERENCES_H

#include "parcel.h"
#include <json/json.h>

namespace OHOS::Print {
class PrinterPreferences final : public Parcelable {
public:
    explicit PrinterPreferences();

    PrinterPreferences(const PrinterPreferences &right);

    PrinterPreferences &operator=(const PrinterPreferences &right);

    virtual ~PrinterPreferences();

    void Reset();

    void SetDefaultDuplexMode(uint32_t defaultDuplexMode);

    void SetDefaultPrintQuality(uint32_t defaultPrintQuality);

    void SetDefaultMediaType(const std::string &defaultMediaType);

    void SetDefaultPageSizeId(const std::string &defaultPageSizeId);

    void SetDefaultOrientation(uint32_t defaultOrientation);

    void SetBorderless(bool borderless);

    void SetOption(const std::string &option);

    [[nodiscard]] bool HasDefaultDuplexMode() const;

    [[nodiscard]] uint32_t GetDefaultDuplexMode() const;

    [[nodiscard]] bool HasDefaultPrintQuality() const;

    [[nodiscard]] uint32_t GetDefaultPrintQuality() const;

    [[nodiscard]] bool HasDefaultMediaType() const;

    [[nodiscard]] const std::string &GetDefaultMediaType() const;

    [[nodiscard]] bool HasDefaultPageSizeId() const;

    [[nodiscard]] const std::string &GetDefaultPageSizeId() const;

    [[nodiscard]] bool HasDefaultOrientation() const;

    [[nodiscard]] uint32_t GetDefaultOrientation() const;

    [[nodiscard]] bool HasBorderless() const;

    [[nodiscard]] bool GetBorderless() const;

    [[nodiscard]] bool HasOption() const;

    [[nodiscard]] std::string GetOption() const;

    virtual bool Marshalling(Parcel &parcel) const override;

    static std::shared_ptr<PrinterPreferences> Unmarshalling(Parcel &parcel);

    void Dump() const;

    Json::Value ConvertToJson();

private:
    bool ReadFromParcel(Parcel &parcel);

private:
    bool hasDefaultDuplexMode_;

    uint32_t defaultDuplexMode_;

    bool hasDefaultPrintQuality_;

    uint32_t defaultPrintQuality_;

    bool hasDefaultMediaType_;

    std::string defaultMediaType_;

    bool hasDefaultPageSizeId_;

    std::string defaultPageSizeId_;

    bool hasDefaultOrientation_;

    uint32_t defaultOrientation_;

    bool hasBorderless_;

    bool borderless_;

    bool hasOption_;

    std::string option_;
};
}  // namespace OHOS::Print
#endif  // PRINTER_PREFERENCES_H
