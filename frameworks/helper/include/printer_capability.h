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
#ifndef PRINTER_CAPABILITY_H
#define PRINTER_CAPABILITY_H

#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "parcel.h"
#include "print_margin.h"
#include "print_page_size.h"
#include "print_resolution.h"

namespace OHOS::Print {
class PrinterCapability final : public Parcelable {
public:
    explicit PrinterCapability();

    PrinterCapability(const PrinterCapability &right);

    PrinterCapability &operator=(const PrinterCapability &right);

    virtual ~PrinterCapability();

    void Reset();

    [[nodiscard]] bool HasMargin() const;

    void GetMinMargin(PrintMargin &margin) const;

    void GetPageSize(std::vector<PrintPageSize> &pageSizeList) const;

    [[nodiscard]] bool HasResolution() const;

    void GetResolution(std::vector<PrintResolution> &resolutionList) const;

    [[nodiscard]] uint32_t GetColorMode() const;

    [[nodiscard]] uint32_t GetDuplexMode() const;

    void SetOption(const std::string &option);

    [[nodiscard]] bool HasOption() const;

    [[nodiscard]] std::string GetOption() const;

    void SetMinMargin(const PrintMargin &minMargin);

    void SetPageSize(const std::vector<PrintPageSize> &pageSizeList);

    void SetResolution(const std::vector<PrintResolution> &resolutionList);

    void SetColorMode(uint32_t colorMode);

    void SetDuplexMode(uint32_t duplexMode);

    virtual bool Marshalling(Parcel &parcel) const override;

    static std::shared_ptr<PrinterCapability> Unmarshalling(Parcel &parcel);

    void Dump();

private:
    bool ReadFromParcel(Parcel &parcel);

private:
    uint32_t colorMode_;
    uint32_t duplexMode_;
    std::vector<PrintPageSize> pageSizeList_;

    bool hasResolution_;
    std::vector<PrintResolution> resolutionList_;

    bool hasMargin_;
    PrintMargin minMargin_;

    bool hasOption_;
    std::string option_;
};
}  // namespace OHOS::Print
#endif  // PRINTER_CAPABILITY_H
