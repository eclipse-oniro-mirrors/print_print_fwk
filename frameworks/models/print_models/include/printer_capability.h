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
#include <nlohmann/json.hpp>

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

    [[nodiscard]] bool HasSupportedPageSize() const;

    [[nodiscard]] bool HasSupportedColorMode() const;

    [[nodiscard]] bool HasSupportedDuplexMode() const;

    [[nodiscard]] bool HasSupportedMediaType() const;

    [[nodiscard]] bool HasSupportedQuality() const;

    [[nodiscard]] bool HasSupportedOrientation() const;

    void GetSupportedPageSize(std::vector<PrintPageSize>& supportedPageSize) const;

    void GetSupportedColorMode(std::vector<uint32_t>& supportedColorModeList) const;

    void GetSupportedDuplexMode(std::vector<uint32_t>& supportedDuplexModeList) const;

    void GetSupportedMediaType(std::vector<std::string>& supportedMediaTypeList) const;

    void GetSupportedQuality(std::vector<uint32_t>& supportedQualityList) const;

    void GetSupportedOrientation(std::vector<uint32_t>& supportedOrientationList) const;

    void SetMinMargin(const PrintMargin& minMargin);

    void SetResolution(const std::vector<PrintResolution>& resolutionList);

    void SetColorMode(uint32_t colorMode);

    void SetDuplexMode(uint32_t duplexMode);

    void SetSupportedColorMode(const std::vector<uint32_t>& supportedColorModeList);

    void SetSupportedPageSize(const std::vector<PrintPageSize>& supportedPageSizeList);

    void SetSupportedDuplexMode(const std::vector<uint32_t>& supportedDuplexModeList);

    void SetSupportedMediaType(const std::vector<std::string>& supportedMediaTypeList);

    void SetSupportedQuality(const std::vector<uint32_t>& supportedQualityList);

    void SetSupportedOrientation(const std::vector<uint32_t>& supportedOrientationList);

    virtual bool Marshalling(Parcel& parcel) const override;

    static std::shared_ptr<PrinterCapability> Unmarshalling(Parcel& parcel);

    void Dump() const;

    const char* GetPrinterAttrValue(const char* name);

    void SetPrinterAttrNameAndValue(const char* name, const char* value);

    nlohmann::json GetPrinterAttrGroupJson();

    void ClearCurPrinterAttrGroup();

private:
    bool ReadFromParcel(Parcel &parcel);

private:
    uint32_t colorMode_; // Property in API 10, deprecated in API 12
    uint32_t duplexMode_; // Property in API 10, deprecated in API 12

    std::vector<PrintPageSize> pageSizeList_;

    bool hasResolution_;
    std::vector<PrintResolution> resolutionList_;

    std::vector<PrintPageSize> supportedPageSizeList_;

    bool hasSupportedColorMode_;
    std::vector<uint32_t> supportedColorModeList_;

    bool hasSupportedDuplexMode_;
    std::vector<uint32_t> supportedDuplexModeList_;

    bool hasSupportedMediaType_;
    std::vector<std::string> supportedMediaTypeList_;

    bool hasSupportedQuality_;
    std::vector<uint32_t> supportedQualityList_;

    bool hasSupportedOrientation_;
    std::vector<uint32_t> supportedOrientationList_;

    bool hasMargin_;
    PrintMargin minMargin_;

    bool hasOption_;
    std::string option_;

    std::map<std::string, std::string> printerAttr_group;
};
}  // namespace OHOS::Print
#endif  // PRINTER_CAPABILITY_H
