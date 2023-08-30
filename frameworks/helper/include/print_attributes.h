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


#ifndef PRINT_FWK_PRINT_ATTRIBUTES_H
#define PRINT_FWK_PRINT_ATTRIBUTES_H
#define TDD_ENABLE 1

#include <map>

#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "parcel.h"
#include "print_margin.h"
#include "print_page_size.h"
#include "print_preview_attribute.h"
#include "print_range.h"

namespace OHOS::Print {
class PrintAttributes final : public Parcelable {
public:
    explicit PrintAttributes();

    PrintAttributes(const PrintAttributes &right);

    PrintAttributes &operator=(const PrintAttributes &right);

    virtual ~PrintAttributes();

    void SetCopyNumber(uint32_t copyNumber);

    void SetPageRange(const PrintRange &pageRange);

    void SetIsSequential(bool isSequential);

    void SetPageSize(const PrintPageSize &pageSize);

    void SetIsLandscape(bool isLandscape);

    void SetColorMode(uint32_t colorMode);

    void SetDuplexMode(uint32_t duplexmode);

    void SetMargin(const PrintMargin &margin);

    void SetOption(const std::string &option);

    void UpdateParams(const PrintAttributes& jobInfo);

    [[nodiscard]] uint32_t GetCopyNumber() const;

    void GetPageRange(PrintRange &range) const;

    [[nodiscard]] bool GetIsSequential() const;

    void GetPageSize(PrintPageSize &printPageSize) const;

    [[nodiscard]] bool GetIsLandscape() const;

    [[nodiscard]] uint32_t GetColorMode() const;

    [[nodiscard]] uint32_t GetDuplexMode() const;

    void GetMargin(PrintMargin &printMargin) const;

    [[nodiscard]] bool HasPreview() const;

    void GetPreview(PrintPreviewAttribute &previewAttr) const;

    [[nodiscard]] bool HasOption() const;

    [[nodiscard]] const std::string &GetOption() const;

    virtual bool Marshalling(Parcel &parcel) const override;

    virtual bool MarshallingParam(Parcel &parcel) const;

    static std::shared_ptr<PrintAttributes> Unmarshalling(Parcel &parcel);

    void Dump();

#ifndef TDD_ENABLE
private:
#endif
    bool ReadFromParcel(Parcel &parcel);

#ifndef TDD_ENABLE
private:
#endif
    uint32_t copyNumber_;
    PrintRange pageRange_;
    bool isSequential_;
    PrintPageSize pageSize_;
    bool isLandscape_;
    uint32_t colorMode_;
    uint32_t duplexMode_;
    bool hasMargin_;
    PrintMargin margin_;
    bool hasOption_;
    std::string option_;
};
} // namespace OHOS::Print
#endif //PRINT_FWK_PRINT_ATTRIBUTES_H
