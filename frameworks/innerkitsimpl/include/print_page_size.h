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

#ifndef PRINT_PAGESIZE_H
#define PRINT_PAGESIZE_H

#include <map>
#include "parcel.h"

namespace OHOS::Print {
enum PageSizeId {
    ISO_A0,
    ISO_A1,
    ISO_A2,
    ISO_A3,
    ISO_A4,
    ISO_A5,
    ISO_A6,
    ISO_A7,
    ISO_A8,
    ISO_A9,
    ISO_A10,

    ISO_B0,
    ISO_B1,
    ISO_B2,
    ISO_B3,
    ISO_B4,
    ISO_B5,
    ISO_B6,
    ISO_B7,
    ISO_B8,
    ISO_B9,
    ISO_B10,

    ISO_C0,
    ISO_C1,
    ISO_C2,
    ISO_C3,
    ISO_C4,
    ISO_C5,
    ISO_C6,
    ISO_C7,
    ISO_C8,
    ISO_C9,
    ISO_C10,

    NA_LETTER,
    NA_GOVT_LETTER,
    NA_LEGAL,
    NA_JUNIOR_LEGAL,
    NA_LEDGER,
    NA_TABLOID,
    NA_INDEX_3X5,
    NA_INDEX_4X6,
    NA_INDEX_5X8,
    NA_MONARCH,
    NA_QUARTO,
    NA_FOOLSCAP,

    ROC_8K,
    ROC_16K,
    PRC_1,
    PRC_2,
    PRC_3,
    PRC_4,
    PRC_5,
    PRC_6,
    PRC_7,
    PRC_8,
    PRC_9,
    PRC_10,
    PRC_16K,
    OM_PA_KAI,
    OM_DAI_PA_KAI,
    OM_JUURO_KU_KAI,

    JIS_B10,
    JIS_B9,
    JIS_B8,
    JIS_B7,
    JIS_B6,
    JIS_B5,
    JIS_B4,
    JIS_B3,
    JIS_B2,
    JIS_B1,
    JIS_B0,
    JIS_EXEC,
    JPN_CHOU4,
    JPN_CHOU3,
    JPN_CHOU2,
    JPN_HAGAKI,
    JPN_OUFUKU,
    JPN_KAHU,
    JPN_KAKU2,
    JPN_YOU4,
};

const std::string PAGE_SIZE_TABLE[] = {
    "ISO_A0",       "ISO_A1",         "ISO_A2",        "ISO_A3",
    "ISO_A4",       "ISO_A5",         "ISO_A6",        "ISO_A7",
    "ISO_A8",       "ISO_A9",         "ISO_A10",

    "ISO_B0",       "ISO_B1",         "ISO_B2",        "ISO_B3",
    "ISO_B4",       "ISO_B5",         "ISO_B6",        "ISO_B7",
    "ISO_B8",       "ISO_B9",         "ISO_B10",

    "ISO_C0",       "ISO_C1",         "ISO_C2",        "ISO_C3",
    "ISO_C4",       "ISO_C5",         "ISO_C6",        "ISO_C7",
    "ISO_C8",       "ISO_C9",         "ISO_C10",

    "NA_LETTER",    "NA_GOVT_LETTER", "NA_LEGAL",      "NA_JUNIOR_LEGAL",
    "NA_LEDGER",    "NA_TABLOID",     "NA_INDEX_3X5",  "NA_INDEX_4X6",
    "NA_INDEX_5X8", "NA_MONARCH",     "NA_QUARTO",     "NA_FOOLSCAP",

    "ROC_8K",       "ROC_16K",        "PRC_1",         "PRC_2",
    "PRC_3",        "PRC_4",          "PRC_5",         "PRC_6",
    "PRC_7",        "PRC_8",          "PRC_9",         "PRC_10",
    "PRC_16K",      "OM_PA_KAI",      "OM_DAI_PA_KAI", "OM_JUURO_KU_KAI",

    "JIS_B10",      "JIS_B9",         "JIS_B8",        "JIS_B7",
    "JIS_B6",       "JIS_B5",         "JIS_B4",        "JIS_B3",
    "JIS_B2",       "JIS_B1",         "JIS_B0",        "JIS_EXEC",
    "JPN_CHOU4",    "JPN_CHOU3",      "JPN_CHOU2",     "JPN_HAGAKI",
    "JPN_OUFUKU",   "JPN_KAHU",       "JPN_KAKU2",     "JPN_YOU4",
};

using DiscreteId = std::string;
using DiscretePageName = std::string;
using PAGE_SIZE_ID = std::string;

class PrintPageSize final : public Parcelable {
public:
    static void BuildPageSizeMap();

    static PrintPageSize GetPageSize(PageSizeId id);

    explicit PrintPageSize();

    PrintPageSize(PAGE_SIZE_ID id, DiscretePageName name, uint32_t width, uint32_t height);

    PrintPageSize(const PrintPageSize &right);

    PrintPageSize &operator=(const PrintPageSize &right);

    virtual ~PrintPageSize();

    void Reset();

    [[nodiscard]] const std::string &GetId() const;

    [[nodiscard]] const std::string &GetName() const;

    [[nodiscard]] uint32_t GetWidth() const;

    [[nodiscard]] uint32_t GetHeight() const;

    void SetId(const std::string &id);

    void SetName(const std::string &name);

    void SetWidth(uint32_t width);

    void SetHeight(uint32_t height);

    virtual bool Marshalling(Parcel &parcel) const override;

    static std::shared_ptr<PrintPageSize> Unmarshalling(Parcel &parcel);

    void Dump();

private:
    void ReadFromParcel(Parcel &parcel);

private:
    std::string id_;
    std::string name_;
    uint32_t width_;
    uint32_t height_;
    static std::map<PAGE_SIZE_ID, std::shared_ptr<PrintPageSize>> pageSize_;
};
} // namespace OHOS::Print
#endif // PRINT_PAGESIZE_H
