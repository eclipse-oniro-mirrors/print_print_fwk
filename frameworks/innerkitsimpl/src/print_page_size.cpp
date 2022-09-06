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

#include "print_page_size.h"

#include "print_log.h"

namespace OHOS::Print {
std::map<PAGE_SIZE_ID, std::shared_ptr<PrintPageSize>> PrintPageSize::pageSize_;
void PrintPageSize::BuildPageSizeMap()
{
    pageSize_.insert(std::make_pair("ISO_A0", std::make_shared<PrintPageSize>("ISO_A0", "Harmony", 33110, 46810)));
    pageSize_.insert(std::make_pair("ISO_A1", std::make_shared<PrintPageSize>("ISO_A1", "Harmony", 23390, 33110)));
    pageSize_.insert(std::make_pair("ISO_A2", std::make_shared<PrintPageSize>("ISO_A2", "Harmony", 16540, 23390)));
    pageSize_.insert(std::make_pair("ISO_A3", std::make_shared<PrintPageSize>("ISO_A3", "Harmony", 11690, 16540)));
    pageSize_.insert(std::make_pair("ISO_A4", std::make_shared<PrintPageSize>("ISO_A4", "Harmony", 8270, 11690)));
    pageSize_.insert(std::make_pair("ISO_A5", std::make_shared<PrintPageSize>("ISO_A5", "Harmony", 5830, 8270)));
    pageSize_.insert(std::make_pair("ISO_A6", std::make_shared<PrintPageSize>("ISO_A6", "Harmony", 4130, 5830)));
    pageSize_.insert(std::make_pair("ISO_A7", std::make_shared<PrintPageSize>("ISO_A7", "Harmony", 2910, 4130)));
    pageSize_.insert(std::make_pair("ISO_A8", std::make_shared<PrintPageSize>("ISO_A8", "Harmony", 2050, 2910)));
    pageSize_.insert(std::make_pair("ISO_A9", std::make_shared<PrintPageSize>("ISO_A9", "Harmony", 1460, 2050)));
    pageSize_.insert(std::make_pair("ISO_A10", std::make_shared<PrintPageSize>("ISO_A10", "Harmony", 1020, 1460)));

    pageSize_.insert(std::make_pair("ISO_B0", std::make_shared<PrintPageSize>("ISO_B0", "Harmony", 39370, 55670)));
    pageSize_.insert(std::make_pair("ISO_B1", std::make_shared<PrintPageSize>("ISO_B1", "Harmony", 27830, 39370)));
    pageSize_.insert(std::make_pair("ISO_B2", std::make_shared<PrintPageSize>("ISO_B2", "Harmony", 19690, 27830)));
    pageSize_.insert(std::make_pair("ISO_B3", std::make_shared<PrintPageSize>("ISO_B3", "Harmony", 13900, 19690)));
    pageSize_.insert(std::make_pair("ISO_B4", std::make_shared<PrintPageSize>("ISO_B4", "Harmony", 39840, 13900)));
    pageSize_.insert(std::make_pair("ISO_B5", std::make_shared<PrintPageSize>("ISO_B5", "Harmony", 6930, 9840)));
    pageSize_.insert(std::make_pair("ISO_B6", std::make_shared<PrintPageSize>("ISO_B6", "Harmony", 4920, 6930)));
    pageSize_.insert(std::make_pair("ISO_B7", std::make_shared<PrintPageSize>("ISO_B7", "Harmony", 3460, 4920)));
    pageSize_.insert(std::make_pair("ISO_B8", std::make_shared<PrintPageSize>("ISO_B8", "Harmony", 2440, 3460)));
    pageSize_.insert(std::make_pair("ISO_B9", std::make_shared<PrintPageSize>("ISO_B9", "Harmony", 1730, 2440)));
    pageSize_.insert(std::make_pair("ISO_B10", std::make_shared<PrintPageSize>("ISO_B10", "Harmony", 1220, 1730)));

    pageSize_.insert(std::make_pair("ISO_C0", std::make_shared<PrintPageSize>("ISO_C0", "Harmony", 36100, 51060)));
    pageSize_.insert(std::make_pair("ISO_C1", std::make_shared<PrintPageSize>("ISO_C1", "Harmony", 25510, 36100)));
    pageSize_.insert(std::make_pair("ISO_C2", std::make_shared<PrintPageSize>("ISO_C2", "Harmony", 18030, 25510)));
    pageSize_.insert(std::make_pair("ISO_C3", std::make_shared<PrintPageSize>("ISO_C3", "Harmony", 12760, 18030)));
    pageSize_.insert(std::make_pair("ISO_C4", std::make_shared<PrintPageSize>("ISO_C4", "Harmony", 9020, 12760)));
    pageSize_.insert(std::make_pair("ISO_C5", std::make_shared<PrintPageSize>("ISO_C5", "Harmony", 6380, 9020)));
    pageSize_.insert(std::make_pair("ISO_C6", std::make_shared<PrintPageSize>("ISO_C6", "Harmony", 4490, 6380)));
    pageSize_.insert(std::make_pair("ISO_C7", std::make_shared<PrintPageSize>("ISO_C7", "Harmony", 3190, 4490)));
    pageSize_.insert(std::make_pair("ISO_C8", std::make_shared<PrintPageSize>("ISO_C8", "Harmony", 2240, 3190)));
    pageSize_.insert(std::make_pair("ISO_C9", std::make_shared<PrintPageSize>("ISO_C9", "Harmony", 1570, 2240)));
    pageSize_.insert(std::make_pair("ISO_C10", std::make_shared<PrintPageSize>("ISO_C10", "Harmony", 1100, 1570)));

    //  North America
    pageSize_.insert(std::make_pair("NA_LETTER", std::make_shared<PrintPageSize>("NA_LETTER", "Harmony", 8500, 11000)));
    pageSize_.insert(
        std::make_pair("NA_GOVT_LETTER", std::make_shared<PrintPageSize>("NA_GOVT_LETTER", "Harmony", 8000, 10500)));
    pageSize_.insert(std::make_pair("NA_LEGAL", std::make_shared<PrintPageSize>("NA_LEGAL", "Harmony", 8500, 14000)));
    pageSize_.insert(
        std::make_pair("NA_JUNIOR_LEGAL", std::make_shared<PrintPageSize>("NA_JUNIOR_LEGAL", "Harmony", 8000, 5000)));
    pageSize_.insert(
        std::make_pair("NA_LEDGER", std::make_shared<PrintPageSize>("NA_LEDGER", "Harmony", 17000, 11000)));
    pageSize_.insert(
        std::make_pair("NA_TABLOID", std::make_shared<PrintPageSize>("NA_TABLOID", "Harmony", 11000, 17000)));
    pageSize_.insert(
        std::make_pair("NA_INDEX_3X5", std::make_shared<PrintPageSize>("NA_INDEX_3X5", "Harmony", 3000, 5000)));
    pageSize_.insert(
        std::make_pair("NA_INDEX_4X6", std::make_shared<PrintPageSize>("NA_INDEX_4X6", "Harmony", 4000, 6000)));
    pageSize_.insert(
        std::make_pair("NA_INDEX_5X8", std::make_shared<PrintPageSize>("NA_INDEX_5X8", "Harmony", 5000, 8000)));
    pageSize_.insert(std::make_pair("NA_QUARTO", std::make_shared<PrintPageSize>("NA_QUARTO", "Harmony", 8000, 10000)));
    pageSize_.insert(
        std::make_pair("NA_FOOLSCAP", std::make_shared<PrintPageSize>("NA_FOOLSCAP", "Harmony", 8000, 13000)));

    // Chinese
    pageSize_.insert(std::make_pair("ROC_8K", std::make_shared<PrintPageSize>("ROC_8K", "Harmony", 10629, 15354)));
    pageSize_.insert(std::make_pair("ROC_16K", std::make_shared<PrintPageSize>("ROC_16K", "Harmony", 7677, 10629)));
    pageSize_.insert(std::make_pair("PRC_1", std::make_shared<PrintPageSize>("PRC_1", "Harmony", 4015, 6496)));
    pageSize_.insert(std::make_pair("PRC_2", std::make_shared<PrintPageSize>("PRC_2", "Harmony", 4015, 6929)));
    pageSize_.insert(std::make_pair("PRC_3", std::make_shared<PrintPageSize>("PRC_3", "Harmony", 4921, 6929)));
    pageSize_.insert(std::make_pair("PRC_4", std::make_shared<PrintPageSize>("PRC_4", "Harmony", 4330, 8189)));
    pageSize_.insert(std::make_pair("PRC_5", std::make_shared<PrintPageSize>("PRC_5", "Harmony", 4330, 8661)));
    pageSize_.insert(std::make_pair("PRC_6", std::make_shared<PrintPageSize>("PRC_6", "Harmony", 4724, 12599)));
    pageSize_.insert(std::make_pair("PRC_7", std::make_shared<PrintPageSize>("PRC_7", "Harmony", 6299, 9055)));
    pageSize_.insert(std::make_pair("PRC_8", std::make_shared<PrintPageSize>("PRC_8", "Harmony", 4724, 12165)));
    pageSize_.insert(std::make_pair("PRC_9", std::make_shared<PrintPageSize>("PRC_9", "Harmony", 9016, 12756)));
    pageSize_.insert(std::make_pair("PRC_10", std::make_shared<PrintPageSize>("PRC_10", "Harmony", 12756, 18032)));
    pageSize_.insert(std::make_pair("PRC_16K", std::make_shared<PrintPageSize>("PRC_16K", "Harmony", 5749, 8465)));
    pageSize_.insert(
        std::make_pair("OM_PA_KAI", std::make_shared<PrintPageSize>("OM_PA_KAI", "Harmony", 10512, 15315)));
    pageSize_.insert(
        std::make_pair("OM_DAI_PA_KAI", std::make_shared<PrintPageSize>("OM_DAI_PA_KAI", "Harmony", 10827, 15551)));
    pageSize_.insert(
        std::make_pair("OM_JUURO_KU_KAI", std::make_shared<PrintPageSize>("OM_JUURO_KU_KAI", "Harmony", 7796, 10827)));

    // Japanese
    pageSize_.insert(std::make_pair("JIS_B10", std::make_shared<PrintPageSize>("JIS_B10", "Harmony", 1259, 1772)));
    pageSize_.insert(std::make_pair("JIS_B9", std::make_shared<PrintPageSize>("JIS_B9", "Harmony", 1772, 2520)));
    pageSize_.insert(std::make_pair("JIS_B8", std::make_shared<PrintPageSize>("JIS_B8", "Harmony", 2520, 3583)));
    pageSize_.insert(std::make_pair("JIS_B7", std::make_shared<PrintPageSize>("JIS_B7", "Harmony", 3583, 5049)));
    pageSize_.insert(std::make_pair("JIS_B6", std::make_shared<PrintPageSize>("JIS_B6", "Harmony", 5049, 7165)));
    pageSize_.insert(std::make_pair("JIS_B5", std::make_shared<PrintPageSize>("JIS_B5", "Harmony", 7165, 10118)));
    pageSize_.insert(std::make_pair("JIS_B4", std::make_shared<PrintPageSize>("JIS_B4", "Harmony", 10118, 14331)));
    pageSize_.insert(std::make_pair("JIS_B3", std::make_shared<PrintPageSize>("JIS_B3", "Harmony", 14331, 20276)));
    pageSize_.insert(std::make_pair("JIS_B2", std::make_shared<PrintPageSize>("JIS_B2", "Harmony", 20276, 28661)));
    pageSize_.insert(std::make_pair("JIS_B1", std::make_shared<PrintPageSize>("JIS_B1", "Harmony", 28661, 40551)));
    pageSize_.insert(std::make_pair("JIS_B0", std::make_shared<PrintPageSize>("JIS_B0", "Harmony", 40551, 57323)));
    pageSize_.insert(std::make_pair("JIS_EXEC", std::make_shared<PrintPageSize>("JIS_EXEC", "Harmony", 8504, 12992)));
    pageSize_.insert(std::make_pair("JPN_CHOU4", std::make_shared<PrintPageSize>("JPN_CHOU4", "Harmony", 3543, 8071)));
    pageSize_.insert(std::make_pair("JPN_CHOU3", std::make_shared<PrintPageSize>("JPN_CHOU3", "Harmony", 4724, 9252)));
    pageSize_.insert(std::make_pair("JPN_CHOU2", std::make_shared<PrintPageSize>("JPN_CHOU2", "Harmony", 4374, 5748)));
    pageSize_.insert(
        std::make_pair("JPN_HAGAKI", std::make_shared<PrintPageSize>("JPN_HAGAKI", "Harmony", 3937, 5827)));
    pageSize_.insert(
        std::make_pair("JPN_OUFUKU", std::make_shared<PrintPageSize>("JPN_OUFUKU", "Harmony", 5827, 7874)));
    pageSize_.insert(std::make_pair("JPN_KAHU", std::make_shared<PrintPageSize>("JPN_KAHU", "Harmony", 9449, 12681)));
    pageSize_.insert(std::make_pair("JPN_KAKU2", std::make_shared<PrintPageSize>("JPN_KAKU2", "Harmony", 9449, 13071)));
    pageSize_.insert(std::make_pair("JPN_YOU4", std::make_shared<PrintPageSize>("JPN_YOU4", "Harmony", 4134, 9252)));
}

PrintPageSize::PrintPageSize() : id_(""), name_("PrintPageSize"), width_(0), height_(0) {}

PrintPageSize::PrintPageSize(PAGE_SIZE_ID id, DiscretePageName name, uint32_t width, uint32_t height)
{
    id_ = id;
    name_ = name;
    width_ = width;
    height_ = height;
}

PrintPageSize PrintPageSize::GetPageSize(PageSizeId id)
{
    uint32_t pageSizeId = (uint32_t)id;
    if (pageSizeId < (uint32_t)sizeof(PAGE_SIZE_TABLE)) {
        std::map<PAGE_SIZE_ID, std::shared_ptr<PrintPageSize>>::iterator iter;
        iter = pageSize_.find(PAGE_SIZE_TABLE[pageSizeId]);
        if (iter != pageSize_.end()) {
            return *(iter->second);
        }
    }
    PrintPageSize printPageSize;
    return printPageSize;
}

PrintPageSize::PrintPageSize(const PrintPageSize &right)
{
    id_ = right.id_;
    name_ = right.name_;
    width_ = right.width_;
    height_ = right.height_;
}

PrintPageSize &PrintPageSize::operator=(const PrintPageSize &right)
{
    if (this != &right) {
        id_ = right.id_;
        name_ = right.name_;
        width_ = right.width_;
        height_ = right.height_;
    }
    return *this;
}

PrintPageSize::~PrintPageSize() {}

void PrintPageSize::SetId(const std::string &id)
{
    id_ = id;
}

void PrintPageSize::SetName(const std::string &name)
{
    name_ = name;
}

void PrintPageSize::SetWidth(uint32_t width)
{
    width_ = width;
}

void PrintPageSize::SetHeight(uint32_t height)
{
    height_ = height;
}

const std::string &PrintPageSize::GetId() const
{
    return id_;
}

const std::string &PrintPageSize::GetName() const
{
    return name_;
}

uint32_t PrintPageSize::GetWidth() const
{
    return width_;
}

uint32_t PrintPageSize::GetHeight() const
{
    return height_;
}

void PrintPageSize::Dump()
{
    PRINT_HILOGD("top_ = %{public}s", id_.c_str());
    PRINT_HILOGD("name_ = %{public}s", name_.c_str());
    PRINT_HILOGD("width_ = %{public}d", width_);
    PRINT_HILOGD("height_ = %{public}d", height_);
}

} // namespace OHOS::Print
