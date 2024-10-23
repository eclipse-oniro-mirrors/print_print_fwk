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

namespace {
const uint32_t ISO_A0_WIDTH  = 33110;
const uint32_t ISO_A0_HEIGHT = 46810;
const uint32_t ISO_A1_WIDTH = 23390;
const uint32_t ISO_A1_HEIGHT = 33110;
const uint32_t ISO_A2_WIDTH = 16540;
const uint32_t ISO_A2_HEIGHT = 23390;
const uint32_t ISO_A3_WIDTH = 11690;
const uint32_t ISO_A3_HEIGHT = 16540;
const uint32_t ISO_A4_WIDTH = 8268;
const uint32_t ISO_A4_HEIGHT = 11692;
const uint32_t ISO_A5_WIDTH = 5830;
const uint32_t ISO_A5_HEIGHT = 8270;
const uint32_t ISO_A6_WIDTH = 4130;
const uint32_t ISO_A6_HEIGHT = 5830;
const uint32_t ISO_B0_WIDTH = 39370;
const uint32_t ISO_B0_HEIGHT = 55670;
const uint32_t ISO_B1_WIDTH = 27830;
const uint32_t ISO_B1_HEIGHT = 39370;
const uint32_t ISO_B2_WIDTH = 19690;
const uint32_t ISO_B2_HEIGHT = 27830;
const uint32_t ISO_B3_WIDTH = 13900;
const uint32_t ISO_B3_HEIGHT = 19690;
const uint32_t ISO_B4_WIDTH = 9840;
const uint32_t ISO_B4_HEIGHT = 13900;
const uint32_t ISO_B5_WIDTH = 6930;
const uint32_t ISO_B5_HEIGHT = 9840;
const uint32_t ISO_C5_WIDTH = 6380;
const uint32_t ISO_C5_HEIGHT = 9020;
const uint32_t ISO_DL_WIDTH = 4330;
const uint32_t ISO_DL_HEIGHT = 8660;
const uint32_t LEGAL_WIDTH = 8500;
const uint32_t LEGAL_HEIGHT = 14000;
const uint32_t LETTER_WIDTH = 8500;
const uint32_t LETTER_HEIGHT = 11000;
const uint32_t ROC_16K_WIDTH = 7677;
const uint32_t ROC_16K_HEIGHT = 10629;
const uint32_t ROC_8K_WIDTH = 10629;
const uint32_t ROC_8K_HEIGHT = 15354;
const uint32_t JIS_B4_WIDTH = 10119;
const uint32_t JIS_B4_HEIGHT = 14331;
const uint32_t JIS_B5_WIDTH = 7165;
const uint32_t JIS_B5_HEIGHT = 10118;
const uint32_t PHOTO_5R_WIDTH = 5000;
const uint32_t PHOTO_5R_HEIGHT = 7000;
const uint32_t PHOTO_4R_WIDTH = 4000;
const uint32_t PHOTO_4R_HEIGHT = 6000;
const uint32_t NA_GOVT_LETTER_8IN_WIDTH = 8000;
const uint32_t NA_GOVT_LETTER_8IN_HEIGHT = 10000;
const uint32_t NA_LEDGER_11IN_WIDTH = 11000;
const uint32_t NA_LEDGER_11IN_HEIGHT = 17000;
const uint32_t JPN_HAGAKI_WIDTH = 3940;
const uint32_t JPN_HAGAKI_HEIGHT = 5830;
const uint32_t OM_SDC_PHOTO_WIDTH = 3504;
const uint32_t OM_SDC_PHOTO_HEIGHT = 4685;
const uint32_t OM_CARD_WIDTH = 2126;
const uint32_t OM_CARD_HEIGHT = 3386;
const uint32_t OE_PHOTO_L_WIDTH = 3500;
const uint32_t OE_PHOTO_L_HEIGHT = 5000;
const uint32_t B_TABLOID_L_WIDTH = 11000;
const uint32_t B_TABLOID_L_HEIGHT = 17000;
}

namespace OHOS::Print {
std::map<PAGE_SIZE_ID, std::shared_ptr<PrintPageSize>> PrintPageSize::pageSize_;
std::mutex PrintPageSize::pageSizeMapMutex;

void UpdatePageSizeMapIso(std::map<PAGE_SIZE_ID, std::shared_ptr<PrintPageSize>>& pageSizeMap)
{
    pageSizeMap["ISO_A0"] =
        std::make_shared<PrintPageSize>("ISO_A0", "iso_a0_841x1189mm", ISO_A0_WIDTH, ISO_A0_HEIGHT);
    pageSizeMap["ISO_A1"] =
        std::make_shared<PrintPageSize>("ISO_A1", "iso_a1_594x841mm", ISO_A1_WIDTH, ISO_A1_HEIGHT);
    pageSizeMap["ISO_A2"] =
        std::make_shared<PrintPageSize>("ISO_A2", "iso_a2_420x594mm", ISO_A2_WIDTH, ISO_A2_HEIGHT);
    pageSizeMap["ISO_A3"] =
        std::make_shared<PrintPageSize>("ISO_A3", "iso_a3_297x420mm", ISO_A3_WIDTH, ISO_A3_HEIGHT);
    pageSizeMap["ISO_A4"] =
        std::make_shared<PrintPageSize>("ISO_A4", "iso_a4_210x297mm", ISO_A4_WIDTH, ISO_A4_HEIGHT);
    pageSizeMap["ISO_A5"] =
        std::make_shared<PrintPageSize>("ISO_A5", "iso_a5_148x210mm", ISO_A5_WIDTH, ISO_A5_HEIGHT);
    pageSizeMap["ISO_A6"] =
        std::make_shared<PrintPageSize>("ISO_A6", "iso_a6_105x148mm", ISO_A6_WIDTH, ISO_A6_HEIGHT);
    pageSizeMap["ISO_B0"] =
        std::make_shared<PrintPageSize>("ISO_B0", "iso_b0_1000x1414mm", ISO_B0_WIDTH, ISO_B0_HEIGHT);
    pageSizeMap["ISO_B1"] =
        std::make_shared<PrintPageSize>("ISO_B1", "iso_b1_707x1000mm", ISO_B1_WIDTH, ISO_B1_HEIGHT);
    pageSizeMap["ISO_B2"] =
        std::make_shared<PrintPageSize>("ISO_B2", "iso_b2_500x707mm", ISO_B2_WIDTH, ISO_B2_HEIGHT);
    pageSizeMap["ISO_B3"] =
        std::make_shared<PrintPageSize>("ISO_B3", "iso_b3_353x500mm", ISO_B3_WIDTH, ISO_B3_HEIGHT);
    pageSizeMap["ISO_B4"] =
        std::make_shared<PrintPageSize>("ISO_B4", "iso_b4_250x353mm", ISO_B4_WIDTH, ISO_B4_HEIGHT);
    pageSizeMap["ISO_B5"] =
        std::make_shared<PrintPageSize>("ISO_B5", "iso_b5_176x250mm", ISO_B5_WIDTH, ISO_B5_HEIGHT);
    pageSizeMap["ISO_C5"] =
        std::make_shared<PrintPageSize>("ISO_C5", "iso_c5_162x229mm", ISO_C5_WIDTH, ISO_C5_HEIGHT);
    pageSizeMap["ISO_DL"] =
        std::make_shared<PrintPageSize>("ISO_DL", "iso_dl_110x220mm", ISO_DL_WIDTH, ISO_DL_HEIGHT);
}
void PrintPageSize::BuildPageSizeMap()
{
    UpdatePageSizeMapIso(pageSize_);
    pageSize_["NA_LEGAL"] =
        std::make_shared<PrintPageSize>("NA_LEGAL", "na_legal_8.5x14in", LEGAL_WIDTH, LEGAL_HEIGHT);
    pageSize_["NA_LETTER"] =
        std::make_shared<PrintPageSize>("NA_LETTER", "na_letter_8.5x11in", LETTER_WIDTH, LETTER_HEIGHT);
    pageSize_["JIS_B5"] =
        std::make_shared<PrintPageSize>("JIS_B5", "jis_b5_182x257mm", JIS_B5_WIDTH, JIS_B5_HEIGHT);
    pageSize_["JIS_B4"] =
        std::make_shared<PrintPageSize>("JIS_B4", "jis_b4_257x364mm", JIS_B4_WIDTH, JIS_B4_HEIGHT);
    pageSize_["NA_INDEX_5X7"] =
        std::make_shared<PrintPageSize>("NA_INDEX_5X7", "na_5x7_5x7in", PHOTO_5R_WIDTH, PHOTO_5R_HEIGHT);
    pageSize_["NA_INDEX_4X6"] =
        std::make_shared<PrintPageSize>("NA_INDEX_4X6", "na_index-4x6_4x6in", PHOTO_4R_WIDTH, PHOTO_4R_HEIGHT);
    pageSize_["NA_GOVT_LETTER"] = std::make_shared<PrintPageSize>(
        "NA_GOVT_LETTER", "na_govt-letter_8x10in", NA_GOVT_LETTER_8IN_WIDTH, NA_GOVT_LETTER_8IN_HEIGHT);
    pageSize_["NA_LEDGER"] = std::make_shared<PrintPageSize>(
        "NA_LEDGER", "na_ledger_11x17in", NA_LEDGER_11IN_WIDTH, NA_LEDGER_11IN_HEIGHT);
    pageSize_["JPN_HAGAKI"] = std::make_shared<PrintPageSize>(
        "JPN_HAGAKI", "jpn_hagaki_100x148mm", JPN_HAGAKI_WIDTH, JPN_HAGAKI_HEIGHT);
    pageSize_["OM_DSC_PHOTO"] = std::make_shared<PrintPageSize>(
        "OM_DSC_PHOTO", "om_dsc-photo_89x119mm", OM_SDC_PHOTO_WIDTH, OM_SDC_PHOTO_HEIGHT);
    pageSize_["OM_CARD"] = std::make_shared<PrintPageSize>(
        "OM_CARD", "om_card_54x86mm", OM_CARD_WIDTH, OM_CARD_HEIGHT);
    pageSize_["OE_PHOTO_L"] = std::make_shared<PrintPageSize>(
        "OE_PHOTO_L", "oe_photo-l_3.5x5in", OE_PHOTO_L_WIDTH, OE_PHOTO_L_HEIGHT);
    pageSize_["NA_TABLOID"] = std::make_shared<PrintPageSize>(
        "NA_TABLOID", "B_TABLOID", B_TABLOID_L_WIDTH, B_TABLOID_L_HEIGHT);
    pageSize_["ROC_16K"] = std::make_shared<PrintPageSize>(
        "ROC_16K", "roc_16k_7.75x10.75in", ROC_16K_WIDTH, ROC_16K_HEIGHT);
    pageSize_["ROC_8K"] = std::make_shared<PrintPageSize>(
        "ROC_8K", "roc_8k_10.75x15.5in", ROC_8K_WIDTH, ROC_8K_HEIGHT);
    PRINT_HILOGD("BuildPageSizeMap count = %{public}zu", pageSize_.size());
}

PAGE_SIZE_ID PrintPageSize::MatchPageSize(const std::string& pageString)
{
    std::lock_guard<std::mutex> lock(pageSizeMapMutex);
    if (pageSize_.size() == 0) {
        BuildPageSizeMap();
    }
    for (auto& item : pageSize_) {
        auto pageSizeItem = item.second;
        if (pageSizeItem == nullptr) {
            continue;
        }
        if (strcasestr(pageSizeItem->GetName().c_str(), pageString.c_str()) != nullptr) {
            return item.first;
        }
    }
    return "";
}

bool PrintPageSize::FindPageSizeById(const PAGE_SIZE_ID &id, PrintPageSize& pageSize)
{
    std::lock_guard<std::mutex> lock(pageSizeMapMutex);
    if (pageSize_.size() == 0) {
        BuildPageSizeMap();
    }
    auto iter = pageSize_.find(id);
    if (iter == pageSize_.end() || iter->second == nullptr) {
        return false;
    }
    pageSize = *(iter->second);
    return true;
}

PrintPageSize::PrintPageSize() : id_(""), name_("PrintPageSize"), width_(0), height_(0)
{}

PrintPageSize::PrintPageSize(PAGE_SIZE_ID id, DiscretePageName name, uint32_t width, uint32_t height)
{
    id_ = id;
    name_ = name;
    width_ = width;
    height_ = height;
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

bool PrintPageSize::operator==(const PrintPageSize &right)
{
    return id_ == right.id_;
}

PrintPageSize::~PrintPageSize()
{}

void PrintPageSize::Reset()
{
    SetId("");
    SetName("");
    SetWidth(0);
    SetHeight(0);
}

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

void PrintPageSize::ReadFromParcel(Parcel &parcel)
{
    SetId(parcel.ReadString());
    SetName(parcel.ReadString());
    SetWidth(parcel.ReadUint32());
    SetHeight(parcel.ReadUint32());
}

bool PrintPageSize::Marshalling(Parcel &parcel) const
{
    parcel.WriteString(GetId());
    parcel.WriteString(GetName());
    parcel.WriteUint32(GetWidth());
    parcel.WriteUint32(GetHeight());
    return true;
}

std::shared_ptr<PrintPageSize> PrintPageSize::Unmarshalling(Parcel &parcel)
{
    auto nativeObj = std::make_shared<PrintPageSize>();
    nativeObj->ReadFromParcel(parcel);
    return nativeObj;
}

void PrintPageSize::Dump()
{
    PRINT_HILOGD("id_ = %{public}s", id_.c_str());
    PRINT_HILOGD("name_ = %{public}s", name_.c_str());
    PRINT_HILOGD("width_ = %{public}d", width_);
    PRINT_HILOGD("height_ = %{public}d", height_);
}
} // namespace OHOS::Print
