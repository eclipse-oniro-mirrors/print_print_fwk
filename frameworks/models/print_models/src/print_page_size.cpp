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
const uint32_t ISO_A7_WIDTH = 2910;
const uint32_t ISO_A7_HEIGHT = 4130;
const uint32_t ISO_A8_WIDTH = 2050;
const uint32_t ISO_A8_HEIGHT = 2910;
const uint32_t ISO_A9_WIDTH = 1460;
const uint32_t ISO_A9_HEIGHT = 2050;
const uint32_t ISO_A10_WIDTH = 1020;
const uint32_t ISO_A10_HEIGHT = 1460;
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
const uint32_t ISO_B6_WIDTH = 4920;
const uint32_t ISO_B6_HEIGHT = 6930;
const uint32_t ISO_B7_WIDTH = 3460;
const uint32_t ISO_B7_HEIGHT = 4920;
const uint32_t ISO_B8_WIDTH = 2440;
const uint32_t ISO_B8_HEIGHT = 3460;
const uint32_t ISO_B9_WIDTH = 1730;
const uint32_t ISO_B9_HEIGHT = 2440;
const uint32_t ISO_B10_WIDTH = 1220;
const uint32_t ISO_B10_HEIGHT = 1730;
const uint32_t ISO_C0_WIDTH = 36100;
const uint32_t ISO_C0_HEIGHT = 51060;
const uint32_t ISO_C1_WIDTH = 25510;
const uint32_t ISO_C1_HEIGHT = 36100;
const uint32_t ISO_C2_WIDTH = 18030;
const uint32_t ISO_C2_HEIGHT = 25510;
const uint32_t ISO_C3_WIDTH = 12760;
const uint32_t ISO_C3_HEIGHT = 18030;
const uint32_t ISO_C4_WIDTH = 9020;
const uint32_t ISO_C4_HEIGHT = 12760;
const uint32_t ISO_C5_WIDTH = 6380;
const uint32_t ISO_C5_HEIGHT = 9020;
const uint32_t ISO_C6_WIDTH = 4490;
const uint32_t ISO_C6_HEIGHT = 6380;
const uint32_t ISO_C7_WIDTH = 3190;
const uint32_t ISO_C7_HEIGHT = 4490;
const uint32_t ISO_C8_WIDTH = 2240;
const uint32_t ISO_C8_HEIGHT = 3190;
const uint32_t ISO_C9_WIDTH = 1570;
const uint32_t ISO_C9_HEIGHT = 2240;
const uint32_t ISO_C10_WIDTH = 1100;
const uint32_t ISO_C10_HEIGHT = 1570;
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
const uint32_t JIS_B0_WIDTH = 40551;
const uint32_t JIS_B0_HEIGHT = 57323;
const uint32_t JIS_B1_WIDTH = 28661;
const uint32_t JIS_B1_HEIGHT = 40551;
const uint32_t JIS_B2_WIDTH = 20276;
const uint32_t JIS_B2_HEIGHT = 28661;
const uint32_t JIS_B3_WIDTH = 14331;
const uint32_t JIS_B3_HEIGHT = 20276;
const uint32_t JIS_B4_WIDTH = 10119;
const uint32_t JIS_B4_HEIGHT = 14331;
const uint32_t JIS_B5_WIDTH = 7165;
const uint32_t JIS_B5_HEIGHT = 10118;
const uint32_t JIS_B6_WIDTH = 5049;
const uint32_t JIS_B6_HEIGHT = 7165;
const uint32_t JIS_B7_WIDTH = 3583;
const uint32_t JIS_B7_HEIGHT = 5049;
const uint32_t JIS_B8_WIDTH = 2520;
const uint32_t JIS_B8_HEIGHT = 3583;
const uint32_t JIS_B9_WIDTH = 1772;
const uint32_t JIS_B9_HEIGHT = 2520;
const uint32_t JIS_B10_WIDTH = 1259;
const uint32_t JIS_B10_HEIGHT = 1772;
const uint32_t JIS_EXEC_WIDTH = 8504;
const uint32_t JIS_EXEC_HEIGHT = 12992;
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
const uint32_t NA_ARCH_A_WIDTH = 9000;
const uint32_t NA_ARCH_A_HEIGHT = 12000;
const uint32_t NA_ARCH_B_WIDTH = 12000;
const uint32_t NA_ARCH_B_HEIGHT = 18000;
const uint32_t NA_ARCH_C_WIDTH = 18000;
const uint32_t NA_ARCH_C_HEIGHT = 24000;
const uint32_t NA_ARCH_D_WIDTH = 24000;
const uint32_t NA_ARCH_D_HEIGHT = 36000;
const uint32_t NA_ARCH_E_WIDTH = 36000;
const uint32_t NA_ARCH_E_HEIGHT = 48000;
const uint32_t JPN_CHOU2_WIDTH = 4374;
const uint32_t JPN_CHOU2_HEIGHT = 5748;
const uint32_t JPN_CHOU3_WIDTH = 4724;
const uint32_t JPN_CHOU3_HEIGHT = 9252;
const uint32_t JPN_CHOU4_WIDTH = 9252;
const uint32_t JPN_CHOU4_HEIGHT = 8071;
const uint32_t NA_FOOLSCAP_WIDTH = 8000;
const uint32_t NA_FOOLSCAP_HEIGHT = 13000;
const uint32_t NA_INDEX_3X5_WIDTH = 3000;
const uint32_t NA_INDEX_3X5_HEIGHT = 5000;
const uint32_t NA_INDEX_5X8_WIDTH = 5000;
const uint32_t NA_INDEX_5X8_HEIGHT = 8000;
const uint32_t PRC1_WIDTH = 4015;
const uint32_t PRC1_HEIGHT = 6496;
const uint32_t PRC2_WIDTH = 4015;
const uint32_t PRC2_HEIGHT = 6929;
const uint32_t PRC4_WIDTH = 4330;
const uint32_t PRC4_HEIGHT = 8189;
const uint32_t PRC6_WIDTH = 4724;
const uint32_t PRC6_HEIGHT = 12599;
const uint32_t PRC7_WIDTH = 6299;
const uint32_t PRC7_HEIGHT = 9055;
const uint32_t PRC8_WIDTH = 4724;
const uint32_t PRC8_HEIGHT = 12165;
const uint32_t PRC16_WIDTH = 5749;
const uint32_t PRC16_HEIGHT = 8465;
}

namespace OHOS::Print {
std::map<PAGE_SIZE_ID, std::shared_ptr<PrintPageSize>> PrintPageSize::pageSize_;
std::mutex PrintPageSize::pageSizeMapMutex;

void UpdatePageSizeMapOther(std::map<PAGE_SIZE_ID, std::shared_ptr<PrintPageSize>>& pageSize_)
{
    pageSize_["NA_ARCH_A"] =
        std::make_shared<PrintPageSize>("NA_ARCH_A", "na_arch-a_9x12in", NA_ARCH_A_WIDTH, NA_ARCH_A_HEIGHT);
    pageSize_["NA_ARCH_B"] =
        std::make_shared<PrintPageSize>("NA_ARCH_B", "na_arch-b_12x18in", NA_ARCH_B_WIDTH, NA_ARCH_B_HEIGHT);
    pageSize_["NA_ARCH_C"] =
        std::make_shared<PrintPageSize>("NA_ARCH_C", "na_arch-c_18x24in", NA_ARCH_C_WIDTH, NA_ARCH_C_HEIGHT);
    pageSize_["NA_ARCH_D"] =
        std::make_shared<PrintPageSize>("NA_ARCH_D", "na_arch-d_24x36in", NA_ARCH_D_WIDTH, NA_ARCH_D_HEIGHT);
    pageSize_["NA_ARCH_E"] =
        std::make_shared<PrintPageSize>("NA_ARCH_E", "na_arch-e_36x48in", NA_ARCH_E_WIDTH, NA_ARCH_E_HEIGHT);
    pageSize_["NA_FOOLSCAP"] =
        std::make_shared<PrintPageSize>("NA_FOOLSCAP", "na_foolscap_8.5x13in", NA_FOOLSCAP_WIDTH, NA_FOOLSCAP_HEIGHT);
    pageSize_["NA_LEGAL"] =
        std::make_shared<PrintPageSize>("NA_LEGAL", "na_legal_8.5x14in", LEGAL_WIDTH, LEGAL_HEIGHT);
    pageSize_["NA_LETTER"] =
        std::make_shared<PrintPageSize>("NA_LETTER", "na_letter_8.5x11in", LETTER_WIDTH, LETTER_HEIGHT);
    pageSize_["NA_INDEX_3X5"] =
        std::make_shared<PrintPageSize>("NA_INDEX_3X5", "na_index-3x5_3x5in", NA_INDEX_3X5_WIDTH, NA_INDEX_3X5_HEIGHT);
    pageSize_["NA_INDEX_5X8"] =
        std::make_shared<PrintPageSize>("NA_INDEX_5X8", "na_index-5x8_5x8in", NA_INDEX_5X8_WIDTH, NA_INDEX_5X8_HEIGHT);
    pageSize_["NA_INDEX_5X7"] =
        std::make_shared<PrintPageSize>("NA_INDEX_5X7", "na_5x7_5x7in", PHOTO_5R_WIDTH, PHOTO_5R_HEIGHT);
    pageSize_["NA_INDEX_4X6"] =
        std::make_shared<PrintPageSize>("NA_INDEX_4X6", "na_index-4x6_4x6in", PHOTO_4R_WIDTH, PHOTO_4R_HEIGHT);
    pageSize_["NA_GOVT_LETTER"] = std::make_shared<PrintPageSize>(
        "NA_GOVT_LETTER", "na_govt-letter_8x10in", NA_GOVT_LETTER_8IN_WIDTH, NA_GOVT_LETTER_8IN_HEIGHT);
    pageSize_["NA_LEDGER"] = std::make_shared<PrintPageSize>(
        "NA_LEDGER", "na_ledger_11x17in", NA_LEDGER_11IN_WIDTH, NA_LEDGER_11IN_HEIGHT);
    pageSize_["OM_DSC_PHOTO"] = std::make_shared<PrintPageSize>(
        "OM_DSC_PHOTO", "om_dsc-photo_89x119mm", OM_SDC_PHOTO_WIDTH, OM_SDC_PHOTO_HEIGHT);
    pageSize_["OM_CARD"] = std::make_shared<PrintPageSize>(
        "OM_CARD", "om_card_54x86mm", OM_CARD_WIDTH, OM_CARD_HEIGHT);
    pageSize_["OE_PHOTO_L"] = std::make_shared<PrintPageSize>(
        "OE_PHOTO_L", "oe_photo-l_3.5x5in", OE_PHOTO_L_WIDTH, OE_PHOTO_L_HEIGHT);
    pageSize_["NA_TABLOID"] = std::make_shared<PrintPageSize>(
        "NA_TABLOID", "B_TABLOID", B_TABLOID_L_WIDTH, B_TABLOID_L_HEIGHT);
}

void UpdatePageSizeMapPRC(std::map<PAGE_SIZE_ID, std::shared_ptr<PrintPageSize>>& pageSize_)
{
    pageSize_["PRC1"] =
        std::make_shared<PrintPageSize>("PRC1", "prc_1_102x165mm", PRC1_WIDTH, PRC1_HEIGHT);
    pageSize_["PRC2"] =
        std::make_shared<PrintPageSize>("PRC2", "prc_2_102x176mm", PRC2_WIDTH, PRC2_HEIGHT);
    pageSize_["PRC4"] =
        std::make_shared<PrintPageSize>("PRC4", "prc_4_110x208mm", PRC4_WIDTH, PRC4_HEIGHT);
    pageSize_["PRC6"] =
        std::make_shared<PrintPageSize>("PRC6", "prc_6_120x320mm", PRC6_WIDTH, PRC6_HEIGHT);
    pageSize_["PRC7"] =
        std::make_shared<PrintPageSize>("PRC7", "prc_7_160x230mm", PRC7_WIDTH, PRC7_HEIGHT);
    pageSize_["PRC8"] =
        std::make_shared<PrintPageSize>("PRC8", "prc_8_120x309mm", PRC8_WIDTH, PRC8_HEIGHT);
    pageSize_["PRC16"] =
        std::make_shared<PrintPageSize>("PRC16", "prc_16k_146x215mm", PRC16_WIDTH, PRC16_HEIGHT);
    pageSize_["ROC_16K"] = std::make_shared<PrintPageSize>(
        "ROC_16K", "roc_16k_7.75x10.75in", ROC_16K_WIDTH, ROC_16K_HEIGHT);
    pageSize_["ROC_8K"] = std::make_shared<PrintPageSize>(
        "ROC_8K", "roc_8k_10.75x15.5in", ROC_8K_WIDTH, ROC_8K_HEIGHT);
}

void UpdatePageSizeMapIso(std::map<PAGE_SIZE_ID, std::shared_ptr<PrintPageSize>>& pageSize_)
{
    pageSize_["ISO_A0"] =
        std::make_shared<PrintPageSize>("ISO_A0", "iso_a0_841x1189mm", ISO_A0_WIDTH, ISO_A0_HEIGHT);
    pageSize_["ISO_A1"] =
        std::make_shared<PrintPageSize>("ISO_A1", "iso_a1_594x841mm", ISO_A1_WIDTH, ISO_A1_HEIGHT);
    pageSize_["ISO_A2"] =
        std::make_shared<PrintPageSize>("ISO_A2", "iso_a2_420x594mm", ISO_A2_WIDTH, ISO_A2_HEIGHT);
    pageSize_["ISO_A3"] =
        std::make_shared<PrintPageSize>("ISO_A3", "iso_a3_297x420mm", ISO_A3_WIDTH, ISO_A3_HEIGHT);
    pageSize_["ISO_A4"] =
        std::make_shared<PrintPageSize>("ISO_A4", "iso_a4_210x297mm", ISO_A4_WIDTH, ISO_A4_HEIGHT);
    pageSize_["ISO_A5"] =
        std::make_shared<PrintPageSize>("ISO_A5", "iso_a5_148x210mm", ISO_A5_WIDTH, ISO_A5_HEIGHT);
    pageSize_["ISO_A6"] =
        std::make_shared<PrintPageSize>("ISO_A6", "iso_a6_105x148mm", ISO_A6_WIDTH, ISO_A6_HEIGHT);
    pageSize_["ISO_A7"] =
        std::make_shared<PrintPageSize>("ISO_A7", "iso_a7_74x105mm", ISO_A7_WIDTH, ISO_A7_HEIGHT);
    pageSize_["ISO_A8"] =
        std::make_shared<PrintPageSize>("ISO_A8", "iso_a8_52x74mm", ISO_A8_WIDTH, ISO_A8_HEIGHT);
    pageSize_["ISO_A9"] =
        std::make_shared<PrintPageSize>("ISO_A9", "iso_a9_37x52mm", ISO_A9_WIDTH, ISO_A9_HEIGHT);
    pageSize_["ISO_A10"] =
        std::make_shared<PrintPageSize>("ISO_A10", "iso_a10_26x37mm", ISO_A10_WIDTH, ISO_A10_HEIGHT);
    pageSize_["ISO_B0"] =
        std::make_shared<PrintPageSize>("ISO_B0", "iso_b0_1000x1414mm", ISO_B0_WIDTH, ISO_B0_HEIGHT);
    pageSize_["ISO_B1"] =
        std::make_shared<PrintPageSize>("ISO_B1", "iso_b1_707x1000mm", ISO_B1_WIDTH, ISO_B1_HEIGHT);
    pageSize_["ISO_B2"] =
        std::make_shared<PrintPageSize>("ISO_B2", "iso_b2_500x707mm", ISO_B2_WIDTH, ISO_B2_HEIGHT);
    pageSize_["ISO_B3"] =
        std::make_shared<PrintPageSize>("ISO_B3", "iso_b3_353x500mm", ISO_B3_WIDTH, ISO_B3_HEIGHT);
    pageSize_["ISO_B4"] =
        std::make_shared<PrintPageSize>("ISO_B4", "iso_b4_250x353mm", ISO_B4_WIDTH, ISO_B4_HEIGHT);
    pageSize_["ISO_B5"] =
        std::make_shared<PrintPageSize>("ISO_B5", "iso_b5_176x250mm", ISO_B5_WIDTH, ISO_B5_HEIGHT);
    pageSize_["ISO_B6"] =
        std::make_shared<PrintPageSize>("ISO_B6", "iso_b6_125x176mm", ISO_B6_WIDTH, ISO_B6_HEIGHT);
    pageSize_["ISO_B7"] =
        std::make_shared<PrintPageSize>("ISO_B7", "iso_b7_88x125mm", ISO_B7_WIDTH, ISO_B7_HEIGHT);
    pageSize_["ISO_B8"] =
        std::make_shared<PrintPageSize>("ISO_B8", "iso_b8_62x88mm", ISO_B8_WIDTH, ISO_B8_HEIGHT);
    pageSize_["ISO_B9"] =
        std::make_shared<PrintPageSize>("ISO_B9", "iso_b9_44x62mm", ISO_B9_WIDTH, ISO_B9_HEIGHT);
    pageSize_["ISO_B10"] =
        std::make_shared<PrintPageSize>("ISO_B10", "iso_b10_31x44mm", ISO_B10_WIDTH, ISO_B10_HEIGHT);
}

void UpdatePageSizeMapIsoEnv(std::map<PAGE_SIZE_ID, std::shared_ptr<PrintPageSize>>& pageSize_)
{
    pageSize_["ISO_C0"] =
        std::make_shared<PrintPageSize>("ISO_C0", "iso_c0_917x1297mm", ISO_C0_WIDTH, ISO_C0_HEIGHT);
    pageSize_["ISO_C1"] =
        std::make_shared<PrintPageSize>("ISO_C1", "iso_c1_648x917mm", ISO_C1_WIDTH, ISO_C1_HEIGHT);
    pageSize_["ISO_C2"] =
        std::make_shared<PrintPageSize>("ISO_C2", "iso_c2_458x648mm", ISO_C2_WIDTH, ISO_C2_HEIGHT);
    pageSize_["ISO_C3"] =
        std::make_shared<PrintPageSize>("ISO_C3", "iso_c3_324x458mm", ISO_C3_WIDTH, ISO_C3_HEIGHT);
    pageSize_["ISO_C4"] =
        std::make_shared<PrintPageSize>("ISO_C4", "iso_c4_229x324mm", ISO_C4_WIDTH, ISO_C4_HEIGHT);
    pageSize_["ISO_C5"] =
        std::make_shared<PrintPageSize>("ISO_C5", "iso_c5_162x229mm", ISO_C5_WIDTH, ISO_C5_HEIGHT);
    pageSize_["ISO_C6"] =
        std::make_shared<PrintPageSize>("ISO_C6", "iso_c6_114x162mm", ISO_C6_WIDTH, ISO_C6_HEIGHT);
    pageSize_["ISO_C7"] =
        std::make_shared<PrintPageSize>("ISO_C7", "iso_c7_81x114mm", ISO_C7_WIDTH, ISO_C7_HEIGHT);
    pageSize_["ISO_C8"] =
        std::make_shared<PrintPageSize>("ISO_C8", "iso_c8_57x81mm", ISO_C8_WIDTH, ISO_C8_HEIGHT);
    pageSize_["ISO_C9"] =
        std::make_shared<PrintPageSize>("ISO_C9", "iso_c9_40x57mm", ISO_C9_WIDTH, ISO_C9_HEIGHT);
    pageSize_["ISO_C10"] =
        std::make_shared<PrintPageSize>("ISO_C10", "iso_c10_28x40mm", ISO_C10_WIDTH, ISO_C10_HEIGHT);
    pageSize_["ISO_DL"] =
        std::make_shared<PrintPageSize>("ISO_DL", "iso_dl_110x220mm", ISO_DL_WIDTH, ISO_DL_HEIGHT);
}

void UpdatePageSizeMapJIS(std::map<PAGE_SIZE_ID, std::shared_ptr<PrintPageSize>>& pageSize_)
{
    pageSize_["JIS_B0"] =
        std::make_shared<PrintPageSize>("JIS_B0", "jis_b0_1030x1456mm", JIS_B0_WIDTH, JIS_B0_HEIGHT);
    pageSize_["JIS_B1"] =
        std::make_shared<PrintPageSize>("JIS_B1", "jis_b1_728x1030mm", JIS_B1_WIDTH, JIS_B1_HEIGHT);
    pageSize_["JIS_B2"] =
        std::make_shared<PrintPageSize>("JIS_B2", "jis_b2_515x728mm", JIS_B2_WIDTH, JIS_B2_HEIGHT);
    pageSize_["JIS_B3"] =
        std::make_shared<PrintPageSize>("JIS_B3", "jis_b3_364x515mm", JIS_B3_WIDTH, JIS_B3_HEIGHT);
    pageSize_["JIS_B4"] =
        std::make_shared<PrintPageSize>("JIS_B4", "jis_b4_257x364mm", JIS_B4_WIDTH, JIS_B4_HEIGHT);
    pageSize_["JIS_B5"] =
        std::make_shared<PrintPageSize>("JIS_B5", "jis_b5_182x257mm", JIS_B5_WIDTH, JIS_B5_HEIGHT);
    pageSize_["JIS_B6"] =
        std::make_shared<PrintPageSize>("JIS_B6", "jis_b6_128x182mm", JIS_B6_WIDTH, JIS_B6_HEIGHT);
    pageSize_["JIS_B7"] =
        std::make_shared<PrintPageSize>("JIS_B7", "jis_b7_91x128mm", JIS_B7_WIDTH, JIS_B7_HEIGHT);
    pageSize_["JIS_B8"] =
        std::make_shared<PrintPageSize>("JIS_B8", "jis_b8_64x91mm", JIS_B8_WIDTH, JIS_B8_HEIGHT);
    pageSize_["JIS_B9"] =
        std::make_shared<PrintPageSize>("JIS_B9", "jis_b9_45x64mm", JIS_B9_WIDTH, JIS_B9_HEIGHT);
    pageSize_["JIS_B10"] =
        std::make_shared<PrintPageSize>("JIS_B10", "jis_b10_32x45mm", JIS_B10_WIDTH, JIS_B10_HEIGHT);
    pageSize_["JIS_EXEC"] =
        std::make_shared<PrintPageSize>("JIS_EXEC", "jis_exec_216x330mm", JIS_EXEC_WIDTH, JIS_EXEC_HEIGHT);
    pageSize_["JPN_CHOU2"] =
        std::make_shared<PrintPageSize>("JPN_CHOU2", "jpn_chou2_111.1x146mm", JPN_CHOU2_WIDTH, JPN_CHOU2_HEIGHT);
    pageSize_["JPN_CHOU3"] =
        std::make_shared<PrintPageSize>("JPN_CHOU3", "jpn_chou3_120x235mm", JPN_CHOU3_WIDTH, JPN_CHOU3_HEIGHT);
    pageSize_["JPN_CHOU4"] =
        std::make_shared<PrintPageSize>("JPN_CHOU4", "jpn_chou4_90x205mm", JPN_CHOU4_WIDTH, JPN_CHOU4_HEIGHT);
    pageSize_["JPN_HAGAKI"] = std::make_shared<PrintPageSize>(
        "JPN_HAGAKI", "jpn_hagaki_100x148mm", JPN_HAGAKI_WIDTH, JPN_HAGAKI_HEIGHT);
}

void PrintPageSize::BuildPageSizeMap()
{
    UpdatePageSizeMapIso(pageSize_);
    UpdatePageSizeMapIsoEnv(pageSize_);
    UpdatePageSizeMapPRC(pageSize_);
    UpdatePageSizeMapOther(pageSize_);
    UpdatePageSizeMapJIS(pageSize_);

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
        if (strcmp(pageSizeItem->GetName().c_str(), pageString.c_str()) == 0) {
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

Json::Value PrintPageSize::ConvertToJsonObject() const
{
    Json::Value pageSizeJson;
    pageSizeJson["id_"] = id_;
    pageSizeJson["name_"] = name_;
    pageSizeJson["width_"] = width_;
    pageSizeJson["height_"] = height_;
    return pageSizeJson;
}
} // namespace OHOS::Print
