/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "print_ppd_adapter.h"
#include "print_constant.h"
#include "print_log.h"
#include "print_page_size.h"
#include <set>

namespace OHOS::Print {

const char *GetCNFromPpdAttr(ppd_file_t *ppd, const char *keyword, const char *choice, const char *defaultText);

static const StdStringMultiMap MMAP_CUPS_CHOICE_PAGE_SIZE = {
    {PAGE_SIZE_ID_ISO_A0, "A0"},
    {PAGE_SIZE_ID_ISO_A1, "A1"},
    {PAGE_SIZE_ID_ISO_A2, "A2"},
    {PAGE_SIZE_ID_ISO_A3, "A3"},
    {PAGE_SIZE_ID_ISO_A4, "A4"},
    {PAGE_SIZE_ID_ISO_A5, "A5"},
    {PAGE_SIZE_ID_ISO_A6, "A6"},
    {PAGE_SIZE_ID_ISO_A7, "A7"},
    {PAGE_SIZE_ID_ISO_A8, "A8"},
    {PAGE_SIZE_ID_ISO_A9, "A9"},
    {PAGE_SIZE_ID_ISO_A10, "A10"},
    {PAGE_SIZE_ID_ISO_B0, "ISOB0"},
    {PAGE_SIZE_ID_ISO_B1, "ISOB1"},
    {PAGE_SIZE_ID_ISO_B2, "ISOB2"},
    {PAGE_SIZE_ID_ISO_B3, "ISOB3"},
    {PAGE_SIZE_ID_ISO_B4, "ISOB4"},
    {PAGE_SIZE_ID_ISO_B5, "ISOB5"},
    {PAGE_SIZE_ID_ISO_B6, "ISOB6"},
    {PAGE_SIZE_ID_ISO_B7, "ISOB7"},
    {PAGE_SIZE_ID_ISO_B8, "ISOB8"},
    {PAGE_SIZE_ID_ISO_B9, "ISOB9"},
    {PAGE_SIZE_ID_ISO_B10, "ISOB10"},
    {PAGE_SIZE_ID_ISO_C0, "EnvC0"},
    {PAGE_SIZE_ID_ISO_C1, "EnvC1"},
    {PAGE_SIZE_ID_ISO_C2, "EnvC2"},
    {PAGE_SIZE_ID_ISO_C3, "EnvC3"},
    {PAGE_SIZE_ID_ISO_C4, "EnvC4"},
    {PAGE_SIZE_ID_ISO_C5, "EnvC5"},
    {PAGE_SIZE_ID_ISO_C6, "EnvC6"},
    {PAGE_SIZE_ID_ISO_C6, "Yougata2"},
    {PAGE_SIZE_ID_ISO_C7, "Env7"},
    {PAGE_SIZE_ID_ISO_C8, "Env8"},
    {PAGE_SIZE_ID_ISO_C9, "EnvC9"},
    {PAGE_SIZE_ID_ISO_C10, "EnvC10"},
    {PAGE_SIZE_ID_ISO_DL, "EnvDL"},
    {PAGE_SIZE_ID_ISO_DL, "envelopdlp"},
    {PAGE_SIZE_ID_JIS_B0, "B0"},
    {PAGE_SIZE_ID_JIS_B1, "B1"},
    {PAGE_SIZE_ID_JIS_B2, "B2"},
    {PAGE_SIZE_ID_JIS_B3, "B3"},
    {PAGE_SIZE_ID_JIS_B4, "B4"},
    {PAGE_SIZE_ID_JIS_B5, "B5"},
    {PAGE_SIZE_ID_JIS_B5, "JISB5"},
    {PAGE_SIZE_ID_JIS_B6, "B6"},
    {PAGE_SIZE_ID_JIS_B7, "B7"},
    {PAGE_SIZE_ID_JIS_B8, "B8"},
    {PAGE_SIZE_ID_JIS_B9, "B9"},
    {PAGE_SIZE_ID_JIS_B10, "B10"},
    {PAGE_SIZE_ID_JIS_EXEC, "216x330mm"},
    {PAGE_SIZE_ID_JPN_CHOU2, "EnvChou2"},
    {PAGE_SIZE_ID_JPN_CHOU3, "EnvChou3"},
    {PAGE_SIZE_ID_JPN_CHOU3, "Younaga3"},
    {PAGE_SIZE_ID_JPN_CHOU3, "Nagagata3"},
    {PAGE_SIZE_ID_JPN_CHOU4, "EnvChou40"},
    {PAGE_SIZE_ID_JPN_HAGAKI, "Postcard"},
    {PAGE_SIZE_ID_NA_FOOLSCAP, "Folio"},
    {PAGE_SIZE_ID_NA_FOOLSCAP, "foolscap"},
    {PAGE_SIZE_ID_NA_LEGAL, "Legal"},
    {PAGE_SIZE_ID_NA_LETTER, "Letter"},
    {PAGE_SIZE_ID_NA_EXECUTIVE, "Executive"},
    {PAGE_SIZE_ID_PRC1, "EnvPRC1"},
    {PAGE_SIZE_ID_PRC2, "EnvPRC2"},
    {PAGE_SIZE_ID_PRC4, "EnvPRC4"},
    {PAGE_SIZE_ID_PRC6, "EnvPRC6"},
    {PAGE_SIZE_ID_PRC7, "EnvPRC7"},
    {PAGE_SIZE_ID_PRC8, "EnvPRC8"},
    {PAGE_SIZE_ID_PRC16, "PRC16K"},
    {PAGE_SIZE_ID_PRC_16K, "16K"},
    {PAGE_SIZE_ID_PRC_16K, "184x260mm"},
    {PAGE_SIZE_ID_ROC_16K, "roc16k"},
    {PAGE_SIZE_ID_ROC_16K, "K16A"},
    {PAGE_SIZE_ID_ROC_16K, "197x273mm"},
    {PAGE_SIZE_ID_ROC_8K, "roc8k"},
    {PAGE_SIZE_ID_NA_INDEX_4X6, "4x6"},
    {PAGE_SIZE_ID_NA_INDEX_5X7, "5x7in"},
    {PAGE_SIZE_ID_NA_GOVT_LETTER, "8x10"},
    {PAGE_SIZE_ID_OE_PHOTO_L, "l"},
};

static const StdStringMultiMap MMAP_CUPS_CHOICE_QUALITY = {
    {CUPS_PRINT_QUALITY_DRAFT, "Draft"},
    {CUPS_PRINT_QUALITY_DRAFT, "Fast"},
    {CUPS_PRINT_QUALITY_DRAFT, "Economy"},
    {CUPS_PRINT_QUALITY_NORMAL, "Normal"},
    {CUPS_PRINT_QUALITY_NORMAL, "Standard"},
    {CUPS_PRINT_QUALITY_HIGH, "High"},
    {CUPS_PRINT_QUALITY_HIGH, "Best"},
    {CUPS_PRINT_QUALITY_HIGH, "Photo"},
};

static const StdStringMultiMap MMAP_CUPS_CHOICE_COLOR_MODEL = {
    {CUPS_PRINT_COLOR_MODE_MONOCHROME, "Gray"},
    {CUPS_PRINT_COLOR_MODE_MONOCHROME, "GrayScale"},
    {CUPS_PRINT_COLOR_MODE_MONOCHROME, "Mono"},
    {CUPS_PRINT_COLOR_MODE_MONOCHROME, "Monochrome"},
    {CUPS_PRINT_COLOR_MODE_COLOR, "RGB"},
    {CUPS_PRINT_COLOR_MODE_COLOR, "CMYK"},
    {CUPS_PRINT_COLOR_MODE_COLOR, "Color"},
};

static const StdStringMultiMap MMAP_CUPS_CHOICE_DUPLEX = {
    {CUPS_SIDES_ONE_SIDED, "None"},
    {CUPS_SIDES_TWO_SIDED_PORTRAIT, "DuplexNoTumble"},
    {CUPS_SIDES_TWO_SIDED_LANDSCAPE, "DuplexTumble"},
};

static const StdStringMultiMap MMAP_CUPS_CHOICE_MEDIA_TYPE = {
    {CUPS_MEDIA_TYPE_ENVELOPE, "Envelope"},
    {CUPS_MEDIA_TYPE_LABELS, "Label"},
    {CUPS_MEDIA_TYPE_LABELS, "Labels"},
    {CUPS_MEDIA_TYPE_LETTERHEAD, "Letterhead"},
    {CUPS_MEDIA_TYPE_PHOTO, "photographic"},
    {CUPS_MEDIA_TYPE_PHOTO_GLOSSY, "Glossy"},
    {CUPS_MEDIA_TYPE_PHOTO_MATTE, "Matte"},
    {CUPS_MEDIA_TYPE_PLAIN, "Plain"},
    {CUPS_MEDIA_TYPE_PLAIN, "Stationery"},
    {CUPS_MEDIA_TYPE_TRANSPARENCY, "Transparency"},
    {"stationery-recycled", "Recycled"},
    {"stationery-inkjet", "Inkjet"},
    {"photographic-high-gloss", "HighGloss"},
};

static const StdStringMultiMap MMAP_CUPS_CHOICE_COLLATE = {
    {PRINT_PARAM_VAL_TRUE, "True"},
    {PRINT_PARAM_VAL_FALSE, "False"},
};

static const std::string PPD_OPT_NAME_PRINTQUALITY = "cupsPrintQuality";
static const std::string PPD_OPT_NAME_QUALITY = "Quality";
static const std::string PPD_OPT_NAME_QUALITY_OUTPUT_MODE = "OutputMode";
static const std::string PPD_OPT_NAME_COLOR_MODE = "ColorModel";
static const std::string PPD_OPT_NAME_DUPLEX = "Duplex";
static const std::string PPT_OPT_NAME_JCLDUPLEX = "JCLDuplex";
static const std::string PPD_OPT_NAME_EFDUPLEX = "EFDuplex";
static const std::string PPD_OPT_NAME_EFDUPLEXING = "EFDuplexing";
static const std::string PPT_OPT_NAME_KD03DUPLEX = "KD03Duplex";
static const std::string PPT_OPT_NAME_MEDIA_TYPE = "MediaType";
static const std::string PPT_OPT_NAME_COLLATE = "Collate";
static const std::string PPD_OPT_NAME_ORIENTATION_REQUESTED = "orientation-requested";
static const std::string PPD_OPT_NAME_OUTPUT_ORDER = "OutputOrder";
static const std::string PPD_OPT_NAME_INPUT_SLOT = "InputSlot";
static const StdStringMultiMap MMAP_CUPS_CHOICE_EMPTY = {};

const std::string PPD_OPT_NAME_PAGESIZE = "PageSize";

const std::multimap<const std::string, const CupsOptionInfo> CUPS_PPD_FIELD_MMAP = {
    {PRINT_PARAM_TYPE_PAGE_SIZE,
        {PPD_OPT_NAME_PAGESIZE, MMAP_CUPS_CHOICE_PAGE_SIZE, ResolverType::CACHE_SIZES}},
    {PRINT_PARAM_TYPE_MEDIA_TYPE,
        {PPT_OPT_NAME_MEDIA_TYPE, MMAP_CUPS_CHOICE_MEDIA_TYPE, ResolverType::STANDARD}},
    {PRINT_PARAM_TYPE_QUALITY,
        {PPD_OPT_NAME_PRINTQUALITY, MMAP_CUPS_CHOICE_QUALITY, ResolverType::STANDARD}},
    {PRINT_PARAM_TYPE_QUALITY,
        {PPD_OPT_NAME_QUALITY, MMAP_CUPS_CHOICE_QUALITY, ResolverType::STANDARD}},
    {PRINT_PARAM_TYPE_QUALITY,
        {PPD_OPT_NAME_QUALITY_OUTPUT_MODE, MMAP_CUPS_CHOICE_QUALITY, ResolverType::STANDARD}},
    {PRINT_PARAM_TYPE_COLOR_MODE,
        {PPD_OPT_NAME_COLOR_MODE, MMAP_CUPS_CHOICE_COLOR_MODEL, ResolverType::STANDARD}},
    {PRINT_PARAM_TYPE_DUPLEX_MODE,
        {PPD_OPT_NAME_DUPLEX, MMAP_CUPS_CHOICE_DUPLEX, ResolverType::STANDARD}},
    {PRINT_PARAM_TYPE_DUPLEX_MODE,
        {PPT_OPT_NAME_JCLDUPLEX, MMAP_CUPS_CHOICE_DUPLEX, ResolverType::STANDARD}},
    {PRINT_PARAM_TYPE_DUPLEX_MODE,
        {PPD_OPT_NAME_EFDUPLEX, MMAP_CUPS_CHOICE_DUPLEX, ResolverType::STANDARD}},
    {PRINT_PARAM_TYPE_DUPLEX_MODE,
        {PPD_OPT_NAME_EFDUPLEXING, MMAP_CUPS_CHOICE_DUPLEX, ResolverType::STANDARD}},
    {PRINT_PARAM_TYPE_DUPLEX_MODE,
        {PPT_OPT_NAME_KD03DUPLEX, MMAP_CUPS_CHOICE_DUPLEX, ResolverType::STANDARD}},
    {PRINT_PARAM_TYPE_DELIVERY_ORDER,
        {PPT_OPT_NAME_COLLATE, MMAP_CUPS_CHOICE_COLLATE, ResolverType::STANDARD}},
    {PPD_OPT_NAME_ORIENTATION_REQUESTED,
        {PPD_OPT_NAME_ORIENTATION_REQUESTED, MMAP_CUPS_CHOICE_EMPTY, ResolverType::STANDALONE}},
    {PPD_OPT_NAME_OUTPUT_ORDER,
        {PPD_OPT_NAME_OUTPUT_ORDER, MMAP_CUPS_CHOICE_EMPTY, ResolverType::STANDALONE}},
    {PPD_OPT_NAME_INPUT_SLOT,
        {PPD_OPT_NAME_INPUT_SLOT, MMAP_CUPS_CHOICE_EMPTY, ResolverType::CACHE_SOURCES}},
};

const std::map<const std::string, const std::string> MAP_CUPS_OPTNAME_TO_TYPE = {
    {PPD_OPT_NAME_PAGESIZE, PRINT_PARAM_TYPE_PAGE_SIZE},
    {PPT_OPT_NAME_MEDIA_TYPE, PRINT_PARAM_TYPE_MEDIA_TYPE},
    {PPD_OPT_NAME_PRINTQUALITY, PRINT_PARAM_TYPE_QUALITY},
    {PPD_OPT_NAME_QUALITY, PRINT_PARAM_TYPE_QUALITY},
    {PPD_OPT_NAME_QUALITY_OUTPUT_MODE, PRINT_PARAM_TYPE_QUALITY},
    {PPD_OPT_NAME_COLOR_MODE, PRINT_PARAM_TYPE_COLOR_MODE},
    {PPD_OPT_NAME_DUPLEX, PRINT_PARAM_TYPE_DUPLEX_MODE},
    {PPT_OPT_NAME_JCLDUPLEX, PRINT_PARAM_TYPE_DUPLEX_MODE},
    {PPD_OPT_NAME_EFDUPLEX, PRINT_PARAM_TYPE_DUPLEX_MODE},
    {PPD_OPT_NAME_EFDUPLEXING, PRINT_PARAM_TYPE_DUPLEX_MODE},
    {PPT_OPT_NAME_KD03DUPLEX, PRINT_PARAM_TYPE_DUPLEX_MODE},
    {PPT_OPT_NAME_COLLATE, PRINT_PARAM_TYPE_DELIVERY_ORDER},
};

static const std::map<std::string, int> PWG_STRING_TO_ENUM_DUPLEX = {
    {CUPS_SIDES_ONE_SIDED, DUPLEX_MODE_NONE},
    {CUPS_SIDES_TWO_SIDED_PORTRAIT, DUPLEX_MODE_LONG_EDGE},
    {CUPS_SIDES_TWO_SIDED_LANDSCAPE, DUPLEX_MODE_SHORT_EDGE},
};

static const std::map<std::string, int> PWG_STRING_TO_ENUM_COLOR = {
    {CUPS_PRINT_COLOR_MODE_MONOCHROME, PRINT_COLOR_MODE_MONOCHROME},
    {CUPS_PRINT_COLOR_MODE_COLOR, PRINT_COLOR_MODE_COLOR},
};

static const std::map<std::string, int> PWG_STRING_TO_ENUM_QUALITY = {
    {CUPS_PRINT_QUALITY_DRAFT, PRINT_QUALITY_DRAFT},
    {CUPS_PRINT_QUALITY_NORMAL, PRINT_QUALITY_NORMAL},
    {CUPS_PRINT_QUALITY_HIGH, PRINT_QUALITY_HIGH},
};

static const std::map<std::string, int> PWG_STRING_TO_ENUM_PAGE_SIZE = {
    {PAGE_SIZE_ID_ISO_A3, PAGE_ISO_A3},
    {PAGE_SIZE_ID_ISO_A4, PAGE_ISO_A4},
    {PAGE_SIZE_ID_ISO_A5, PAGE_ISO_A5},
    {PAGE_SIZE_ID_JIS_B5, PAGE_JIS_B5},
    {PAGE_SIZE_ID_ISO_C5, PAGE_ISO_C5},
    {PAGE_SIZE_ID_ISO_DL, PAGE_ISO_DL},
    {PAGE_SIZE_ID_NA_LETTER, PAGE_LETTER},
    {PAGE_SIZE_ID_NA_LEGAL, PAGE_LEGAL},
    {PAGE_SIZE_ID_NA_INDEX_4X6, PAGE_PHOTO_4X6},
    {PAGE_SIZE_ID_NA_INDEX_5X7, PAGE_PHOTO_5X7},
    {PAGE_SIZE_ID_NA_TABLOID, PAGE_B_TABLOID},
};

static const std::map<std::string, const std::map<std::string, int> *> PWG_TYPE_TO_ENUM_MAP = {
    {PRINT_PARAM_TYPE_DUPLEX_MODE, &PWG_STRING_TO_ENUM_DUPLEX},
    {PRINT_PARAM_TYPE_COLOR_MODE, &PWG_STRING_TO_ENUM_COLOR},
    {PRINT_PARAM_TYPE_QUALITY, &PWG_STRING_TO_ENUM_QUALITY},
    {PRINT_PARAM_TYPE_PAGE_SIZE, &PWG_STRING_TO_ENUM_PAGE_SIZE},
};

// PWG 字符串值转为 textMap 的 int enum 字符串 key（如 "two-sided-long-edge" → "1"）
// enumMap 为空时直接返回 PWG 原始值，查找失败返回空串
static std::string ResolveTextKey(const std::string &pwgValue,
    const std::map<std::string, int> *enumMap)
{
    if (enumMap == nullptr) {
        return pwgValue;
    }
    auto it = enumMap->find(pwgValue);
    if (it == enumMap->end()) {
        return "";
    }
    return std::to_string(it->second);
}

// 在 ppd->cache 中按 PPD choice 名查找对应的 CUPS PWG 名
// CACHE_SIZES: 查 cache->sizes（如 "A4" → "iso_a4_210x297mm"）
// CACHE_SOURCES: 查 cache->sources（如 "Main" → "main"）
static bool FindCacheEntry(ppd_file_t *ppd, ResolverType resolver,
    const char *choice, std::string &pwgKey)
{
    if (resolver == ResolverType::CACHE_SIZES && ppd->cache != nullptr) {
        for (int j = 0; j < ppd->cache->num_sizes; j++) {
            if (strcmp(ppd->cache->sizes[j].map.ppd, choice) == 0) {
                pwgKey = ppd->cache->sizes[j].map.pwg;
                return true;
            }
        }
    } else if (resolver == ResolverType::CACHE_SOURCES && ppd->cache != nullptr) {
        for (int j = 0; j < ppd->cache->num_sources; j++) {
            if (strcmp(ppd->cache->sources[j].ppd, choice) == 0) {
                pwgKey = ppd->cache->sources[j].pwg;
                return true;
            }
        }
    }
    return false;
}

// 统一构建函数：遍历 PPD choices，按 ResolverType 解析 key，同时构建 optionMap choices 和 textMap
// CACHE_SIZES: 从 cache->sizes 取 PWG key，textMap key 用 PrintPageSize::MatchPageSize 转换
// CACHE_SOURCES: 从 cache->sources 取 PWG key，textMap key 用 PPD choice 名
// STANDALONE: key 和 value 都用 PPD choice 名（identity 映射）
// STANDARD: 从 reverseChoiceMap 反查 PWG 值作 key，enumMap 转 int enum 作 textMap key
static void BuildEntries(const ResolveContext &ctx, EntryResult &result)
{
    ppd_file_t *ppd = ctx.ppd;
    ppd_option_t *opt = ctx.opt;
    bool isStandalone = ctx.reverseChoiceMap->empty();
    bool useCache = (ctx.resolver == ResolverType::CACHE_SIZES ||
        ctx.resolver == ResolverType::CACHE_SOURCES) && ppd->cache != nullptr;
    for (int i = 0; i < opt->num_choices; i++) {
        std::string ppdKey;
        std::string textKey;
        if (useCache && ctx.resolver == ResolverType::CACHE_SIZES) {
            if (!FindCacheEntry(ppd, ctx.resolver, opt->choices[i].choice, ppdKey)) {
                continue;
            }
            std::string pageId = PrintPageSize::MatchPageSize(ppdKey);
            textKey = pageId.empty() ? ppdKey : pageId;
        } else if (useCache && ctx.resolver == ResolverType::CACHE_SOURCES) {
            std::string cacheKey;
            if (FindCacheEntry(ppd, ctx.resolver, opt->choices[i].choice, cacheKey)) {
                ppdKey = cacheKey;
            } else {
                ppdKey = opt->choices[i].choice;
            }
            textKey = opt->choices[i].choice;
            result.ppdChoices[ppdKey] = opt->choices[i].choice;
            result.textDefault[textKey] = opt->choices[i].text;
            result.textZhCN[textKey] = GetCNFromPpdAttr(ppd, opt->keyword,
                opt->choices[i].choice, opt->choices[i].text);
            continue;
        } else if (ctx.reverseChoiceMap->empty()) {
            ppdKey = opt->choices[i].choice;
            textKey = opt->choices[i].choice;
        } else {
            auto revIt = ctx.reverseChoiceMap->find(opt->choices[i].choice);
            if (revIt == ctx.reverseChoiceMap->end()) {
                continue;
            }
            ppdKey = revIt->second;
            textKey = ResolveTextKey(ppdKey, ctx.enumMap);
            if (textKey.empty()) {
                continue;
            }
        }
        result.ppdChoices[ppdKey] = opt->choices[i].choice;
        if (ppdKey != opt->choices[i].choice) {
            result.ppdChoices[opt->choices[i].choice] = opt->choices[i].choice;
        }
        result.textDefault[textKey] = opt->choices[i].text;
        result.textZhCN[textKey] = GetCNFromPpdAttr(ppd, opt->keyword,
            opt->choices[i].choice, opt->choices[i].text);
    }
}

// 从 CUPS_PPD_FIELD_MMAP 中查找 PWG 类型对应的第一个存在的 PPD option 变体
// 例如 Duplex 有 5 个变体（Duplex/JCLDuplex/EFDuplex/...），返回 PPD 文件中实际存在的第一个
static ppd_option_t *FindPpdOptionByPwgType(ppd_file_t *ppd, const std::string &pwgType,
    const StdStringMultiMap *&outChoiceMmap, ResolverType &outResolver)
{
    auto range = CUPS_PPD_FIELD_MMAP.equal_range(pwgType);
    for (auto it = range.first; it != range.second; ++it) {
        ppd_option_t *opt = ppdFindOption(ppd, it->second.name.c_str());
        PRINT_HILOGI("FindPpdOptionByPwgType: pwgType=%{public}s, try=%{public}s, found=%{public}d",
            pwgType.c_str(), it->second.name.c_str(), opt != nullptr);
        if (opt != nullptr) {
            outChoiceMmap = &it->second.choiceMmap;
            outResolver = it->second.resolver;
            return opt;
        }
    }
    PRINT_HILOGW("FindPpdOptionByPwgType: no option found for pwgType=%{public}s", pwgType.c_str());
    return nullptr;
}

// 将构建好的 entries 写入 optionMap 和 textMap JSON
// optionMap: {pwgType: {optionName, choices}}（供下发时 PWG→PPD 查表）
// textMap: {ppdKeyword: {default: {key: text}, zh_CN: {key: text}}}（供应用显示翻译）
static void WriteOptionMaps(ppd_option_t *opt, const std::string &pwgType,
    const EntryResult &result, Json::Value &ppdOptionMap, Json::Value &ppdOptionTextMap)
{
    if (!pwgType.empty() && !result.ppdChoices.empty()) {
        Json::Value optionEntry;
        optionEntry["optionName"] = opt->keyword;
        optionEntry["choices"] = result.ppdChoices;
        ppdOptionMap[pwgType] = optionEntry;
    }
    if (!result.textDefault.empty()) {
        Json::Value textMap;
        textMap["default"] = result.textDefault;
        textMap["zh_CN"] = result.textZhCN;
        ppdOptionTextMap[opt->keyword] = textMap;
    }
}

// 处理单个 PWG 类型的完整流程：查找 PPD option → 构建 reverseChoiceMap → BuildEntries → WriteOptionMaps
static void ProcessOptionEntry(ppd_file_t *ppd, const std::string &pwgType,
    Json::Value &ppdOptionMap, Json::Value &ppdOptionTextMap)
{
    const StdStringMultiMap *choiceMmap = nullptr;
    ResolverType resolver = ResolverType::STANDARD;
    ppd_option_t *opt = FindPpdOptionByPwgType(ppd, pwgType, choiceMmap, resolver);
    if (opt == nullptr || choiceMmap == nullptr) {
        return;
    }
    const std::map<std::string, int> *enumMap = nullptr;
    auto enumMapIt = PWG_TYPE_TO_ENUM_MAP.find(pwgType);
    if (enumMapIt != PWG_TYPE_TO_ENUM_MAP.end()) {
        enumMap = enumMapIt->second;
    }
    std::map<std::string, std::string> reverseChoiceMap;
    for (const auto &entry : *choiceMmap) {
        reverseChoiceMap[entry.second] = entry.first;
    }
    ResolveContext ctx = {ppd, opt, resolver, &reverseChoiceMap, enumMap};
    EntryResult result;
    BuildEntries(ctx, result);
    PRINT_HILOGI("ProcessOptionEntry: pwgType=%{public}s, keyword=%{public}s, "
        "choices=%{public}d, text=%{public}d",
        pwgType.c_str(), opt->keyword, result.ppdChoices.size(), result.textDefault.size());
    WriteOptionMaps(opt, pwgType, result, ppdOptionMap, ppdOptionTextMap);
}

// 从 PPD 文件构建完整的 optionMap 和 textMap
// 遍历 CUPS_PPD_FIELD_MMAP 中所有 PWG 类型，逐个调用 ProcessOptionEntry
void PpdAdapter::BuildOptionMaps(ppd_file_t *ppd, Json::Value &optionMap, Json::Value &textMap)
{
    std::set<std::string> pwgTypes;
    for (const auto &entry : CUPS_PPD_FIELD_MMAP) {
        pwgTypes.insert(entry.first);
    }
    for (const auto &pwgType : pwgTypes) {
        ProcessOptionEntry(ppd, pwgType, optionMap, textMap);
    }
}

// 单维度 PWG→PPD 查表：从 optionMap 中查找值对应的 PPD option 名和 choice 名
// optionMap choices 同时存 PWG 格式和 PPD choice 名两种 key，value 固定为 PPD choice 名
// 返回 true 表示命中，false 表示未命中（调用方应回退 PWG 标准值）
bool PpdAdapter::ConvertPwgToPpd(const Json::Value &optionMap, const std::string &pwgType,
    const std::string &pwgVal, std::string &optName, std::string &choiceName)
{
    if (pwgVal.empty() || !optionMap.isMember(pwgType)) {
        return false;
    }
    const Json::Value &entry = optionMap[pwgType];
    const Json::Value &choices = entry["choices"];
    if (!choices.isMember(pwgVal)) {
        return false;
    }
    optName = entry["optionName"].asString();
    choiceName = choices[pwgVal].asString();
    PRINT_HILOGI("PPD option: %{public}s=%{public}s", optName.c_str(), choiceName.c_str());
    return true;
}

// 纸张/介质/纸盒 all-or-nothing 查表：所有非空维度都命中 PPD 才返回 true
// CUPS 的 media 选项会覆盖 PageSize/MediaType/InputSlot，不能混发，必须全命中或全回退
bool PpdAdapter::ConvertMediaOptions(const Json::Value &optionMap,
    const std::string &mediaSize, const std::string &mediaType,
    const std::string &inputSlot,
    std::vector<std::pair<std::string, std::string>> &result)
{
    if (mediaSize.empty() && mediaType.empty() && inputSlot.empty()) {
        return false;
    }
    if (!mediaSize.empty() &&
        (!optionMap.isMember(PRINT_PARAM_TYPE_PAGE_SIZE) ||
         !optionMap[PRINT_PARAM_TYPE_PAGE_SIZE]["choices"].isMember(mediaSize))) {
        return false;
    }
    if (!mediaType.empty() &&
        (!optionMap.isMember(PRINT_PARAM_TYPE_MEDIA_TYPE) ||
         !optionMap[PRINT_PARAM_TYPE_MEDIA_TYPE]["choices"].isMember(mediaType))) {
        return false;
    }
    if (!inputSlot.empty() &&
        (!optionMap.isMember(PPD_OPT_NAME_INPUT_SLOT) ||
         !optionMap[PPD_OPT_NAME_INPUT_SLOT]["choices"].isMember(inputSlot))) {
        return false;
    }
    if (!mediaSize.empty()) {
        const Json::Value &entry = optionMap[PRINT_PARAM_TYPE_PAGE_SIZE];
        result.emplace_back(entry["optionName"].asString(),
            entry["choices"][mediaSize].asString());
    }
    if (!mediaType.empty()) {
        const Json::Value &entry = optionMap[PRINT_PARAM_TYPE_MEDIA_TYPE];
        result.emplace_back(entry["optionName"].asString(),
            entry["choices"][mediaType].asString());
    }
    if (!inputSlot.empty()) {
        const Json::Value &entry = optionMap[PPD_OPT_NAME_INPUT_SLOT];
        result.emplace_back(entry["optionName"].asString(),
            entry["choices"][inputSlot].asString());
    }
    PRINT_HILOGI("PPD media: size=%{public}s, type=%{public}s, slot=%{public}s",
        mediaSize.c_str(), mediaType.c_str(), inputSlot.c_str());
    return true;
}

}  // namespace OHOS::Print
