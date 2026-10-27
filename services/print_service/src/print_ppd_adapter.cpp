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
static const std::string PPD_OPT_NAME_JCLDUPLEX = "JCLDuplex";
static const std::string PPD_OPT_NAME_EFDUPLEX = "EFDuplex";
static const std::string PPD_OPT_NAME_EFDUPLEXING = "EFDuplexing";
static const std::string PPD_OPT_NAME_KD03DUPLEX = "KD03Duplex";
static const std::string PPD_OPT_NAME_MEDIA_TYPE = "MediaType";
static const std::string PPD_OPT_NAME_COLLATE = "Collate";
static const std::string PPD_OPT_NAME_ORIENTATION_REQUESTED = "orientation-requested";
static const std::string PPD_OPT_NAME_OUTPUT_ORDER = "OutputOrder";
const std::string PPD_OPT_NAME_INPUT_SLOT = "InputSlot";
static const StdStringMultiMap MMAP_CUPS_CHOICE_EMPTY = {};

const std::string PPD_OPT_NAME_PAGESIZE = "PageSize";

const std::multimap<const std::string, const CupsOptionInfo> CUPS_PPD_FIELD_MMAP = {
    {PRINT_PARAM_TYPE_PAGE_SIZE,
        {PPD_OPT_NAME_PAGESIZE, MMAP_CUPS_CHOICE_PAGE_SIZE, ResolverType::CACHE_SIZES}},
    {PRINT_PARAM_TYPE_MEDIA_TYPE,
        {PPD_OPT_NAME_MEDIA_TYPE, MMAP_CUPS_CHOICE_MEDIA_TYPE, ResolverType::STANDARD}},
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
        {PPD_OPT_NAME_JCLDUPLEX, MMAP_CUPS_CHOICE_DUPLEX, ResolverType::STANDARD}},
    {PRINT_PARAM_TYPE_DUPLEX_MODE,
        {PPD_OPT_NAME_EFDUPLEX, MMAP_CUPS_CHOICE_DUPLEX, ResolverType::STANDARD}},
    {PRINT_PARAM_TYPE_DUPLEX_MODE,
        {PPD_OPT_NAME_EFDUPLEXING, MMAP_CUPS_CHOICE_DUPLEX, ResolverType::STANDARD}},
    {PRINT_PARAM_TYPE_DUPLEX_MODE,
        {PPD_OPT_NAME_KD03DUPLEX, MMAP_CUPS_CHOICE_DUPLEX, ResolverType::STANDARD}},
    {PRINT_PARAM_TYPE_DELIVERY_ORDER,
        {PPD_OPT_NAME_COLLATE, MMAP_CUPS_CHOICE_COLLATE, ResolverType::STANDARD}},
    {PPD_OPT_NAME_ORIENTATION_REQUESTED,
        {PPD_OPT_NAME_ORIENTATION_REQUESTED, MMAP_CUPS_CHOICE_EMPTY, ResolverType::STANDALONE}},
    {PPD_OPT_NAME_OUTPUT_ORDER,
        {PPD_OPT_NAME_OUTPUT_ORDER, MMAP_CUPS_CHOICE_EMPTY, ResolverType::STANDALONE}},
    {PPD_OPT_NAME_INPUT_SLOT,
        {PPD_OPT_NAME_INPUT_SLOT, MMAP_CUPS_CHOICE_EMPTY, ResolverType::CACHE_SOURCES}},
};

const std::map<const std::string, const std::string> MAP_CUPS_OPTNAME_TO_TYPE = {
    {PPD_OPT_NAME_PAGESIZE, PRINT_PARAM_TYPE_PAGE_SIZE},
    {PPD_OPT_NAME_MEDIA_TYPE, PRINT_PARAM_TYPE_MEDIA_TYPE},
    {PPD_OPT_NAME_PRINTQUALITY, PRINT_PARAM_TYPE_QUALITY},
    {PPD_OPT_NAME_QUALITY, PRINT_PARAM_TYPE_QUALITY},
    {PPD_OPT_NAME_QUALITY_OUTPUT_MODE, PRINT_PARAM_TYPE_QUALITY},
    {PPD_OPT_NAME_COLOR_MODE, PRINT_PARAM_TYPE_COLOR_MODE},
    {PPD_OPT_NAME_DUPLEX, PRINT_PARAM_TYPE_DUPLEX_MODE},
    {PPD_OPT_NAME_JCLDUPLEX, PRINT_PARAM_TYPE_DUPLEX_MODE},
    {PPD_OPT_NAME_EFDUPLEX, PRINT_PARAM_TYPE_DUPLEX_MODE},
    {PPD_OPT_NAME_EFDUPLEXING, PRINT_PARAM_TYPE_DUPLEX_MODE},
    {PPD_OPT_NAME_KD03DUPLEX, PRINT_PARAM_TYPE_DUPLEX_MODE},
    {PPD_OPT_NAME_COLLATE, PRINT_PARAM_TYPE_DELIVERY_ORDER},
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

// Convert PWG string value to textMap int-enum string key (e.g. "two-sided-long-edge" -> "1")
// Return the raw PWG value when enumMap is null; return empty string on lookup miss
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

// Look up the CUPS PWG name by PPD choice name in ppd->cache
// CACHE_SIZES: search cache->sizes (e.g. "A4" -> "iso_a4_210x297mm")
// CACHE_SOURCES: search cache->sources (e.g. "Main" -> "main")
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

// Unified builder: iterate PPD choices, resolve the key by ResolverType, build optionMap choices and textMap
// CACHE_SIZES: take PWG key from cache->sizes, convert textMap key via PrintPageSize::MatchPageSize
// CACHE_SOURCES: take PWG key from cache->sources, use PPD choice name as textMap key
// STANDALONE: use PPD choice name for both key and value (identity mapping)
// STANDARD: reverse-lookup PWG value from reverseChoiceMap as key, convert to int enum via enumMap as textMap key
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
        } else if (isStandalone) {
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

// Find the first existing PPD option variant for a PWG type from CUPS_PPD_FIELD_MMAP
// e.g. Duplex has 5 variants (Duplex/JCLDuplex/EFDuplex/...); return the first one present in the PPD file
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

// Write built entries into optionMap and textMap JSON
// optionMap: {pwgType: {optionName, choices}} (for PWG->PPD lookup when sending options)
// textMap: {ppdKeyword: {default: {key: text}, zh_CN: {key: text}}} (for app display translation)
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

// Full pipeline for one PWG type: find PPD option -> build reverseChoiceMap -> BuildEntries -> WriteOptionMaps
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

// Build the complete optionMap and textMap from the PPD file
// Iterate all PWG types in CUPS_PPD_FIELD_MMAP and call ProcessOptionEntry for each
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

// Single-dimension PWG->PPD lookup: find the PPD option name and choice name for a value from optionMap
// optionMap choices store both PWG-format and PPD choice name as keys; value is always the PPD choice name
// Return true on hit, false on miss (caller should fall back to the standard PWG value)
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

// All-or-nothing media lookup: return true only if every non-empty (value, pwgType) pair hits PPD
// The CUPS media option overrides PageSize/MediaType/InputSlot and cannot be mixed; all must hit or all fall back
bool PpdAdapter::ConvertMediaOptions(const Json::Value &optionMap,
    const std::vector<std::pair<std::string, std::string>> &dims,
    std::vector<std::pair<std::string, std::string>> &result)
{
    bool hasAny = false;
    for (const auto &[value, pwgType] : dims) {
        if (!value.empty()) {
            hasAny = true;
            if (!optionMap.isMember(pwgType) ||
                !optionMap[pwgType]["choices"].isMember(value)) {
                return false;
            }
        }
    }
    if (!hasAny) {
        return false;
    }
    for (const auto &[value, pwgType] : dims) {
        if (!value.empty()) {
            const Json::Value &entry = optionMap[pwgType];
            result.emplace_back(entry["optionName"].asString(),
                entry["choices"][value].asString());
        }
    }
    return true;
}

}  // namespace OHOS::Print
