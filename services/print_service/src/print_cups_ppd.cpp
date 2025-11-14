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

#include "print_cups_ppd.h"
#include "print_service_converter.h"
#include "print_log.h"


namespace OHOS::Print {
using namespace std;

const std::vector<std::string> baseOptionStr = {
    "PageSize",
    "PageRegion",
    "MediaType",
    "ColorModel",
    "OutputMode",
    "cupsPrintQuality",
    "Duplex",
    "JCLDuplex",
    "EFDuplex",
    "EFDuplexing",
    "KD03Duplex",
    "Collate",
    "OutputOrder",
    "CNGrayscale",
    "BRMonoColor"
};

using StdStringMultiMap = std::multimap<const std::string, const std::string>;
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
    {PAGE_SIZE_ID_JIS_B0, "B0"},
    {PAGE_SIZE_ID_JIS_B1, "B1"},
    {PAGE_SIZE_ID_JIS_B2, "B2"},
    {PAGE_SIZE_ID_JIS_B3, "B3"},
    {PAGE_SIZE_ID_JIS_B4, "B4"},
    {PAGE_SIZE_ID_JIS_B5, "B5"},
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
    {PAGE_SIZE_ID_ROC_16K, "roc16k"},
    {PAGE_SIZE_ID_ROC_8K, "roc8k"},
};

static const StdStringMultiMap MMAP_CUPS_CHOICE_QUALITY = {
    {CUPS_PRINT_QUALITY_DRAFT, "Draft"},
    {CUPS_PRINT_QUALITY_DRAFT, "Fast"},
    {CUPS_PRINT_QUALITY_NORMAL, "Normal"},
    {CUPS_PRINT_QUALITY_HIGH, "High"},
    {CUPS_PRINT_QUALITY_HIGH, "Best"},
};

static const StdStringMultiMap MMAP_CUPS_CHOICE_COLOR_MODEL = {
    {CUPS_PRINT_COLOR_MODE_MONOCHROME, "Gray"},
    {CUPS_PRINT_COLOR_MODE_MONOCHROME, "monochrome"},
    {CUPS_PRINT_COLOR_MODE_COLOR, "RGB"},
    {CUPS_PRINT_COLOR_MODE_COLOR, "CMYK"},
    {CUPS_PRINT_COLOR_MODE_COLOR, "color"},
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

static const std::string PPD_OPT_NAME_PAGESIZE = "PageSize";
static const std::string PPT_OPT_NAME_MEDIA_TYPE = "MediaType";
static const std::string PPD_OPT_NAME_PRINTQUALITY = "cupsPrintQuality";
static const std::string PPD_OPT_NAME_QUALITY = "Quality";
static const std::string PPD_OPT_NAME_QUALITY_OUTPUT_MODE = "OutputMode";
static const std::string PPD_OPT_NAME_COLOR_MODE = "ColorModel";
static const std::string PPD_OPT_NAME_DUPLEX = "Duplex";
static const std::string PPT_OPT_NAME_JCLDUPLEX = "JCLDuplex";
static const std::string PPD_OPT_NAME_EFDUPLEX = "EFDuplex";
static const std::string PPD_OPT_NAME_EFDUPLEXING = "EFDuplexing";
static const std::string PPT_OPT_NAME_KD03DUPLEX = "KD03Duplex";
static const std::string PPT_OPT_NAME_COLLATE = "Collate";

struct CupsOptionInfo {
    // Avoid redundant copy, must point to static variables.
    const std::string &name;
    const StdStringMultiMap &choiceMmap;
};

static const std::multimap<const std::string, const CupsOptionInfo> CUPS_PPD_FIELD_MMAP = {
    {PRINT_PARAM_TYPE_PAGE_SIZE, {PPD_OPT_NAME_PAGESIZE, MMAP_CUPS_CHOICE_PAGE_SIZE}},
    {PRINT_PARAM_TYPE_MEDIA_TYPE, {PPT_OPT_NAME_MEDIA_TYPE, MMAP_CUPS_CHOICE_MEDIA_TYPE}},
    {PRINT_PARAM_TYPE_QUALITY, {PPD_OPT_NAME_PRINTQUALITY, MMAP_CUPS_CHOICE_QUALITY}},
    {PRINT_PARAM_TYPE_QUALITY, {PPD_OPT_NAME_QUALITY, MMAP_CUPS_CHOICE_QUALITY}},
    {PRINT_PARAM_TYPE_QUALITY, {PPD_OPT_NAME_QUALITY_OUTPUT_MODE, MMAP_CUPS_CHOICE_QUALITY}},
    {PRINT_PARAM_TYPE_COLOR_MODE, {PPD_OPT_NAME_COLOR_MODE, MMAP_CUPS_CHOICE_COLOR_MODEL}},
    {PRINT_PARAM_TYPE_DUPLEX_MODE, {PPD_OPT_NAME_DUPLEX, MMAP_CUPS_CHOICE_DUPLEX}},
    {PRINT_PARAM_TYPE_DUPLEX_MODE, {PPT_OPT_NAME_JCLDUPLEX, MMAP_CUPS_CHOICE_DUPLEX}},
    {PRINT_PARAM_TYPE_DUPLEX_MODE, {PPD_OPT_NAME_EFDUPLEX, MMAP_CUPS_CHOICE_DUPLEX}},
    {PRINT_PARAM_TYPE_DUPLEX_MODE, {PPD_OPT_NAME_EFDUPLEXING, MMAP_CUPS_CHOICE_DUPLEX}},
    {PRINT_PARAM_TYPE_DUPLEX_MODE, {PPT_OPT_NAME_KD03DUPLEX, MMAP_CUPS_CHOICE_DUPLEX}},
    {PRINT_PARAM_TYPE_DELIVERY_ORDER, {PPT_OPT_NAME_COLLATE, MMAP_CUPS_CHOICE_COLLATE}},
};

static const std::map<const std::string, const std::string> MAP_CUPS_OPTNAME_TO_TYPE = {
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

const char *GetCNFromPpdAttr(ppd_file_t *ppd, const char *keyword, const char* choice, const char* defaultText)
{
    ppd_attr_t *locattrCN = _ppdLocalizedAttr(ppd, keyword, choice, "zh_CN");
    if (!locattrCN) {
        return defaultText;
    }

    return locattrCN->text;
}

void GetAdvanceOptJsSingleJSFromOption(ppd_file_t *ppd, ppd_option_t *opt, Json::Value& advanceOptJsSingle)
{
    Json::Value advanceChoiceJs;
    Json::Value advanceChoiceJsDefaultLanguage;
    Json::Value advanceChoiceJsCNLanguage;
    Json::Value advanceOptionTextJs;

    PRINT_HILOGI("option=%{public}s default=%{public}s text=%{public}s\n", opt->keyword, opt->defchoice, opt->text);
    ppd_choice_t* choices = opt->choices;
    for (int k = 0; k < opt->num_choices; k++) {
        if (choices + k == nullptr) {
            PRINT_HILOGE("PPD choice found error: %{public}s", opt->keyword);
            break;
        }
        if (!strcmp(choices[k].choice, "Custom") && ppdFindCustomOption(ppd, opt->keyword)) {
            PRINT_HILOGI("Ignore Custom PPD Choice: %{public}s", opt->keyword);
            continue;
        }
        advanceChoiceJsDefaultLanguage[choices[k].choice] = choices[k].text;
        advanceChoiceJsCNLanguage[choices[k].choice] = GetCNFromPpdAttr(ppd, opt->keyword, choices[k].choice,
            choices[k].text);
    }
    advanceChoiceJs["default"] = advanceChoiceJsDefaultLanguage;
    advanceChoiceJs["zh_CN"] = advanceChoiceJsCNLanguage;
    advanceOptionTextJs["default"] = opt->text;
    advanceOptionTextJs["zh_CN"] = GetCNFromPpdAttr(ppd, "Translation", opt->keyword, opt->text);
    advanceOptJsSingle["choice"] = advanceChoiceJs;
    advanceOptJsSingle["keyword"] = opt->keyword;
    advanceOptJsSingle["optionText"] = advanceOptionTextJs;
    advanceOptJsSingle["uiType"] = opt->ui;
}

void GetAdvanceOptionsFromPPD(ppd_file_t *ppd, PrinterCapability &printerCaps)
{
    cups_array_t *options_arr = ppd->options;
    Json::Value advanceOptJs;
    Json::Value advanceDefaultJs;
    for (ppd_option_t *opt = (ppd_option_t*)cupsArrayFirst(options_arr);
        opt != nullptr; opt = (ppd_option_t*)cupsArrayNext(options_arr)) {
        if (advanceOptJs.size() > ADVANCE_OPTION_MAXLENGTH) {
            PRINT_HILOGE("AdvanceOption size is over max length!");
            break;
        }
        if (std::find(baseOptionStr.begin(), baseOptionStr.end(), string(opt->keyword)) != baseOptionStr.end()) {
            continue;
        }
        if (opt->ui == PPD_UI_PICKMANY) {
            PRINT_HILOGW("PPD_UI_PICKMANY Found: %{public}s", opt->keyword);
            continue;
        }
        advanceDefaultJs[opt->keyword] = opt->defchoice;
        Json::Value advanceOptJsSingle;
        GetAdvanceOptJsSingleJSFromOption(ppd, opt, advanceOptJsSingle);
        advanceOptJs.append(advanceOptJsSingle);
    }
    printerCaps.SetPrinterAttrNameAndValue("advanceOptions", PrintJsonUtil::WriteString(advanceOptJs).c_str());
    printerCaps.SetPrinterAttrNameAndValue("advanceDefault", PrintJsonUtil::WriteString(advanceDefaultJs).c_str());
}

void FindDefaultPageSize(_ppd_cache_t *ppdCache, ppd_option_t *sizeOption, PrinterCapability &printerCaps)
{
    // find default media size
    if (sizeOption && sizeOption->defchoice) {
        pwg_size_t *pwgSize = _ppdCacheGetSize(ppdCache, sizeOption->defchoice);
        if (pwgSize == nullptr) {
            PRINT_HILOGE("Failed to get default page size, pwgSize is nullptr.");
            return;
        }
        PRINT_HILOGI("Default page size: %{public}s, defchoice : %{public}s", pwgSize->map.ppd, sizeOption->defchoice);
        std::string defaultPageSizeId;
        if (!ConvertPageSizeId(pwgSize->map.pwg, defaultPageSizeId)) {
            defaultPageSizeId = std::string(pwgSize->map.ppd);
        }
        printerCaps.SetPrinterAttrNameAndValue("defaultPageSizeId", defaultPageSizeId.c_str());
    } else {
        PRINT_HILOGE("Default page size: None");
    }
}

void ParsePageSizeAttributesFromPPD(ppd_file_t *ppd, PrinterCapability &printerCaps)
{
    Json::Value mediaSizeMap;
    Json::Value mediaSizeMapDefaultLanguage;
    Json::Value mediaSizeMapCNLanguage;
    _ppd_cache_t *ppdCache = ppd->cache;
    pwg_size_t *cacheSizes = ppdCache->sizes;
    if (cacheSizes == nullptr) {
        PRINT_HILOGE("cacheSizes get nullptr!");
        return;
    }
    std::vector<PrintPageSize> supportedPageSizes;
    ppd_option_t *sizeOption = ppdFindOption(ppd, "PageSize");

    for (int i = 0; i < ppdCache->num_sizes; i++) {
        pwg_size_t pwgSize = cacheSizes[i];
        ppd_choice_t *sizeChoice = ppdFindChoice(sizeOption, pwgSize.map.ppd);
        if (sizeChoice == nullptr) {
            PRINT_HILOGE("sizeChoice get nullptr!");
            return;
        }
        std::string id = PrintPageSize::MatchPageSize(pwgSize.map.pwg);
        PrintPageSize dst;
        if (!id.empty()) {
            PrintPageSize::FindPageSizeById(id, dst);
        } else {
            dst = PrintPageSize(sizeChoice->text, pwgSize.map.pwg,
                round(pwgSize.width * HUNDRED_OF_MILLIMETRE_TO_INCH / ONE_HUNDRED),
                round(pwgSize.length * HUNDRED_OF_MILLIMETRE_TO_INCH / ONE_HUNDRED));
        }
        supportedPageSizes.emplace_back(dst);

        mediaSizeMapDefaultLanguage[pwgSize.map.pwg] = sizeChoice->text;
        mediaSizeMapCNLanguage[pwgSize.map.pwg] = GetCNFromPpdAttr(ppd, "PageSize",
            sizeChoice->choice, sizeChoice->text);
    }
    mediaSizeMap["default"] = mediaSizeMapDefaultLanguage;
    mediaSizeMap["zh_CN"] = mediaSizeMapCNLanguage;
    printerCaps.SetSupportedPageSize(supportedPageSizes);
    printerCaps.SetPrinterAttrNameAndValue("mediaSizeMap", PrintJsonUtil::WriteString(mediaSizeMap).c_str());
    FindDefaultPageSize(ppdCache, sizeOption, printerCaps);
}

void ParseDuplexModeAttributesFromPPD(ppd_file_t *ppd, PrinterCapability &printerCaps)
{
    _ppd_cache_t *ppdCache = ppd->cache;
    std::vector<DuplexModeCode> supportedDuplexModeList = { DUPLEX_MODE_ONE_SIDED };
    if (ppdCache->sides_2sided_long) {
        supportedDuplexModeList.emplace_back(DUPLEX_MODE_TWO_SIDED_LONG_EDGE);
    }
    if (ppdCache->sides_2sided_short) {
        supportedDuplexModeList.emplace_back(DUPLEX_MODE_TWO_SIDED_SHORT_EDGE);
    }
    printerCaps.SetSupportedDuplexMode(std::vector<uint32_t>(supportedDuplexModeList.begin(),
        supportedDuplexModeList.end()));
    if (static_cast<int>(supportedDuplexModeList.size()) <= 1) {
        printerCaps.SetDuplexMode((uint32_t)DUPLEX_MODE_ONE_SIDED);
    } else {
        printerCaps.SetDuplexMode((uint32_t)DUPLEX_MODE_TWO_SIDED_LONG_EDGE);
    }
    std::string duplexModeJson = ConvertListToJson<DuplexModeCode>(supportedDuplexModeList, ConvertDuplexModeToJson);
    printerCaps.SetPrinterAttrNameAndValue("sides-supported", duplexModeJson.c_str());
    // find default duplex mode
    ppd_option_t *duplex = nullptr;
    DuplexModeCode code = DUPLEX_MODE_ONE_SIDED;
    const std::vector<std::string> duplexOptions = { "Duplex", "EFDuplex", "EFDuplexing", "KD03Duplex", "JCLDuplex" };
    for (const auto& option : duplexOptions) {
        duplex = ppdFindOption(ppd, option.c_str());
        if (duplex != nullptr) {
            break;
        }
    }
    // save duplex default option
    if (duplex && duplex->num_choices > 1) {
        if (!strcmp(duplex->defchoice, "DuplexTumble"))
            code = DUPLEX_MODE_TWO_SIDED_SHORT_EDGE;
        else if (!strcmp(duplex->defchoice, "DuplexNoTumble"))
            code = DUPLEX_MODE_TWO_SIDED_LONG_EDGE;
    }
    uint32_t value = static_cast<uint32_t>(code);
    printerCaps.SetPrinterAttrNameAndValue("sides-default", std::to_string(value).c_str());
}

void ParseMediaTypeAttributeFromPPD(ppd_file_t *ppd, PrinterCapability &printerCaps)
{
    ppd_option_t *typeOption = ppdFindOption(ppd, "MediaType");
    if (typeOption == nullptr) {
        PRINT_HILOGE("ppdFindOption MediaType fail!");
        return;
    }
    _ppd_cache_t *ppdCache = ppd->cache;
    Json::Value jsonArray;
    Json::Value jsonArrayDefaultLanguage;
    Json::Value jsonArrayCNLanguage;
    
    // compatible with Spooler USB
    Json::Value jsonArrayOld;

    std::vector<std::string> supportedMediaTypeList;
    for (int i = 0; i < ppdCache->num_types; i++) {
        if (ppdCache->types + i == nullptr) {
            PRINT_HILOGE("ppdCache types is nullptr!");
            return;
        }
        ppd_choice_t *typeChoice = ppdFindChoice(typeOption, ppdCache->types[i].ppd);
        if (typeChoice == nullptr) {
            PRINT_HILOGE("typeChoice is nullptr!");
            return;
        }
        jsonArrayDefaultLanguage[ppdCache->types[i].pwg] = typeChoice->text;
        jsonArrayCNLanguage[ppdCache->types[i].pwg] = GetCNFromPpdAttr(ppd, "MediaType",
            typeChoice->choice, typeChoice->text);
        // compatible with Spooler USB
        jsonArrayOld.append(ppdCache->types[i].pwg);

        supportedMediaTypeList.emplace_back(std::string(ppdCache->types[i].pwg));
    }
    jsonArray["default"] = jsonArrayDefaultLanguage;
    jsonArray["zh_CN"] = jsonArrayCNLanguage;
    printerCaps.SetSupportedMediaType(supportedMediaTypeList);

    if (!supportedMediaTypeList.empty()) {
        printerCaps.SetPrinterAttrNameAndValue("mediaTypeMap", PrintJsonUtil::WriteString(jsonArray).c_str());
        // compatible with Spooler USB
        printerCaps.SetPrinterAttrNameAndValue("media-type-supported",
            PrintJsonUtil::WriteString(jsonArrayOld).c_str());
    }

    // handle media type default option
    if (typeOption->defchoice == nullptr) {
        PRINT_HILOGE("typeOption->defchoice fail!");
        return;
    }
    const char *typeDefault = _ppdCacheGetType(ppdCache, typeOption->defchoice);
    if (typeDefault == nullptr) {
        PRINT_HILOGE("_ppdCacheGetType typeDefault fail! typeOption: %{public}s", typeOption->defchoice);
        return;
    }
    printerCaps.SetPrinterAttrNameAndValue("media-type-default", typeDefault);
}

void ParseColorModeAttributesFromPPD(ppd_file_t *ppd, PrinterCapability &printerCaps)
{
    std::vector<ColorModeCode> supportedColorModes = { ColorModeCode::COLOR_MODE_MONOCHROME };
    ColorModeCode defaultColor = ColorModeCode::COLOR_MODE_MONOCHROME;
    printerCaps.SetColorMode(ColorModeCode::COLOR_MODE_MONOCHROME);
    if (ppd->color_device) {
        printerCaps.SetColorMode(ColorModeCode::COLOR_MODE_COLOR);
        supportedColorModes.emplace_back(ColorModeCode::COLOR_MODE_COLOR);
        defaultColor = ColorModeCode::COLOR_MODE_COLOR;
    }
    printerCaps.SetSupportedColorMode(std::vector<uint32_t>(supportedColorModes.begin(), supportedColorModes.end()));

    std::string keyword = "print-color-mode-supported";
    std::string colorModeJson = ConvertListToJson<ColorModeCode>(supportedColorModes, ConvertColorModeToJson);
    printerCaps.SetPrinterAttrNameAndValue(keyword.c_str(), colorModeJson.c_str());

    uint32_t mode = static_cast<uint32_t>(defaultColor);
    printerCaps.SetPrinterAttrNameAndValue("defaultColorMode", std::to_string(mode).c_str());
}


void ParseQualityAttributesFromPPD(ppd_file_t *ppd, PrinterCapability &printerCaps)
{
    std::vector<PrintQualityCode> supportedQualitiesList;
    ppd_option_t *outputMode = ppdFindOption(ppd, "OutputMode");
    if (!outputMode) {
        outputMode = ppdFindOption(ppd, "cupsPrintQuality");
    }
    if (outputMode) {
        if (ppdFindChoice(outputMode, "draft") || ppdFindChoice(outputMode, "fast")) {
            supportedQualitiesList.emplace_back(PrintQualityCode::PRINT_QUALITY_DRAFT);
        }
        supportedQualitiesList.emplace_back(PrintQualityCode::PRINT_QUALITY_NORMAL);
        if (ppdFindChoice(outputMode, "best") || ppdFindChoice(outputMode, "high")) {
            supportedQualitiesList.emplace_back(PrintQualityCode::PRINT_QUALITY_HIGH);
        }
    } else {
        supportedQualitiesList = { PrintQualityCode::PRINT_QUALITY_NORMAL };
    };

    printerCaps.SetSupportedQuality(std::vector<uint32_t>(supportedQualitiesList.begin(),
        supportedQualitiesList.end()));

    // compatible with Spooler USB
    Json::Value supportedQualities;
    for (auto &quality : supportedQualitiesList) {
        Json::Value jsonObject;
        uint32_t value = static_cast<uint32_t>(quality);
        jsonObject["quality"] = value;
        supportedQualities.append(jsonObject);
    }
    std::string attrString = PrintJsonUtil::WriteString(supportedQualities);
    std::string keyword = "print-quality-supported";
    printerCaps.SetPrinterAttrNameAndValue(keyword.c_str(), attrString.c_str());
}

void SetOptionAttributeFromPPD(ppd_file_t *ppd, PrinterCapability &printerCaps)
{
    Json::Value options;
    if (ppd->nickname) {
        options["make"] = ppd->nickname;
    } else if (ppd->modelname) {
        options["make"] = ppd->modelname;
    } else if (ppd->shortnickname) {
        options["make"] = ppd->shortnickname;
    } else {
        options["make"] = "Bad PPD File";
    }

    if (ppd->manufacturer) {
        options["manufacturer"] = ppd->manufacturer;
    } else {
        options["manufacturer"] = "others";
    }

    Json::Value cupsOptionsJson = printerCaps.GetPrinterAttrGroupJson();
    options["cupsOptions"] = cupsOptionsJson;

    std::string optionStr = PrintJsonUtil::WriteString(options);
    PRINT_HILOGD("SetOption: %{public}s", optionStr.c_str());
    printerCaps.SetOption(optionStr);
}

void ParsePrinterAttributesFromPPD(ppd_file_t *ppd, PrinterCapability &printerCaps)
{
    ParseColorModeAttributesFromPPD(ppd, printerCaps);
    ParseDuplexModeAttributesFromPPD(ppd, printerCaps);
    ParsePageSizeAttributesFromPPD(ppd, printerCaps);
    ParseQualityAttributesFromPPD(ppd, printerCaps);
    ParseMediaTypeAttributeFromPPD(ppd, printerCaps);
    SetOptionAttributeFromPPD(ppd, printerCaps);
}

int32_t QueryPrinterCapabilityFromPPDFile(PrinterCapability &printerCaps, const std::string &ppdFilePath)
{
    PRINT_HILOGI("QueryPrinterCapabilityFromPPDFile start %{private}s", ppdFilePath.c_str());
    char *locale = setlocale(LC_ALL, "zh_CN.UTF-8");
    if (locale == nullptr) {
        PRINT_HILOGE("setlocale fail");
        return E_PRINT_FILE_IO;
    }
    ppd_file_t *ppd = ppdOpenFile(ppdFilePath.c_str());
    if (ppd == nullptr) {
        PRINT_HILOGE("Open PPD File fail");
        return E_PRINT_FILE_IO;
    }

    ppd->cache = _ppdCacheCreateWithPPD(ppd);
    if (ppd->cache == nullptr) {
        PRINT_HILOGE("PPDCacheCreateWithPPD fail");
        ppdClose(ppd);
        return E_PRINT_FILE_IO;
    }
    GetAdvanceOptionsFromPPD(ppd, printerCaps);
    ParsePrinterAttributesFromPPD(ppd, printerCaps);

    ppdClose(ppd);
    return E_PRINT_NONE;
}

bool ConvertOptionAndChoiceNameToPpd(ppd_file_t *ppd, const std::string &type, const std::string &val,
    std::string &optName, std::string &choiceName)
{
    ppd_option_t *ppdOption = nullptr;
    const CupsOptionInfo *optInf = nullptr;
    auto optRange = CUPS_PPD_FIELD_MMAP.equal_range(type);
    for (auto it = optRange.first; it != optRange.second; ++it) {
        ppdOption = ppdFindOption(ppd, it->second.name.c_str());
        if (ppdOption != nullptr) {
            optInf = &it->second;
            break;
        }
    }

    if (ppdOption == nullptr) {
        optName = type;
        choiceName = val;
        return false;
    }

    optName = optInf->name;
    auto choiceRange = optInf->choiceMmap.equal_range(val);
    for (auto it = choiceRange.first; it != choiceRange.second; ++it) {
        ppd_choice_t *ppdChoice = ppdFindChoice(ppdOption, it->second.c_str());
        if (ppdChoice != nullptr) {
            choiceName = it->second;
            return true;
        }
    }

    if (PPD_OPT_NAME_PAGESIZE == ppdOption->keyword) {
        // Convert Human-readable page size name to PPD name
        for (int i = 0; i < ppdOption->num_choices; ++i) {
            if (val == ppdOption->choices[i].text) {
                choiceName = ppdOption->choices[i].choice;
                return true;
            }
        }
    }

    choiceName = val;
    return false;
}

int32_t MarkPpdOption(ppd_file_t *ppd, const std::string &type, const std::string &val)
{
    std::string optName;
    std::string choiceName;
    ConvertOptionAndChoiceNameToPpd(ppd, type, val, optName, choiceName);

    return ppdMarkOption(ppd, optName.c_str(), choiceName.c_str());
}

int32_t CheckPpdConflicts(ppd_file_t *ppd, const std::string &type,
    const std::string &val, std::vector<std::string>& conflictTypes)
{
    conflictTypes.clear();
    std::string optName;
    std::string choiceName;
    ConvertOptionAndChoiceNameToPpd(ppd, type, val, optName, choiceName);

    cups_option_t *conflictOptions = nullptr;
    int32_t conflictsNum = cupsGetConflicts(ppd, optName.c_str(), choiceName.c_str(), &conflictOptions);
    for (int32_t idx = 0; idx < conflictsNum; ++idx) {
        if (optName == conflictOptions[idx].name) {
            continue;
        }

        auto it = MAP_CUPS_OPTNAME_TO_TYPE.find(conflictOptions[idx].name);
        if (it != MAP_CUPS_OPTNAME_TO_TYPE.end()) {
            conflictTypes.emplace_back(it->second);
        } else {
            conflictTypes.emplace_back(conflictOptions[idx].name);
        }
    }

    if (conflictOptions != nullptr) {
        cupsFreeOptions(conflictsNum, conflictOptions);
    }

    return conflictsNum;
}

}