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

}