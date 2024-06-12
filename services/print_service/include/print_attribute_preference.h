/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef PRINT_ATTRIBUTR_PREFERENCE_H
#define PRINT_ATTRIBUTR_PREFERENCE_H

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
namespace OHOS::Print {
class PreferenceSetting {
public:
    std::string pagesizeId;
    std::string orientation;
    std::string duplex;
    std::string quality;
    PreferenceSetting() {};
    PreferenceSetting(std::string pagesizeId, std::string orientation, std::string duplex, std::string quality)
        : pagesizeId(pagesizeId), orientation(orientation), duplex(duplex), quality(quality) {}

    static PreferenceSetting BuildPreferenceSettingFromJson(const json& printerAttr)
    {
        return {
            printerAttr.at("pagesizeId").get<std::string>(),
            printerAttr.at("orientation").get<std::string>(),
            printerAttr.at("duplex").get<std::string>(),
            printerAttr.at("quality").get<std::string>()
        };
    }

    json BuildPreferenceSettingJson() const
    {
        return json{{"pagesizeId", pagesizeId}, {"orientation", orientation},
            {"duplex", duplex}, {"quality", quality}};
    }
    ~PreferenceSetting() {};
};

class PrinterPreference {
public:
    std::vector<std::string> pagesizeId;
    std::vector<std::string> orientation;
    std::vector<std::string> duplex;
    std::vector<std::string> quality;
    PreferenceSetting defaultSetting;
    PreferenceSetting setting;
    PrinterPreference() {};
    PrinterPreference(std::vector<std::string> pagesizeId, std::vector<std::string> orientation,
        std::vector<std::string> duplex, std::vector<std::string> quality,
        PreferenceSetting defaultSetting, PreferenceSetting setting)
        : pagesizeId(pagesizeId), orientation(orientation), duplex(duplex), quality(quality),
          defaultSetting(defaultSetting), setting(setting) {}

    static PrinterPreference BuildPrinterPreferenceFromJson(const json& printerAttrs)
    {
        return {
            printerAttrs.at("pagesizeId").get<std::vector<std::string>>(),
            printerAttrs.at("orientation").get<std::vector<std::string>>(),
            printerAttrs.at("duplex").get<std::vector<std::string>>(),
            printerAttrs.at("quality").get<std::vector<std::string>>(),
            PreferenceSetting::BuildPreferenceSettingFromJson(printerAttrs.at("defaultSetting")),
            PreferenceSetting::BuildPreferenceSettingFromJson(printerAttrs.at("setting"))
        };
    }

    json BuildPrinterPreferenceJson() const
    {
        return json{
            {"pagesizeId", pagesizeId},
            {"orientation", orientation},
            {"duplex", duplex},
            {"quality", quality},
            {"defaultSetting", defaultSetting.BuildPreferenceSettingJson()},
            {"setting", setting.BuildPreferenceSettingJson()}
        };
    }
    ~PrinterPreference() {};
};
}
#endif