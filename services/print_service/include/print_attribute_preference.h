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
        PreferenceSetting preferenceSetting;
        if (printerAttr.contains("pagesizeId") && printerAttr["pagesizeId"].is_string()) {
            preferenceSetting.pagesizeId = printerAttr.at("pagesizeId").get<std::string>();
        }
        if (printerAttr.contains("orientation") && printerAttr["orientation"].is_string()) {
            preferenceSetting.orientation = printerAttr.at("orientation").get<std::string>();
        }
        if (printerAttr.contains("duplex") && printerAttr["duplex"].is_string()) {
            preferenceSetting.duplex = printerAttr.at("duplex").get<std::string>();
        }
        if (printerAttr.contains("quality") && printerAttr["quality"].is_string()) {
            preferenceSetting.quality = printerAttr.at("quality").get<std::string>();
        }
        return preferenceSetting;
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

    static void GetArrayFromJson(const json& value, std::vector<std::string> &target, const std::string& key)
    {
        if (value.contains(key) && value.is_object()) {
            const json& jsonValue = value.at(key);
            for (auto &element : jsonValue.items()) {
                nlohmann::json item = element.value();
                if (!item.is_string()) {
                    PRINT_HILOGW("this item in preference is not string");
                    continue;
                }
                target.emplace_back(item.get<std::string>());
            }
        } else {
            PRINT_HILOGW("can not find target array in preference, key: %{public}s", key.c_str());
        }
    }

    static PrinterPreference BuildPrinterPreferenceFromJson(const json& printerAttrs)
    {
        PrinterPreference printerPreference;
        GetArrayFromJson(printerAttrs, printerPreference.pagesizeId, "pagesizeId");
        GetArrayFromJson(printerAttrs, printerPreference.orientation, "orientation");
        GetArrayFromJson(printerAttrs, printerPreference.duplex, "duplex");
        GetArrayFromJson(printerAttrs, printerPreference.quality, "quality");
        if (printerAttrs.contains("defaultSetting") && printerAttrs["defaultSetting"].is_object()) {
            printerPreference.defaultSetting =
                PreferenceSetting::BuildPreferenceSettingFromJson(printerAttrs.at("defaultSetting"));
        }
        if (printerAttrs.contains("setting") && printerAttrs["setting"].is_object()) {
            printerPreference.setting = PreferenceSetting::BuildPreferenceSettingFromJson(printerAttrs.at("setting"));
        }
        return printerPreference;
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