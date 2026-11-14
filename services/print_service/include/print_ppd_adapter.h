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

#ifndef PRINT_PPD_ADAPTER_H
#define PRINT_PPD_ADAPTER_H

#include <string>
#include <vector>
#include <utility>
#include <map>
#include <json/json.h>
#include <cups/ppd.h>
#include <cups/ppd-private.h>
#include <cups/cups.h>

namespace OHOS::Print {

using StdStringMultiMap = std::multimap<const std::string, const std::string>;

enum class ResolverType {
    STANDARD,
    CACHE_SIZES,
    CACHE_SOURCES,
    STANDALONE,
};

struct CupsOptionInfo {
    const std::string &name;
    const StdStringMultiMap &choiceMmap;
    ResolverType resolver;
};

struct EntryResult {
    Json::Value textDefault;
    Json::Value textLang;
    Json::Value ppdChoices;
};

struct ResolveContext {
    ppd_file_t *ppd;
    ppd_option_t *opt;
    ResolverType resolver;
    const std::map<std::string, std::string> *reverseChoiceMap;
    const std::map<std::string, int> *enumMap;
    std::string lang;
};

struct PwgOptionSpec {
    std::string pwgType;
    std::string pwgVal;
    const char *pwgOptName;
    const char *defaultVal;
};

extern const std::multimap<const std::string, const CupsOptionInfo> CUPS_PPD_FIELD_MMAP;
extern const std::map<const std::string, const std::string> MAP_CUPS_OPTNAME_TO_TYPE;
extern const std::string PPD_OPT_NAME_PAGESIZE;
extern const std::string PPD_OPT_NAME_INPUT_SLOT;

class PpdAdapter {
public:
    static void BuildOptionMaps(ppd_file_t *ppd, Json::Value &optionMap, Json::Value &textMap);
    // Same pipeline as BuildOptionMaps but textMap language layer keyed by the
    // queried language (uses real PPD choice names internally; capability
    // snapshot path keeps calling BuildOptionMaps for the zh_CN form).
    static void BuildOptionTextMap(ppd_file_t *ppd, const std::string &language, Json::Value &textMap);
    static bool ConvertPwgToPpd(const Json::Value &optionMap, const std::string &pwgType,
        const std::string &pwgVal, std::string &optName, std::string &choiceName);
    static bool ConvertMediaOptions(const Json::Value &optionMap,
        const std::vector<std::pair<std::string, std::string>> &dims,
        std::vector<std::pair<std::string, std::string>> &result);
    static int AddPpdOrPwgOption(const Json::Value &optionMap, const PwgOptionSpec &spec,
        int num_options, cups_option_t **options);
private:
    static std::string ResolveTextKey(const std::string &pwgValue,
        const std::map<std::string, int> *enumMap);
    static bool FindCacheEntry(ppd_file_t *ppd, ResolverType resolver,
        const char *choice, std::string &pwgKey);
    static void BuildEntries(const ResolveContext &ctx, EntryResult &result);
    static ppd_option_t *FindPpdOptionByPwgType(ppd_file_t *ppd, const std::string &pwgType,
        const StdStringMultiMap *&outChoiceMmap, ResolverType &outResolver);
    static std::string GetCanonicalPpdName(const std::string &pwgType);
    static void WriteOptionMaps(const ResolveContext &ctx, const std::string &pwgType,
        const EntryResult &result, Json::Value &ppdOptionMap, Json::Value &ppdOptionTextMap);
    static void BuildOptionMapsInternal(ppd_file_t *ppd, const std::string &language,
        Json::Value &optionMap, Json::Value &textMap);
    static void ProcessOptionEntry(ppd_file_t *ppd, const std::string &pwgType,
        const std::string &language,
        Json::Value &ppdOptionMap, Json::Value &ppdOptionTextMap);
};
}  // namespace OHOS::Print
#endif  // PRINT_PPD_ADAPTER_H
