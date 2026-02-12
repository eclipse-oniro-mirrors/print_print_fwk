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

#ifndef ESCL_SCANNER_STATUS_H
#define ESCL_SCANNER_STATUS_H

#include <string>
#include <map>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include "curl_http_client.h"

namespace OHOS::Scan {
class EsclScannerStatus {
public:
    static bool QueryScannerStatus(const std::string& ipAddress, int32_t portNumber,
        std::map<std::string, std::string>& statusMap);
private:
    static bool ValidateParameters(const std::string& ipAddress, int32_t portNumber);
    static bool ParseXmlResponse(const std::string& responseBuffer,
        std::map<std::string, std::string>& statusMap);
    static bool ExtractStatusInfo(xmlDoc* xmlDoc, std::map<std::string, std::string>& statusMap);
    static bool AddStatusEntry(xmlXPathContextPtr xpathCtx, const char* xpath, const char* key,
        std::map<std::string, std::string>& statusMap);
};
} // namespace OHOS::Scan

#endif // ESCL_SCANNER_STATUS_H