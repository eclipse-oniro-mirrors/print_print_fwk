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

#include <arpa/inet.h>
#include "scan_log.h"
#include "escl_scanner_status.h"

namespace OHOS::Scan {
static const int32_t MAX_PORT_NUMBER = 65535;

bool EsclScannerStatus::ValidateParameters(const std::string& ipAddress, int32_t portNumber)
{
    if (ipAddress.empty() || portNumber <= 0 || portNumber > MAX_PORT_NUMBER) {
        SCAN_HILOGE("Invalid parameters, ip empty or port out of range");
        return false;
    }
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress.c_str(), &(sa.sin_addr));
    if (result != 1) {
        SCAN_HILOGE("Invalid IP address format: %{public}s", ipAddress.c_str());
        return false;
    }
    return true;
}

bool EsclScannerStatus::ParseXmlResponse(const std::string& responseBuffer,
    std::map<std::string, std::string>& statusMap)
{
    xmlDocPtr xmlDoc = {nullptr};
    xmlDoc = xmlParseDoc(reinterpret_cast<const xmlChar*>(responseBuffer.c_str()));
    if (!xmlDoc) {
        SCAN_HILOGE("Failed to parse XML response");
        return false;
    }

    bool result = ExtractStatusInfo(xmlDoc, statusMap);
    xmlFreeDoc(xmlDoc);

    if (result) {
        SCAN_HILOGI("Successfully extracted scanner status");
    } else {
        SCAN_HILOGE("Failed to extract scanner status from XML");
    }
    return result;
}

bool EsclScannerStatus::QueryScannerStatus(const std::string& ipAddress, int32_t portNumber,
    std::map<std::string, std::string>& statusMap)
{
    if (!ValidateParameters(ipAddress, portNumber)) {
        SCAN_HILOGE("Parameter validation failed");
        return false;
    }

    SCAN_HILOGI("Query scanner status: ip=%{private}s, port=%{private}d", ipAddress.c_str(), portNumber);

    std::string url = "http://" + ipAddress + ":" + std::to_string(portNumber) + "/eSCL/ScannerStatus";
    std::string responseBuffer;

    if (!CurlHttpClient::PerformHttpRequest(url, responseBuffer)) {
        SCAN_HILOGE("HTTP request failed");
        return false;
    }

    if (!ParseXmlResponse(responseBuffer, statusMap)) {
        SCAN_HILOGE("Parse XML response failed");
        return false;
    }

    return true;
}

bool EsclScannerStatus::ExtractStatusInfo(xmlDoc* xmlDoc, std::map<std::string, std::string>& statusMap)
{
    if (!xmlDoc) {
        SCAN_HILOGE("xmlDoc is null");
        return false;
    }

    xmlXPathContextPtr xpathCtx = xmlXPathNewContext(xmlDoc);
    if (!xpathCtx) {
        SCAN_HILOGE("Failed to create XPath context");
        return false;
    }

    AddStatusEntry(xpathCtx, "/*[local-name()='ScannerStatus']/*[local-name()='State']", "pwg:State", statusMap);
    AddStatusEntry(xpathCtx, "/*[local-name()='ScannerStatus']/*[local-name()='AdfState']", "scan:AdfState",
        statusMap);

    xmlXPathFreeContext(xpathCtx);
    return true;
}

bool EsclScannerStatus::AddStatusEntry(xmlXPathContextPtr xpathCtx, const char* xpath, const char* key,
    std::map<std::string, std::string>& statusMap)
{
    if (!xpathCtx || !xpath || !key) {
        SCAN_HILOGE("Invalid parameters");
        return false;
    }

    xmlXPathObjectPtr xpathObj = xmlXPathEvalExpression(BAD_CAST xpath, xpathCtx);
    if (!xpathObj) {
        SCAN_HILOGW("XPath evaluation failed for: %{public}s", xpath);
        return false;
    }

    if (xpathObj->nodesetval && xpathObj->nodesetval->nodeNr > 0) {
        xmlNodePtr xmlNode = xpathObj->nodesetval->nodeTab[0];
        if (xmlNode && xmlNode->children && xmlNode->children->content) {
            const char* content = reinterpret_cast<const char*>(xmlNode->children->content);
            statusMap[key] = content;
            SCAN_HILOGD("Extracted status: %{public}s=%{public}s", key, content);
        } else {
            SCAN_HILOGW("XML node has no content for key: %{public}s", key);
        }
    } else {
        SCAN_HILOGW("No nodes found for XPath: %{public}s", xpath);
    }

    xmlXPathFreeObject(xpathObj);
    return true;
}
} // namespace OHOS::Scan