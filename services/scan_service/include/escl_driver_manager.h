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

#ifndef ESCL_DRIVER_MANAGER
#define ESCL_DRIVER_MANAGER
#include "scanner_info.h"
#include <string>
namespace OHOS::Scan {
constexpr const char* SCHEME_HTTPS = "https";
constexpr const char* SCHEME_HTTP = "http";

class SaneOptionDescriptor;

class EsclDriverManager {
public:
    static int32_t InitializeEsclScannerDriver();
    static bool GenerateEsclScannerInfo(const ScanDeviceInfoTCP& rawInfo, ScanDeviceInfo& info);
    static void AddEsclScannerInfo(std::vector<ScanDeviceInfo>& discoveredScanners);
    static bool IsEsclScanner(const std::string& scannerId);
    static bool IsAdfMode(const std::string& scannerId);
    static bool ExtractIpAndPort(const std::string& scannerId, std::string& ipAddress, int32_t& portNumber);
    static bool IsAdfEmpty(bool isHttps, const std::string& ipAddress, int32_t portNumber);
    static void InjectLineartOption(SaneOptionDescriptor &saneDesc);
    static bool ShouldDowngradeBwMode(const std::string& scannerId, const std::string& value);
    static void RenameTofuCert(const std::string& oldDeviceId, const std::string& newDeviceId);
    static bool BuildPlainHttpDeviceId(const std::string& scannerId, std::string& plainDeviceId,
        const std::string& plainPort = "80");
private:
    static bool CreateSoftLink();
    static bool CreateAirscanConfigFile();
};

} // namespace OHOS::Scan
#endif // ESCL_DRIVER_MANAGER_H