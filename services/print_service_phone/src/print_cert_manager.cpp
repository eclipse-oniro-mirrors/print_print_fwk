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

#include "print_cert_manager.h"

#include <cups/cups-private.h>
#include <cerrno>
#include <unistd.h>
#include "print_log.h"
#include "print_utils.h"

namespace OHOS::Print {

static const uint32_t CERT_CONNECT_TIMEOUT = 3000;
static const char *CUPS_SSL_DIR = "/data/service/el1/public/print_service/cups/ssl";

namespace {
class PrintCertAbility : public IPrintCertAbility {
public:
    http_t *Connect(const char *host, int port, int timeout) override
    {
        return httpConnect2(host, port, nullptr, AF_UNSPEC, HTTP_ENCRYPTION_ALWAYS, 1, timeout, nullptr);
    }

    bool IsEncrypted(http_t *http) override
    {
        return httpIsEncrypted(http) != 0;
    }

    int CopyCredentials(http_t *http, cups_array_t **creds) override
    {
        return httpCopyCredentials(http, creds);
    }

    int SaveCredentials(const char *path, cups_array_t *creds, const char *commonName) override
    {
        return httpSaveCredentials(path, creds, commonName);
    }

    void Close(http_t *http) override
    {
        httpClose(http);
    }
};
} // namespace

PrintCertManager::PrintCertManager() : certAbility_(new PrintCertAbility()) {}

PrintCertManager::~PrintCertManager()
{
    delete certAbility_;
    certAbility_ = nullptr;
}

bool PrintCertManager::SaveCertForPrinter(const std::string &printerUri, const std::string &printerName)
{
    PRINT_HILOGI("SaveCertForPrinter start, uri: %{public}s, printerName: %{public}s",
        PrintUtils::AnonymizePrinterUri(printerUri).c_str(), printerName.c_str());

    char scheme[32] = {0};
    char username[256] = {0};
    char host[1024] = {0};
    char resource[1024] = {0};
    int port = 0;
    httpSeparateURI(HTTP_URI_CODING_ALL, printerUri.c_str(), scheme, sizeof(scheme),
        username, sizeof(username), host, sizeof(host), &port, resource, sizeof(resource));

    std::string hostname(host);
    if (hostname.empty()) {
        PRINT_HILOGE("Failed to extract hostname from URI");
        return false;
    }

    if (port == 0) {
        port = IPP_PORT;
    }

    http_t *http = certAbility_->Connect(host, port, CERT_CONNECT_TIMEOUT);
    if (http == nullptr) {
        PRINT_HILOGE("Failed to connect to printer for cert fetch: %{public}s", PrintUtils::AnonymizeIp(host).c_str());
        return false;
    }

    if (!certAbility_->IsEncrypted(http)) {
        PRINT_HILOGE("Connection is not encrypted, cannot fetch certificate");
        certAbility_->Close(http);
        return false;
    }

    cups_array_t *creds = nullptr;
    if (certAbility_->CopyCredentials(http, &creds) != 0 || creds == nullptr) {
        PRINT_HILOGE("Failed to copy credentials from printer");
        certAbility_->Close(http);
        return false;
    }

    // Use the printer name as the trust key (same as CUPS backend uses PRINTER env var),
    // so certificate trust survives IP address changes.
    int ret = certAbility_->SaveCredentials(nullptr, creds, printerName.c_str());
    httpFreeCredentials(creds);
    certAbility_->Close(http);

    if (ret != 0) {
        PRINT_HILOGE("Failed to save credentials for printer: %{public}s", printerName.c_str());
        return false;
    }

    PRINT_HILOGI("SaveCertForPrinter success, printerName: %{public}s", printerName.c_str());
    return true;
}

bool PrintCertManager::DeleteCertForPrinter(const std::string &printerName)
{
    PRINT_HILOGI("DeleteCertForPrinter start, printerName: %{public}s", printerName.c_str());

    // httpSaveCredentials uses http_make_path which sanitizes the common_name:
    // alnum, '-' and '.' are kept, others replaced with '_'.
    std::string filename = std::string(CUPS_SSL_DIR) + "/";
    for (char c : printerName) {
        if (isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '.') {
            filename += c;
        } else {
            filename += '_';
        }
    }
    filename += ".crt";

    int ret = unlink(filename.c_str());
    if (ret != 0 && errno != ENOENT) {
        PRINT_HILOGE("Failed to delete cert file, errno: %{public}d", errno);
        return false;
    }

    PRINT_HILOGI("DeleteCertForPrinter success");
    return true;
}

} // namespace OHOS::Print
