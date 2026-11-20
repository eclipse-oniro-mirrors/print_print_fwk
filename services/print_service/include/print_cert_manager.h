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

#ifndef PRINT_CERT_MANAGER_H
#define PRINT_CERT_MANAGER_H

#include <cups/cups-private.h>
#include <string>
#include "singleton.h"

namespace OHOS::Print {

class IPrintCertAbility {
public:
    virtual ~IPrintCertAbility() {}
    virtual http_t *Connect(const char *host, int port, int timeout) = 0;
    virtual bool IsEncrypted(http_t *http) = 0;
    virtual int CopyCredentials(http_t *http, cups_array_t **creds) = 0;
    virtual int SaveCredentials(const char *path, cups_array_t *creds, const char *commonName) = 0;
    virtual void Close(http_t *http) = 0;
};

class PrintCertManager : public DelayedSingleton<PrintCertManager> {
    DECLARE_DELAYED_SINGLETON(PrintCertManager)

public:
    // Establish TLS connection to printer, fetch certificate, and save to CUPS trust store.
    // printerName: CUPS standardized printer name, used as the certificate trust key.
    // Returns true if the certificate was saved successfully.
    bool SaveCertForPrinter(const std::string &printerUri, const std::string &printerName);

    // Delete the printer's certificate from CUPS trust store.
    // printerName: CUPS standardized printer name, used as the certificate trust key.
    // Returns true if the certificate was deleted (or did not exist).
    bool DeleteCertForPrinter(const std::string &printerName);

private:
    IPrintCertAbility *certAbility_ = nullptr;
};

} // namespace OHOS::Print
#endif // PRINT_CERT_MANAGER_H
