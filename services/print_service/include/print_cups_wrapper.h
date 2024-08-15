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

#ifndef PRINT_CUPS_WRAPPER_H
#define PRINT_CUPS_WRAPPER_H

#include <vector>
#include <string>
#include <functional>
#include <cups/cups-private.h>
#include <cups/ppd.h>

namespace OHOS::Print {
typedef std::function<void()> CallbackFunc;

class IPrintAbilityBase {
public:
    virtual ~IPrintAbilityBase() {}
    virtual cups_dest_t *GetNamedDest(http_t *http, const char *name, const char *instance) = 0;
    virtual void FreeDests(int num, cups_dest_t *dests) = 0;
    virtual ipp_t *DoRequest(http_t *http, ipp_t *request, const char *resource) = 0;
    virtual cups_dinfo_t *CopyDestInfo(http_t *http, cups_dest_t *dest) = 0;
};

class PrintCupsWrapper : public IPrintAbilityBase {
public:
    cups_dest_t* GetNamedDest(http_t *http, const char *name, const char *instance) override;
    void FreeDests(int num, cups_dest_t *dests) override;
    ipp_t *DoRequest(http_t *http, ipp_t *request, const char *resource) override;
    cups_dinfo_t *CopyDestInfo(http_t *http, cups_dest_t *dest) override;
};
} // namespace OHOS::Print
#endif // PRINT_CUPS_WRAPPER_H