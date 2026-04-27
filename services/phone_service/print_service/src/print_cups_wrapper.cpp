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

#include "print_cups_wrapper.h"

namespace OHOS::Print {

cups_dest_t* PrintCupsWrapper::GetNamedDest(http_t *http, const char *name, const char *instance)
{
    return cupsGetNamedDest(http, name, instance);
}

void PrintCupsWrapper::FreeDests(int num, cups_dest_t *dests)
{
    cupsFreeDests(num, dests);
}

void PrintCupsWrapper::FreeDestInfo(cups_dinfo_t *dinfo)
{
    cupsFreeDestInfo(dinfo);
}

ipp_t *PrintCupsWrapper::DoRequest(http_t *http, ipp_t *request, const char *resource)
{
    return cupsDoRequest(http, request, resource);
}

cups_dinfo_t *PrintCupsWrapper::CopyDestInfo(http_t *http, cups_dest_t *dest)
{
    return cupsCopyDestInfo(http, dest);
}

void PrintCupsWrapper::FreeRequest(ipp_t *response)
{
    ippDelete(response);
}
}