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

#ifndef PRINT_FWK_ENTERPRISE_API_H
#define PRINT_FWK_ENTERPRISE_API_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PRINT_FWK_ENTERPRISE_OK 0
#define PRINT_FWK_ENTERPRISE_ERR_INTERNAL (-1)

typedef struct {
    uint32_t abiVersion;
    int32_t (*isEnterpriseWorkspace)(int32_t workspaceId, bool *isEnterprise);
} PrintFwkEnterpriseApi;

const PrintFwkEnterpriseApi *GetPrintFwkEnterpriseApi(void);

#ifdef __cplusplus
}
#endif

#endif // PRINT_FWK_ENTERPRISE_API_H
