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

#ifndef SPACE_MGR_WRAPPER_API_H
#define SPACE_MGR_WRAPPER_API_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SPACE_MGR_WRAPPER_OK 0
#define SPACE_MGR_WRAPPER_ERR_INTERNAL (-1)

typedef struct {
    uint32_t abiVersion;
    int32_t (*isEnterpriseWorkspace)(int32_t workspaceId, bool *isEnterprise);
} SpaceMgrWrapperApi;

const SpaceMgrWrapperApi *GetSpaceMgrWrapperApi(void);

#ifdef __cplusplus
}
#endif

#endif // SPACE_MGR_WRAPPER_API_H
