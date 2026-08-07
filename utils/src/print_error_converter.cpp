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

#include "print_error_converter.h"

#include "ability_manager_errors.h"

namespace OHOS::Print {

PrintErrorCode PrintErrorConverter::FromAafwkError(ErrCode aafwkErr)
{
    if (aafwkErr == ERR_OK) {
        return E_PRINT_NONE;
    }

    using namespace AAFwk;
    switch (aafwkErr) {
        // Permission related
        case CHECK_PERMISSION_FAILED:
        case ERR_STATIC_CFG_PERMISSION:
        case ERR_NO_PERMISSION_CALLER:
            return E_PRINT_NO_PERMISSION;

        // Non-system app using system API
        case ERR_NOT_SYSTEM_APP:
            return E_PRINT_ILLEGAL_USE_OF_SYSTEM_API;

        // Invalid parameter / caller / ability not found
        case RESOLVE_ABILITY_ERR:
        case RESOLVE_APP_ERR:
        case RESOLVE_CALL_ABILITY_TYPE_ERR:
        case RESOLVE_CALL_ABILITY_INNER_ERR:
        case ERR_INVALID_CALLER:
        case INVALID_CALLER_TOKEN:
        case ERR_NATIVE_ABILITY_NOT_FOUND:
        case ERR_TARGET_BUNDLE_NOT_EXIST:
        case ERR_BUNDLE_NOT_EXIST:
        case ERR_ABILITY_TYPE_INVALID:
            return E_PRINT_INVALID_PARAMETER;

        // Invalid extension
        case ERR_INVALID_EXTENSION_TYPE:
        case EXTENSION_ABILITY_NOT_EXIST:
        case EXTENSION_ABILITY_INFO_NOT_QUERY_BY_URI:
            return E_PRINT_INVALID_EXTENSION;

        // Connection / RPC related
        case CONNECTION_NOT_EXIST:
        case INVALID_CONNECTION_STATE:
        case CONNECTION_TIMEOUT:
        case TARGET_ABILITY_NOT_SERVICE:
            return E_PRINT_RPC_FAILURE;

        // Service unavailable
        case ABILITY_SERVICE_NOT_CONNECTED:
        case GET_ABILITY_SERVICE_FAILED:
        case ERR_APP_MGR_SERVICE_NOT_READY:
        case ERR_ABILITY_NOT_FOREGROUND:
            return E_PRINT_SERVER_FAILURE;

        // Invalid userid
        case INVALID_USERID_VALUE:
        case ERR_CROSS_USER:
            return E_PRINT_INVALID_USERID;

        // Terminate ability related
        case TERMINATE_LAUNCHER_DENIED:
        case TERMINATE_SERVICE_IS_CONNECTED:
        case TERMINATE_ABILITY_RESULT_FAILED:
            return E_PRINT_GENERIC_FAILURE;

        default:
            PRINT_HILOGW("Unmapped AAFwk error code: %{public}d, fallback to E_PRINT_GENERIC_FAILURE", aafwkErr);
            return E_PRINT_GENERIC_FAILURE;
    }
}

} // namespace OHOS::Print
