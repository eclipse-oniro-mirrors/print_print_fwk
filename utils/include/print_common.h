/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef PRINT_COMMON_H
#define PRINT_COMMON_H

namespace OHOS::Print {
enum PrintError {
    E_PRINT_OK,
    E_PRINT_SA_DIED,
    E_PRINT_READ_PARCEL_ERROR,
    E_PRINT_WRITE_PARCEL_ERROR,
    E_PRINT_PUBLISH_FAIL,
    E_PRINT_IPC_ERROR,
    E_PRINT_DEAL_FAILED,
    E_PRINT_PARAMETERS_INVALID,
    E_PRINT_SET_RTC_FAILED,
    E_PRINT_NOT_FOUND,
    E_PRINT_NO_PERMISSION,
};
} // namespace OHOS::Print

#endif // PRINT_COMMON_H