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

#include <ani.h>
#include "print_base_ani_util.h"
#include "print_object_ani_util.h"
#include "ani_scan_progress_helper.h"
#include "scan_log.h"

namespace {
const char* PARAM_PROGRESS = "progress";
const char* PARAM_PICTURE_FD = "pictureFd";
const char* PARAM_IS_FINAL = "isFinal";
const char *CLASSNAME = "@ohos.scan.scan.PictureScanProgress";
}

namespace OHOS::Scan {
using namespace OHOS::Print;
ani_object AniScanProgressHelper::CreateScanProgress(ani_env *env, const ScanProgress &progress)
{
    if (env == nullptr) {
        SCAN_HILOGE("null env");
        return nullptr;
    }
    ani_object obj = CreateObject(env, nullptr, CLASSNAME);
    if (obj == nullptr) {
        SCAN_HILOGE("null obj");
        return nullptr;
    }
    SetIntProperty(env, obj, PARAM_PROGRESS, progress.GetScanProgress());
    SetIntProperty(env, obj, PARAM_PICTURE_FD, progress.GetScanPictureFd());
    SetIntPropertyObject(env, obj, PARAM_IS_FINAL, progress.GetIsFinal());
    return obj;
}
}  // namespace OHOS::Scan
