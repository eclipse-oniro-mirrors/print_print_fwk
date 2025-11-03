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
#include "ani_print_extension_info_helper.h"
#include "print_log.h"

namespace OHOS::Print {
const char* EXTENSION_ID_STR = "extensionId";
const char* VENDOR_ID_STR = "vendorId";
const char* VENDOR_NAME_STR = "vendorName";
const char* VENDOR_ICON_STR = "vendorIcon";
const char* VERSION_STR = "version";
const char *CLASS_NAME = "@ohos.print.print.PrinterExtensionInfoImpl";

ani_object AniPrintExtensionInfoHelper::CreatePrinterExtensionInfoArray(ani_env *env,
    const std::vector<PrintExtensionInfo>& infos)
{
    ani_class arrayCls = nullptr;
    ani_status status = env->FindClass("escompat.Array", &arrayCls);
    if (status != ANI_OK) {
        PRINT_HILOGE("[ANI] find class fail");
        return nullptr;
    }
    ani_method arrayCtor;
    status = env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor);
    if (status != ANI_OK) {
        PRINT_HILOGE("[ANI] Class_FindMethod Failed");
        return nullptr;
    }
    ani_size length = infos.size();
    ani_object arrayObj;
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, length);
    if (status != ANI_OK) {
        PRINT_HILOGE("Object_New failed %{public}d", status);
        return nullptr;
    }
    ani_class cls;
    if (ANI_OK != env->FindClass(CLASS_NAME, &cls)) {
        PRINT_HILOGE("[ANI] find class fail");
        return nullptr;
    }

    for (size_t i = 0; i < infos.size(); i++) {
        ani_object infoObj = {};
        ani_method ctor;
        if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) {
            PRINT_HILOGE("[ANI] find method fail");
            return arrayObj;
        }
        if (ANI_OK != env->Object_New(cls, ctor, &infoObj)) {
            PRINT_HILOGE("Create Object Failed");
            return arrayObj;
        }
        SetStringProperty(env, infoObj, EXTENSION_ID_STR, infos[i].GetExtensionId());
        SetStringProperty(env, infoObj, VENDOR_ID_STR, infos[i].GetVendorId());
        SetStringProperty(env, infoObj, VENDOR_NAME_STR, infos[i].GetVendorName());
        SetIntProperty(env, infoObj, VENDOR_ICON_STR, infos[i].GetVendorIcon());
        SetStringProperty(env, infoObj, VERSION_STR, infos[i].GetVersion());
        if (ANI_OK != env->Object_CallMethodByName_Void(arrayObj, "$_set", "iY:", i, infoObj)) {
            PRINT_HILOGE("Set Array Element Failed");
            return arrayObj;
        }
    }
    return arrayObj;
}
}  // namespace OHOS::Print
