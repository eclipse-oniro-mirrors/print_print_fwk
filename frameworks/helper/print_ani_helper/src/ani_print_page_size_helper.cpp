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
#include "ani_print_page_size_helper.h"
#include "print_log.h"

namespace {
const char* ID_STR = "id";
const char* NAME_STR = "name";
const char* WIDTH_STR = "width";
const char* HEIGHT_STR = "height";
}

namespace OHOS::Print {
static const char *CLASS_NAME = "L@ohos/print/PrintPageSize;";
PrintPageSize AniPrintPageSizeHelper::ParsePrintPageSize(ani_env *env, ani_object pageSizeAni)
{
    PRINT_HILOGI("enter ParsePrintPageSize");
    PrintPageSize pageSize;

    std::string id;
    if (GetStringOrUndefined(env, pageSizeAni, ID_STR, id)) {
        pageSize.SetId(id);
    }
    std::string name;
    if (GetStringOrUndefined(env, pageSizeAni, NAME_STR, name)) {
        pageSize.SetName(name);
    }
    int32_t width = 0;
    if (GetIntByName(env, pageSizeAni, WIDTH_STR, width)) {
        pageSize.SetWidth(static_cast<uint32_t>(width));
    }
    int32_t height = 0;
    if (GetIntByName(env, pageSizeAni, HEIGHT_STR, height)) {
        pageSize.SetHeight(static_cast<uint32_t>(height));
    }
    return pageSize;
}

ani_object AniPrintPageSizeHelper::CreatePageSize(ani_env *env, const PrintPageSize& pageSize)
{
    PRINT_HILOGI("enter CreatePageSize");
    ani_class cls;
    ani_object obj = CreateObject(env, CLASS_NAME, cls);

    SetFieldString(env, cls, obj, ID_STR, pageSize.GetId());
    SetFieldString(env, cls, obj, NAME_STR, pageSize.GetName());
    SetFieldInt(env, cls, obj, WIDTH_STR, static_cast<int32_t>(pageSize.GetWidth()));
    SetFieldInt(env, cls, obj, HEIGHT_STR, static_cast<int32_t>(pageSize.GetHeight()));

    return obj;
}
}  // namespace OHOS::Print
