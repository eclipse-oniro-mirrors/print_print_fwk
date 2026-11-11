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

#include "i_print_feature.h"

namespace OHOS::Print {

class TestPrintFeature : public IPrintFeature {
public:
    ~TestPrintFeature() override = default;

    void *QueryInterface(PrintFeatureIid /* iid */) override
    {
        return static_cast<IPrintFeature *>(this);
    }
};

extern "C" __attribute__((visibility("default"))) IPrintFeature *CreatePrintFeature()
{
    return new TestPrintFeature();
}

extern "C" __attribute__((visibility("default"))) IPrintFeature *CreateNullPrintFeature()
{
    return nullptr;
}

extern "C" __attribute__((visibility("default"))) void DestroyPrintFeature(IPrintFeature *feature)
{
    delete feature;
}

} // namespace OHOS::Print
