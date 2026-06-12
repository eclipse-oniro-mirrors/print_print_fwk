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

#ifndef MOCK_HKS_ADAPTER_H
#define MOCK_HKS_ADAPTER_H

#include <gmock/gmock.h>
#include "print_hks_adapter.h"

namespace OHOS::Print {

class MockHksAdapter : public HksAdapter {
public:
    MOCK_METHOD2(HksKeyExist, int32_t(const HksBlob*, const HksParamSet*));
    MOCK_METHOD3(HksGenerateKey, int32_t(const HksBlob*, const HksParamSet*, HksParamSet*));
    MOCK_METHOD4(HksEncrypt, int32_t(const HksBlob*, const HksParamSet*, const HksBlob*, HksBlob*));
    MOCK_METHOD4(HksDecrypt, int32_t(const HksBlob*, const HksParamSet*, const HksBlob*, HksBlob*));
    MOCK_METHOD1(HksInitParamSet, int32_t(HksParamSet**));
    MOCK_METHOD3(HksAddParams, int32_t(HksParamSet*, const HksParam*, uint32_t));
    MOCK_METHOD1(HksBuildParamSet, int32_t(HksParamSet**));
    MOCK_METHOD1(HksFreeParamSet, void(HksParamSet**));
    MOCK_METHOD3(EVP_EncodeBlockWrapper, int(unsigned char*, const unsigned char*, int));
    MOCK_METHOD3(EVP_DecodeBlockWrapper, int(unsigned char*, const unsigned char*, int));
};

} // namespace OHOS::Print

#endif // MOCK_HKS_ADAPTER_H