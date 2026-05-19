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

#ifndef MOCK_HKS_API_H
#define MOCK_HKS_API_H

#include <cstdint>
#include <cstring>
#include "hks_api.h"
#include "hks_param.h"

class MockHksApi {
public:
    static MockHksApi& Instance();
    
    int32_t HksInitParamSet(HksParamSet **paramSet);
    int32_t HksAddParams(HksParamSet *paramSet, const HksParam *params, uint32_t paramsCnt);
    int32_t HksBuildParamSet(HksParamSet **paramSet);
    void HksFreeParamSet(HksParamSet **paramSet);
    int32_t HksGenerateKey(const HksBlob *keyAlias, const HksParamSet *paramSet, const HksParamSet *paramSetOut);
    int32_t HksEncrypt(const HksBlob *keyAlias, const HksParamSet *paramSet,
        const HksBlob *plainText, HksBlob *cipherText);
    int32_t HksDecrypt(const HksBlob *keyAlias, const HksParamSet *paramSet,
        const HksBlob *cipherText, HksBlob *plainText);
    
    void SetInitParamSetResult(int32_t result);
    void SetAddParamsResult(int32_t result);
    void SetBuildParamSetResult(int32_t result);
    void SetGenerateKeyResult(int32_t result);
    void SetEncryptResult(int32_t result);
    void SetDecryptResult(int32_t result);
    void Reset();

private:
    MockHksApi() = default;
    ~MockHksApi() = default;
    
    int32_t initParamSetResult_ = HKS_SUCCESS;
    int32_t addParamsResult_ = HKS_SUCCESS;
    int32_t buildParamSetResult_ = HKS_SUCCESS;
    int32_t generateKeyResult_ = HKS_SUCCESS;
    int32_t encryptResult_ = HKS_SUCCESS;
    int32_t decryptResult_ = HKS_SUCCESS;
};

inline int32_t HksInitParamSet(HksParamSet **paramSet)
{
    return MockHksApi::Instance().HksInitParamSet(paramSet);
}

inline int32_t HksAddParams(HksParamSet *paramSet, const HksParam *params, uint32_t paramsCnt)
{
    return MockHksApi::Instance().HksAddParams(paramSet, params, paramsCnt);
}

inline int32_t HksBuildParamSet(HksParamSet **paramSet)
{
    return MockHksApi::Instance().HksBuildParamSet(paramSet);
}

inline void HksFreeParamSet(HksParamSet **paramSet)
{
    MockHksApi::Instance().HksFreeParamSet(paramSet);
}

inline int32_t HksGenerateKey(const HksBlob *keyAlias, const HksParamSet *paramSet, const HksParamSet *paramSetOut)
{
    return MockHksApi::Instance().HksGenerateKey(keyAlias, paramSet, paramSetOut);
}

inline int32_t HksEncrypt(const HksBlob *keyAlias, const HksParamSet *paramSet,
    const HksBlob *plainText, HksBlob *cipherText)
{
    return MockHksApi::Instance().HksEncrypt(keyAlias, paramSet, plainText, cipherText);
}

inline int32_t HksDecrypt(const HksBlob *keyAlias, const HksParamSet *paramSet,
    const HksBlob *cipherText, HksBlob *plainText)
{
    return MockHksApi::Instance().HksDecrypt(keyAlias, paramSet, cipherText, plainText);
}

#endif // MOCK_HKS_API_H