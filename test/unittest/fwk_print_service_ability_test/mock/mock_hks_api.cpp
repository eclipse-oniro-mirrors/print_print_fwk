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

#include "mock_hks_api.h"

MockHksApi& MockHksApi::Instance()
{
    static MockHksApi instance;
    return instance;
}

int32_t MockHksApi::HksInitParamSet(HksParamSet **paramSet)
{
    if (initParamSetResult_ != HKS_SUCCESS) {
        return initParamSetResult_;
    }
    *paramSet = new HksParamSet();
    (*paramSet)->paramSetSize = sizeof(HksParamSet);
    (*paramSet)->paramsCnt = 0;
    return HKS_SUCCESS;
}

int32_t MockHksApi::HksAddParams(HksParamSet *paramSet, const HksParam *params, uint32_t paramsCnt)
{
    if (addParamsResult_ != HKS_SUCCESS) {
        return addParamsResult_;
    }
    if (paramSet == nullptr || params == nullptr) {
        return HKS_FAILURE;
    }
    paramSet->paramsCnt = paramsCnt;
    HksParam *paramArray = new HksParam[paramsCnt];
    for (uint32_t i = 0; i < paramsCnt; i++) {
        paramArray[i] = params[i];
    }
    (void)memcpy_s(paramSet->params, paramsCnt * sizeof(HksParam), paramArray, paramsCnt * sizeof(HksParam));
    delete[] paramArray;
    return HKS_SUCCESS;
}

int32_t MockHksApi::HksBuildParamSet(HksParamSet **paramSet)
{
    if (buildParamSetResult_ != HKS_SUCCESS) {
        return buildParamSetResult_;
    }
    return HKS_SUCCESS;
}

void MockHksApi::HksFreeParamSet(HksParamSet **paramSet)
{
    if (paramSet == nullptr || *paramSet == nullptr) {
        return;
    }
    HksParam *params = (*paramSet)->params;
    if (params != nullptr) {
        delete[] params;
    }
    delete *paramSet;
    *paramSet = nullptr;
}

int32_t MockHksApi::HksGenerateKey(const HksBlob *keyAlias, const HksParamSet *paramSet, const HksParamSet *paramSetOut)
{
    return generateKeyResult_;
}

int32_t MockHksApi::HksEncrypt(const HksBlob *keyAlias, const HksParamSet *paramSet,
    const HksBlob *plainText, HksBlob *cipherText)
{
    if (encryptResult_ != HKS_SUCCESS) {
        return encryptResult_;
    }
    if (plainText == nullptr || cipherText == nullptr || plainText->data == nullptr || cipherText->data == nullptr) {
        return HKS_FAILURE;
    }
    for (uint32_t i = 0; i < plainText->size && i < cipherText->size; i++) {
        cipherText->data[i] = plainText->data[i] ^ 0xAA;
    }
    cipherText->size = plainText->size + 16;
    return HKS_SUCCESS;
}

int32_t MockHksApi::HksDecrypt(const HksBlob *keyAlias, const HksParamSet *paramSet,
    const HksBlob *cipherText, HksBlob *plainText)
{
    if (decryptResult_ != HKS_SUCCESS) {
        return decryptResult_;
    }
    if (cipherText == nullptr || plainText == nullptr || cipherText->data == nullptr || plainText->data == nullptr) {
        return HKS_FAILURE;
    }
    uint32_t plainSize = cipherText->size > 16 ? cipherText->size - 16 : 0;
    for (uint32_t i = 0; i < plainSize && i < plainText->size; i++) {
        plainText->data[i] = cipherText->data[i] ^ 0xAA;
    }
    plainText->size = plainSize;
    return HKS_SUCCESS;
}

void MockHksApi::SetInitParamSetResult(int32_t result)
{
    initParamSetResult_ = result;
}

void MockHksApi::SetAddParamsResult(int32_t result)
{
    addParamsResult_ = result;
}

void MockHksApi::SetBuildParamSetResult(int32_t result)
{
    buildParamSetResult_ = result;
}

void MockHksApi::SetGenerateKeyResult(int32_t result)
{
    generateKeyResult_ = result;
}

void MockHksApi::SetEncryptResult(int32_t result)
{
    encryptResult_ = result;
}

void MockHksApi::SetDecryptResult(int32_t result)
{
    decryptResult_ = result;
}

void MockHksApi::Reset()
{
    initParamSetResult_ = HKS_SUCCESS;
    addParamsResult_ = HKS_SUCCESS;
    buildParamSetResult_ = HKS_SUCCESS;
    generateKeyResult_ = HKS_SUCCESS;
    encryptResult_ = HKS_SUCCESS;
    decryptResult_ = HKS_SUCCESS;
}