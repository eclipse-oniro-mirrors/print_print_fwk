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

#include "print_hks_adapter.h"
#include "print_log.h"
#include "print_constant.h"
#include <openssl/evp.h>
#include <securec.h>

namespace OHOS::Print {

const size_t AUTH_TAG_SIZE = 16;
static const std::string KEY_ALIAS_PREFIX = "print_custom_option_key_user_";
constexpr size_t BASE64_LAST_PADDING_OFFSET = 1;
constexpr size_t BASE64_SECOND_LAST_PADDING_OFFSET = 2;

int32_t HksAdapter::HksKeyExist(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet)
{
    return ::HksKeyExist(keyAlias, paramSet);
}

int32_t HksAdapter::HksGenerateKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksParamSet *paramSetOut)
{
    return ::HksGenerateKey(keyAlias, paramSet, paramSetOut);
}

int32_t HksAdapter::HksEncrypt(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText)
{
    return ::HksEncrypt(keyAlias, paramSet, plainText, cipherText);
}

int32_t HksAdapter::HksDecrypt(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText)
{
    return ::HksDecrypt(keyAlias, paramSet, cipherText, plainText);
}

int32_t HksAdapter::HksInitParamSet(struct HksParamSet **paramSet)
{
    return ::HksInitParamSet(paramSet);
}

int32_t HksAdapter::HksAddParams(struct HksParamSet *paramSet,
    const struct HksParam *params, uint32_t paramsCnt)
{
    return ::HksAddParams(paramSet, params, paramsCnt);
}

int32_t HksAdapter::HksBuildParamSet(struct HksParamSet **paramSet)
{
    return ::HksBuildParamSet(paramSet);
}

void HksAdapter::HksFreeParamSet(struct HksParamSet **paramSet)
{
    ::HksFreeParamSet(paramSet);
}

int32_t HksAdapter::EncryptCustomOption(int32_t userId, struct HksBlob &plainBlob, struct HksBlob &cipherBlob)
{
    if (userId == INVALID_USER_ID) {
        PRINT_HILOGE("invalid user id");
        return HKS_FAILURE;
    }
    std::string keyAliasStr = KEY_ALIAS_PREFIX + std::to_string(userId);
    struct HksBlob keyAlias = {
        .size = keyAliasStr.size(),
        .data = (uint8_t *)keyAliasStr.data()
    };
    
    struct HksParamSet *genParamSet = nullptr;
    int32_t ret = InitGenParamSet(userId, &genParamSet);
    if (ret != HKS_SUCCESS) {
        PRINT_HILOGE("InitGenParamSet failed, ret: %{public}d", ret);
        return ret;
    }
    
    ret = HksKeyExist(&keyAlias, genParamSet);
    if (ret == HKS_SUCCESS) {
        PRINT_HILOGI("key already exists, skip generate");
    } else if (ret == HKS_ERROR_NOT_EXIST) {
        ret = HksGenerateKey(&keyAlias, genParamSet, nullptr);
        if (ret != HKS_SUCCESS) {
            PRINT_HILOGE("HksGenerateKey failed, ret: %{public}d", ret);
            HksFreeParamSet(&genParamSet);
            return ret;
        }
    } else {
        PRINT_HILOGE("HksKeyExist failed, ret: %{public}d", ret);
        HksFreeParamSet(&genParamSet);
        return ret;
    }
    
    struct HksParamSet *encryptParamSet = nullptr;
    ret = InitCipherParamSet(userId, &encryptParamSet, HKS_KEY_PURPOSE_ENCRYPT);
    if (ret != HKS_SUCCESS) {
        HksFreeParamSet(&genParamSet);
        return ret;
    }
    
    ret = DoEncrypt(&keyAlias, encryptParamSet, plainBlob, cipherBlob);
    
    HksFreeParamSet(&genParamSet);
    HksFreeParamSet(&encryptParamSet);
    return ret;
}

int32_t HksAdapter::DecryptCustomOption(int32_t userId, struct HksBlob &cipherBlob, struct HksBlob &plainBlob)
{
    if (userId == INVALID_USER_ID) {
        PRINT_HILOGE("invalid user id");
        return HKS_FAILURE;
    }
    std::string keyAliasStr = KEY_ALIAS_PREFIX + std::to_string(userId);
    struct HksBlob keyAlias = {
        .size = keyAliasStr.size(),
        .data = (uint8_t *)keyAliasStr.data()
    };
    
    struct HksParamSet *decryptParamSet = nullptr;
    int32_t ret = InitCipherParamSet(userId, &decryptParamSet, HKS_KEY_PURPOSE_DECRYPT);
    if (ret != HKS_SUCCESS) {
        return ret;
    }
    
    ret = DoDecrypt(&keyAlias, decryptParamSet, cipherBlob, plainBlob);
    
    HksFreeParamSet(&decryptParamSet);
    return ret;
}

int32_t HksAdapter::InitGenParamSet(int32_t userId, struct HksParamSet **paramSet)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        PRINT_HILOGE("HksInitParamSet failed, ret: %{public}d", ret);
        return ret;
    }
    
    struct HksParam genParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = userId }
    };
    
    ret = HksAddParams(*paramSet, genParams, sizeof(genParams) / sizeof(genParams[0]));
    if (ret != HKS_SUCCESS) {
        PRINT_HILOGE("HksAddParams failed, ret: %{public}d", ret);
        HksFreeParamSet(paramSet);
        return ret;
    }
    
    ret = HksBuildParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        PRINT_HILOGE("HksBuildParamSet failed, ret: %{public}d", ret);
        HksFreeParamSet(paramSet);
    }
    return ret;
}

int32_t HksAdapter::InitCipherParamSet(int32_t userId, struct HksParamSet **paramSet, uint32_t purpose)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        PRINT_HILOGE("HksInitParamSet failed, ret: %{public}d", ret);
        return ret;
    }
    
    uint8_t nonceData[12] = {0};
    struct HksBlob nonce = { .size = sizeof(nonceData), .data = nonceData };
    struct HksParam cipherParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_AES },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = purpose },
        { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_GCM },
        { .tag = HKS_TAG_PADDING, .uint32Param = HKS_PADDING_NONE },
        { .tag = HKS_TAG_NONCE, .blob = nonce },
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = userId }
    };
    
    ret = HksAddParams(*paramSet, cipherParams, sizeof(cipherParams) / sizeof(cipherParams[0]));
    if (ret != HKS_SUCCESS) {
        PRINT_HILOGE("HksAddParams failed, ret: %{public}d", ret);
        HksFreeParamSet(paramSet);
        return ret;
    }
    
    ret = HksBuildParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        PRINT_HILOGE("HksBuildParamSet failed, ret: %{public}d", ret);
        HksFreeParamSet(paramSet);
    }
    return ret;
}

int32_t HksAdapter::DoEncrypt(struct HksBlob *keyAlias, struct HksParamSet *paramSet,
    struct HksBlob &plainBlob, struct HksBlob &cipherBlob)
{
    size_t bufferSize = plainBlob.size + AUTH_TAG_SIZE;
    cipherBlob.data = new (std::nothrow) uint8_t[bufferSize];
    if (cipherBlob.data == nullptr) {
        PRINT_HILOGE("failed to allocate cipher buffer");
        return HKS_ERROR_MALLOC_FAIL;
    }
    
    cipherBlob.size = bufferSize;
    int32_t ret = HksEncrypt(keyAlias, paramSet, &plainBlob, &cipherBlob);
    if (ret != HKS_SUCCESS) {
        PRINT_HILOGE("HksEncrypt failed, ret: %{public}d", ret);
        (void)memset_s(cipherBlob.data, bufferSize, 0, bufferSize);
        delete[] cipherBlob.data;
        cipherBlob.data = nullptr;
        cipherBlob.size = 0;
        return ret;
    }
    
    return HKS_SUCCESS;
}

int32_t HksAdapter::DoDecrypt(struct HksBlob *keyAlias, struct HksParamSet *paramSet,
    struct HksBlob &cipherBlob, struct HksBlob &plainBlob)
{
    size_t bufferSize = cipherBlob.size;
    plainBlob.data = new (std::nothrow) uint8_t[bufferSize];
    if (plainBlob.data == nullptr) {
        PRINT_HILOGE("failed to allocate plain buffer");
        return HKS_ERROR_MALLOC_FAIL;
    }
    
    plainBlob.size = bufferSize;
    int32_t ret = HksDecrypt(keyAlias, paramSet, &cipherBlob, &plainBlob);
    if (ret != HKS_SUCCESS) {
        PRINT_HILOGE("HksDecrypt failed, ret: %{public}d", ret);
        (void)memset_s(plainBlob.data, bufferSize, 0, bufferSize);
        delete[] plainBlob.data;
        plainBlob.data = nullptr;
        plainBlob.size = 0;
        return ret;
    }
    
    return HKS_SUCCESS;
}

int HksAdapter::EVP_EncodeBlockWrapper(unsigned char *t, const unsigned char *f, int n)
{
    return EVP_EncodeBlock(t, f, n);
}

int HksAdapter::EVP_DecodeBlockWrapper(unsigned char *t, const unsigned char *f, int n)
{
    return EVP_DecodeBlock(t, f, n);
}

bool HksAdapter::Base64Encode(const struct HksBlob &cipherBlob, SecureBlob &secureValue)
{
    if (cipherBlob.data == nullptr || cipherBlob.size == 0) {
        return false;
    }
    
    uint32_t outputLen = 4 * ((cipherBlob.size + 2) / 3);
    secureValue.Allocate(outputLen);
    
    if (secureValue.data == nullptr) {
        PRINT_HILOGE("SecureBlob allocate failed");
        return false;
    }
    
    int encodedLen = EVP_EncodeBlockWrapper(secureValue.data, cipherBlob.data, cipherBlob.size);
    if (encodedLen <= 0 || encodedLen != static_cast<int>(outputLen)) {
        PRINT_HILOGE("EVP_EncodeBlock failed, ret: %{public}d, expected: %{public}u", encodedLen, outputLen);
        secureValue.Clear();
        return false;
    }
    
    return true;
}

bool HksAdapter::Base64Decode(const struct HksBlob &base64Blob, struct HksBlob &cipherBlob)
{
    if (base64Blob.data == nullptr || base64Blob.size == 0) {
        cipherBlob.size = 0;
        cipherBlob.data = nullptr;
        return true;
    }
    
    size_t paddingCount = 0;
    if (base64Blob.size >= BASE64_LAST_PADDING_OFFSET &&
        base64Blob.data[base64Blob.size - BASE64_LAST_PADDING_OFFSET] == '=') {
        paddingCount++;
    }
    if (base64Blob.size >= BASE64_SECOND_LAST_PADDING_OFFSET &&
        base64Blob.data[base64Blob.size - BASE64_SECOND_LAST_PADDING_OFFSET] == '=') {
        paddingCount++;
    }
    
    size_t decodedLen = base64Blob.size / 4 * 3 - paddingCount;
    cipherBlob.data = new (std::nothrow) uint8_t[decodedLen];
    if (cipherBlob.data == nullptr) {
        PRINT_HILOGE("failed to allocate cipher buffer for base64 decode");
        return false;
    }
    
    int ret = EVP_DecodeBlockWrapper(cipherBlob.data, base64Blob.data, static_cast<int>(base64Blob.size));
    if (ret < 0) {
        PRINT_HILOGE("Base64 decode failed");
        delete[] cipherBlob.data;
        cipherBlob.data = nullptr;
        cipherBlob.size = 0;
        return false;
    }
    
    cipherBlob.size = static_cast<uint32_t>(decodedLen);
    return true;
}

} // Namespace OHOS::Print