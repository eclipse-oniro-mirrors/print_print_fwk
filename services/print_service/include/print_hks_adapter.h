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

#ifndef PRINT_HKS_ADAPTER_H
#define PRINT_HKS_ADAPTER_H

#include <string>
#include <memory>
#include <cstdint>
#include "hks_api.h"
#include "hks_param.h"
#include "printer_user_preferences.h"

namespace OHOS::Print {

class IHksAdapter {
public:
    virtual ~IHksAdapter() = default;
    
    virtual int32_t HksKeyExist(const struct HksBlob *keyAlias,
        const struct HksParamSet *paramSet) = 0;
    
    virtual int32_t HksGenerateKey(const struct HksBlob *keyAlias,
        const struct HksParamSet *paramSet, struct HksParamSet *paramSetOut) = 0;
    
    virtual int32_t HksGenerateRandom(const struct HksParamSet *paramSet, struct HksBlob *randomBlob) = 0;
    
    virtual int32_t HksEncrypt(const struct HksBlob *keyAlias,
        const struct HksParamSet *paramSet,
        const struct HksBlob *plainText, struct HksBlob *cipherText) = 0;
    
    virtual int32_t HksDecrypt(const struct HksBlob *keyAlias,
        const struct HksParamSet *paramSet,
        const struct HksBlob *cipherText, struct HksBlob *plainText) = 0;
    
    virtual int32_t HksInitParamSet(struct HksParamSet **paramSet) = 0;
    virtual int32_t HksAddParams(struct HksParamSet *paramSet,
        const struct HksParam *params, uint32_t paramsCnt) = 0;
    virtual int32_t HksBuildParamSet(struct HksParamSet **paramSet) = 0;
    virtual void HksFreeParamSet(struct HksParamSet **paramSet) = 0;
    
    virtual int32_t EncryptCustomOption(int32_t userId, struct HksBlob &plainBlob, struct HksBlob &cipherBlob) = 0;
    virtual int32_t DecryptCustomOption(int32_t userId, struct HksBlob &cipherBlob, struct HksBlob &plainBlob) = 0;
    
    virtual bool Base64Encode(const struct HksBlob &cipherBlob, SecureBlob &secureValue) = 0;
    virtual bool Base64Decode(const struct HksBlob &base64Blob, struct HksBlob &cipherBlob) = 0;
};

class HksAdapter : public IHksAdapter {
public:
    int32_t HksKeyExist(const struct HksBlob *keyAlias,
        const struct HksParamSet *paramSet) override;
    
    int32_t HksGenerateKey(const struct HksBlob *keyAlias,
        const struct HksParamSet *paramSet, struct HksParamSet *paramSetOut) override;
    
    int32_t HksGenerateRandom(const struct HksParamSet *paramSet, struct HksBlob *randomBlob) override;
    
    int32_t HksEncrypt(const struct HksBlob *keyAlias,
        const struct HksParamSet *paramSet,
        const struct HksBlob *plainText, struct HksBlob *cipherText) override;
    
    int32_t HksDecrypt(const struct HksBlob *keyAlias,
        const struct HksParamSet *paramSet,
        const struct HksBlob *cipherText, struct HksBlob *plainText) override;
    
    int32_t HksInitParamSet(struct HksParamSet **paramSet) override;
    int32_t HksAddParams(struct HksParamSet *paramSet,
        const struct HksParam *params, uint32_t paramsCnt) override;
    int32_t HksBuildParamSet(struct HksParamSet **paramSet) override;
    void HksFreeParamSet(struct HksParamSet **paramSet) override;
    
    int32_t EncryptCustomOption(int32_t userId, struct HksBlob &plainBlob, struct HksBlob &cipherBlob) override;
    int32_t DecryptCustomOption(int32_t userId, struct HksBlob &cipherBlob, struct HksBlob &plainBlob) override;
    
    bool Base64Encode(const struct HksBlob &cipherBlob, SecureBlob &secureValue) override;
    bool Base64Decode(const struct HksBlob &base64Blob, struct HksBlob &cipherBlob) override;

protected:
    virtual int EVP_EncodeBlockWrapper(unsigned char *t, const unsigned char *f, int n);
    virtual int EVP_DecodeBlockWrapper(unsigned char *t, const unsigned char *f, int n);

private:
    int32_t InitGenParamSet(int32_t userId, struct HksParamSet **paramSet);
    int32_t InitCipherParamSet(int32_t userId, struct HksParamSet **paramSet, uint32_t purpose,
        const struct HksBlob *nonce);
    int32_t DoEncrypt(struct HksBlob *keyAlias, struct HksParamSet *paramSet,
        struct HksBlob &plainBlob, struct HksBlob &cipherBlob, const struct HksBlob &nonce);
    int32_t DoDecrypt(struct HksBlob *keyAlias, struct HksParamSet *paramSet,
        struct HksBlob &cipherBlob, struct HksBlob &plainBlob);
};

} // namespace OHOS::Print

#endif // PRINT_HKS_ADAPTER_H