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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "mock_hks_adapter.h"
#include "print_hks_adapter.h"
#include "hks_type.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace Print {

class PrintHksAdapterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    
protected:
    std::shared_ptr<MockHksAdapter> mockAdapter_;
};

void PrintHksAdapterTest::SetUpTestCase(void)
{}

void PrintHksAdapterTest::TearDownTestCase(void)
{}

void PrintHksAdapterTest::SetUp(void)
{
    mockAdapter_ = std::make_shared<MockHksAdapter>();
}

void PrintHksAdapterTest::TearDown(void)
{
    mockAdapter_.reset();
}

HWTEST_F(PrintHksAdapterTest, EncryptCustomOption_EncryptSuccess_ReturnsSuccess, TestSize.Level1)
{
    struct HksBlob plainBlob = { .size = 9, .data = (uint8_t*)"test_data" };
    struct HksBlob cipherBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, HksKeyExist(_, _))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksGenerateRandom(_, _))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksEncrypt(_, _, _, _))
        .WillOnce(Return(HKS_SUCCESS));
    
    int32_t ret = mockAdapter_->EncryptCustomOption(0, plainBlob, cipherBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

HWTEST_F(PrintHksAdapterTest, EncryptCustomOption_KeyNotExist_GeneratesKeyAndEncrypts, TestSize.Level1)
{
    struct HksBlob plainBlob = { .size = 9, .data = (uint8_t*)"test_data" };
    struct HksBlob cipherBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, HksKeyExist(_, _))
        .WillOnce(Return(HKS_ERROR_NOT_EXIST));
    EXPECT_CALL(*mockAdapter_, HksGenerateKey(_, _, _))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksGenerateRandom(_, _))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksEncrypt(_, _, _, _))
        .WillOnce(Return(HKS_SUCCESS));
    
    int32_t ret = mockAdapter_->EncryptCustomOption(0, plainBlob, cipherBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

HWTEST_F(PrintHksAdapterTest, DecryptCustomOption_DecryptSuccess_ReturnsSuccess, TestSize.Level1)
{
    struct HksBlob cipherBlob = { .size = 16, .data = (uint8_t*)"encrypted_data" };
    struct HksBlob plainBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, HksDecrypt(_, _, _, _))
        .WillOnce(Return(HKS_SUCCESS));
    
    int32_t ret = mockAdapter_->DecryptCustomOption(0, cipherBlob, plainBlob);
    EXPECT_EQ(ret, HKS_SUCCESS);
}

HWTEST_F(PrintHksAdapterTest, DecryptCustomOption_DecryptFail_ReturnsError, TestSize.Level1)
{
    struct HksBlob cipherBlob = { .size = 16, .data = (uint8_t*)"encrypted_data" };
    struct HksBlob plainBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, HksDecrypt(_, _, _, _))
        .WillOnce(Return(HKS_FAILURE));
    
    int32_t ret = mockAdapter_->DecryptCustomOption(0, cipherBlob, plainBlob);
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(PrintHksAdapterTest, EncryptCustomOption_InvalidUserId_ReturnsError, TestSize.Level1)
{
    struct HksBlob plainBlob = { .size = 9, .data = (uint8_t*)"test_data" };
    struct HksBlob cipherBlob = { 0, nullptr };
    
    int32_t ret = mockAdapter_->EncryptCustomOption(-1, plainBlob, cipherBlob);
    EXPECT_EQ(ret, HKS_FAILURE);
}

HWTEST_F(PrintHksAdapterTest, EncryptCustomOption_InitGenParamSetFail_ReturnsError, TestSize.Level1)
{
    struct HksBlob plainBlob = { .size = 9, .data = (uint8_t*)"test_data" };
    struct HksBlob cipherBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, HksInitParamSet(_))
        .WillOnce(Return(HKS_FAILURE));
    
    int32_t ret = mockAdapter_->EncryptCustomOption(0, plainBlob, cipherBlob);
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(PrintHksAdapterTest, EncryptCustomOption_HksKeyExistOtherError_ReturnsError, TestSize.Level1)
{
    struct HksBlob plainBlob = { .size = 9, .data = (uint8_t*)"test_data" };
    struct HksBlob cipherBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, HksInitParamSet(_))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksAddParams(_, _, _))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksBuildParamSet(_))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksKeyExist(_, _))
        .WillOnce(Return(HKS_FAILURE));
    EXPECT_CALL(*mockAdapter_, HksFreeParamSet(_))
        .Times(1);
    
    int32_t ret = mockAdapter_->EncryptCustomOption(0, plainBlob, cipherBlob);
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(PrintHksAdapterTest, EncryptCustomOption_GenerateKeyFail_ReturnsError, TestSize.Level1)
{
    struct HksBlob plainBlob = { .size = 9, .data = (uint8_t*)"test_data" };
    struct HksBlob cipherBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, HksInitParamSet(_))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksAddParams(_, _, _))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksBuildParamSet(_))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksKeyExist(_, _))
        .WillOnce(Return(HKS_ERROR_NOT_EXIST));
    EXPECT_CALL(*mockAdapter_, HksGenerateKey(_, _, _))
        .WillOnce(Return(HKS_FAILURE));
    EXPECT_CALL(*mockAdapter_, HksFreeParamSet(_))
        .Times(1);
    
    int32_t ret = mockAdapter_->EncryptCustomOption(0, plainBlob, cipherBlob);
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(PrintHksAdapterTest, EncryptCustomOption_InitCipherParamSetFail_ReturnsError, TestSize.Level1)
{
    struct HksBlob plainBlob = { .size = 9, .data = (uint8_t*)"test_data" };
    struct HksBlob cipherBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, HksInitParamSet(_))
        .WillOnce(Return(HKS_SUCCESS))
        .WillOnce(Return(HKS_FAILURE));
    EXPECT_CALL(*mockAdapter_, HksAddParams(_, _, _))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksBuildParamSet(_))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksKeyExist(_, _))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksGenerateRandom(_, _))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksFreeParamSet(_))
        .Times(1);
    
    int32_t ret = mockAdapter_->EncryptCustomOption(0, plainBlob, cipherBlob);
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(PrintHksAdapterTest, EncryptCustomOption_HksEncryptFail_ReturnsError, TestSize.Level1)
{
    struct HksBlob plainBlob = { .size = 9, .data = (uint8_t*)"test_data" };
    struct HksBlob cipherBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, HksInitParamSet(_))
        .WillOnce(Return(HKS_SUCCESS))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksAddParams(_, _, _))
        .WillOnce(Return(HKS_SUCCESS))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksBuildParamSet(_))
        .WillOnce(Return(HKS_SUCCESS))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksKeyExist(_, _))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksGenerateRandom(_, _))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksEncrypt(_, _, _, _))
        .WillOnce(Return(HKS_FAILURE));
    EXPECT_CALL(*mockAdapter_, HksFreeParamSet(_))
        .Times(2);
    
    int32_t ret = mockAdapter_->EncryptCustomOption(0, plainBlob, cipherBlob);
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(PrintHksAdapterTest, EncryptCustomOption_HksGenerateRandomFail_ReturnsError, TestSize.Level1)
{
    struct HksBlob plainBlob = { .size = 9, .data = (uint8_t*)"test_data" };
    struct HksBlob cipherBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, HksInitParamSet(_))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksAddParams(_, _, _))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksBuildParamSet(_))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksKeyExist(_, _))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksGenerateRandom(_, _))
        .WillOnce(Return(HKS_FAILURE));
    EXPECT_CALL(*mockAdapter_, HksFreeParamSet(_))
        .Times(1);
    
    int32_t ret = mockAdapter_->EncryptCustomOption(0, plainBlob, cipherBlob);
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(PrintHksAdapterTest, DecryptCustomOption_CipherBlobSizeTooSmall_ReturnsError, TestSize.Level1)
{
    struct HksBlob cipherBlob = { .size = 8, .data = (uint8_t*)"short" };
    struct HksBlob plainBlob = { 0, nullptr };
    
    int32_t ret = mockAdapter_->DecryptCustomOption(0, cipherBlob, plainBlob);
    EXPECT_EQ(ret, HKS_FAILURE);
}

HWTEST_F(PrintHksAdapterTest, DecryptCustomOption_InvalidUserId_ReturnsError, TestSize.Level1)
{
    struct HksBlob cipherBlob = { .size = 16, .data = (uint8_t*)"encrypted_data" };
    struct HksBlob plainBlob = { 0, nullptr };
    
    int32_t ret = mockAdapter_->DecryptCustomOption(-1, cipherBlob, plainBlob);
    EXPECT_EQ(ret, HKS_FAILURE);
}

HWTEST_F(PrintHksAdapterTest, DecryptCustomOption_InitCipherParamSetFail_ReturnsError, TestSize.Level1)
{
    struct HksBlob cipherBlob = { .size = 16, .data = (uint8_t*)"encrypted_data" };
    struct HksBlob plainBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, HksInitParamSet(_))
        .WillOnce(Return(HKS_FAILURE));
    
    int32_t ret = mockAdapter_->DecryptCustomOption(0, cipherBlob, plainBlob);
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(PrintHksAdapterTest, InitGenParamSet_HksAddParamsFail_ReturnsError, TestSize.Level1)
{
    struct HksBlob plainBlob = { .size = 9, .data = (uint8_t*)"test_data" };
    struct HksBlob cipherBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, HksInitParamSet(_))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksAddParams(_, _, _))
        .WillOnce(Return(HKS_FAILURE));
    EXPECT_CALL(*mockAdapter_, HksFreeParamSet(_))
        .Times(1);
    
    int32_t ret = mockAdapter_->EncryptCustomOption(0, plainBlob, cipherBlob);
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(PrintHksAdapterTest, InitGenParamSet_HksBuildParamSetFail_ReturnsError, TestSize.Level1)
{
    struct HksBlob plainBlob = { .size = 9, .data = (uint8_t*)"test_data" };
    struct HksBlob cipherBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, HksInitParamSet(_))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksAddParams(_, _, _))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksBuildParamSet(_))
        .WillOnce(Return(HKS_FAILURE));
    EXPECT_CALL(*mockAdapter_, HksFreeParamSet(_))
        .Times(1);
    
    int32_t ret = mockAdapter_->EncryptCustomOption(0, plainBlob, cipherBlob);
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(PrintHksAdapterTest, InitCipherParamSet_HksAddParamsFail_ReturnsError, TestSize.Level1)
{
    struct HksBlob cipherBlob = { .size = 16, .data = (uint8_t*)"encrypted_data" };
    struct HksBlob plainBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, HksInitParamSet(_))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksAddParams(_, _, _))
        .WillOnce(Return(HKS_FAILURE));
    EXPECT_CALL(*mockAdapter_, HksFreeParamSet(_))
        .Times(1);
    
    int32_t ret = mockAdapter_->DecryptCustomOption(0, cipherBlob, plainBlob);
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(PrintHksAdapterTest, InitCipherParamSet_HksBuildParamSetFail_ReturnsError, TestSize.Level1)
{
    struct HksBlob cipherBlob = { .size = 16, .data = (uint8_t*)"encrypted_data" };
    struct HksBlob plainBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, HksInitParamSet(_))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksAddParams(_, _, _))
        .WillOnce(Return(HKS_SUCCESS));
    EXPECT_CALL(*mockAdapter_, HksBuildParamSet(_))
        .WillOnce(Return(HKS_FAILURE));
    EXPECT_CALL(*mockAdapter_, HksFreeParamSet(_))
        .Times(1);
    
    int32_t ret = mockAdapter_->DecryptCustomOption(0, cipherBlob, plainBlob);
    EXPECT_NE(ret, HKS_SUCCESS);
}

HWTEST_F(PrintHksAdapterTest, Base64Encode_NullData_ReturnsFalse, TestSize.Level1)
{
    struct HksBlob cipherBlob = { .size = 16, .data = nullptr };
    SecureBlob secureValue;
    
    bool ret = mockAdapter_->Base64Encode(cipherBlob, secureValue);
    EXPECT_FALSE(ret);
}

HWTEST_F(PrintHksAdapterTest, Base64Encode_ZeroSize_ReturnsFalse, TestSize.Level1)
{
    uint8_t data[4] = {1, 2, 3, 4};
    struct HksBlob cipherBlob = { .size = 0, .data = data };
    SecureBlob secureValue;
    
    bool ret = mockAdapter_->Base64Encode(cipherBlob, secureValue);
    EXPECT_FALSE(ret);
}

HWTEST_F(PrintHksAdapterTest, Base64Encode_AllocateFail_ReturnsFalse, TestSize.Level1)
{
    uint8_t data[] = "Hello";
    struct HksBlob cipherBlob = { .size = 5, .data = data };
    SecureBlob secureValue;
    secureValue.data = nullptr;
    secureValue.size = 0;
    
    bool ret = mockAdapter_->Base64Encode(cipherBlob, secureValue);
    EXPECT_FALSE(ret);
}

HWTEST_F(PrintHksAdapterTest, Base64Encode_EncodeFail_ReturnsFalse, TestSize.Level1)
{
    uint8_t data[] = "Hello";
    struct HksBlob cipherBlob = { .size = 5, .data = data };
    SecureBlob secureValue;
    
    EXPECT_CALL(*mockAdapter_, EVP_EncodeBlockWrapper(_, _, _))
        .WillOnce(Return(-1));
    
    bool ret = mockAdapter_->Base64Encode(cipherBlob, secureValue);
    EXPECT_FALSE(ret);
}

HWTEST_F(PrintHksAdapterTest, Base64Encode_EncodeLenMismatch_ReturnsFalse, TestSize.Level1)
{
    uint8_t data[] = "Hello";
    struct HksBlob cipherBlob = { .size = 5, .data = data };
    SecureBlob secureValue;
    
    EXPECT_CALL(*mockAdapter_, EVP_EncodeBlockWrapper(_, _, _))
        .WillOnce(Return(10));
    
    bool ret = mockAdapter_->Base64Encode(cipherBlob, secureValue);
    EXPECT_FALSE(ret);
}

HWTEST_F(PrintHksAdapterTest, Base64Encode_Success_ReturnsTrue, TestSize.Level1)
{
    uint8_t data[] = "Hello";
    struct HksBlob cipherBlob = { .size = 5, .data = data };
    SecureBlob secureValue;
    
    EXPECT_CALL(*mockAdapter_, EVP_EncodeBlockWrapper(_, _, _))
        .WillOnce(Return(8));
    
    bool ret = mockAdapter_->Base64Encode(cipherBlob, secureValue);
    EXPECT_TRUE(ret);
    EXPECT_NE(secureValue.data, nullptr);
    EXPECT_GT(secureValue.size, 0u);
}

HWTEST_F(PrintHksAdapterTest, Base64Decode_NullData_ReturnsTrue, TestSize.Level1)
{
    struct HksBlob base64Blob = { .size = 16, .data = nullptr };
    struct HksBlob cipherBlob = { 0, nullptr };
    
    bool ret = mockAdapter_->Base64Decode(base64Blob, cipherBlob);
    EXPECT_TRUE(ret);
    EXPECT_EQ(cipherBlob.size, 0u);
    EXPECT_EQ(cipherBlob.data, nullptr);
}

HWTEST_F(PrintHksAdapterTest, Base64Decode_ZeroSize_ReturnsTrue, TestSize.Level1)
{
    uint8_t data[] = "test";
    struct HksBlob base64Blob = { .size = 0, .data = data };
    struct HksBlob cipherBlob = { 0, nullptr };
    
    bool ret = mockAdapter_->Base64Decode(base64Blob, cipherBlob);
    EXPECT_TRUE(ret);
    EXPECT_EQ(cipherBlob.size, 0u);
    EXPECT_EQ(cipherBlob.data, nullptr);
}

HWTEST_F(PrintHksAdapterTest, Base64Decode_InvalidSizeNotMultipleOfFour_ReturnsFalse, TestSize.Level1)
{
    uint8_t data[] = "SGVsbG8";
    struct HksBlob base64Blob = { .size = 7, .data = data };
    struct HksBlob cipherBlob = { 0, nullptr };
    
    bool ret = mockAdapter_->Base64Decode(base64Blob, cipherBlob);
    EXPECT_FALSE(ret);
}

HWTEST_F(PrintHksAdapterTest, Base64Decode_DecodeFail_ReturnsFalse, TestSize.Level1)
{
    uint8_t base64Data[] = "SGVsbG8=";
    struct HksBlob base64Blob = { .size = 8, .data = base64Data };
    struct HksBlob cipherBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, EVP_DecodeBlockWrapper(_, _, _))
        .WillOnce(Return(-1));
    
    bool ret = mockAdapter_->Base64Decode(base64Blob, cipherBlob);
    EXPECT_FALSE(ret);
    EXPECT_EQ(cipherBlob.data, nullptr);
    EXPECT_EQ(cipherBlob.size, 0u);
}

HWTEST_F(PrintHksAdapterTest, Base64Decode_SuccessWithOnePadding_ReturnsTrue, TestSize.Level1)
{
    uint8_t base64Data[] = "SGVsbG8=";
    struct HksBlob base64Blob = { .size = 8, .data = base64Data };
    struct HksBlob cipherBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, EVP_DecodeBlockWrapper(_, _, _))
        .WillOnce(Return(5));
    
    bool ret = mockAdapter_->Base64Decode(base64Blob, cipherBlob);
    EXPECT_TRUE(ret);
    EXPECT_NE(cipherBlob.data, nullptr);
    EXPECT_GT(cipherBlob.size, 0u);
    delete[] cipherBlob.data;
}

HWTEST_F(PrintHksAdapterTest, Base64Decode_SuccessWithTwoPadding_ReturnsTrue, TestSize.Level1)
{
    uint8_t base64Data[] = "YQ==";
    struct HksBlob base64Blob = { .size = 4, .data = base64Data };
    struct HksBlob cipherBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, EVP_DecodeBlockWrapper(_, _, _))
        .WillOnce(Return(1));
    
    bool ret = mockAdapter_->Base64Decode(base64Blob, cipherBlob);
    EXPECT_TRUE(ret);
    EXPECT_NE(cipherBlob.data, nullptr);
    EXPECT_GT(cipherBlob.size, 0u);
    delete[] cipherBlob.data;
}

HWTEST_F(PrintHksAdapterTest, Base64Decode_SuccessNoPadding_ReturnsTrue, TestSize.Level1)
{
    uint8_t base64Data[] = "TWFu";
    struct HksBlob base64Blob = { .size = 4, .data = base64Data };
    struct HksBlob cipherBlob = { 0, nullptr };
    
    EXPECT_CALL(*mockAdapter_, EVP_DecodeBlockWrapper(_, _, _))
        .WillOnce(Return(3));
    
    bool ret = mockAdapter_->Base64Decode(base64Blob, cipherBlob);
    EXPECT_TRUE(ret);
    EXPECT_NE(cipherBlob.data, nullptr);
    EXPECT_EQ(cipherBlob.size, 3u);
    delete[] cipherBlob.data;
}

}  // namespace Print
}  // namespace OHOS