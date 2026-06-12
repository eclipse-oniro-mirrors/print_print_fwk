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

#include <curl/curl.h>
#include "curl_http_client.h"
#include "scan_log.h"

namespace OHOS::Scan {
static const long HTTP_STATUS_OK = 200;
static const long HTTP_REQUEST_TIMEOUT = 1;
static const char* SECURE_CIPHER_LIST =
    "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
static const char* TLS13_CIPHER_LIST =
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";

CurlHttpClient::CurlGlobalInitializer::CurlGlobalInitializer()
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

CurlHttpClient::CurlGlobalInitializer::~CurlGlobalInitializer()
{
    curl_global_cleanup();
}

CurlHttpClient::CurlGlobalInitializer& CurlHttpClient::CurlGlobalInitializer::GetInstance()
{
    static CurlGlobalInitializer instance;
    return instance;
}

size_t CurlHttpClient::WriteCallback(void* contents, size_t size, size_t nmemb, void* userp)
{
    if (!contents || !userp) {
        SCAN_HILOGE("null pointer fail");
        return 0;
    }
    size_t totalSize = size * nmemb;
    std::string* responseStr = static_cast<std::string*>(userp);
    responseStr->append(static_cast<char*>(contents), totalSize);
    return totalSize;
}

bool CurlHttpClient::PerformHttpRequest(const std::string& url, std::string& responseBuffer)
{
    CurlGlobalInitializer::GetInstance();

    CURL* curlHandle = curl_easy_init();
    if (!curlHandle) {
        SCAN_HILOGE("Failed to initialize curl handle");
        return false;
    }

    curl_easy_setopt(curlHandle, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curlHandle, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curlHandle, CURLOPT_WRITEDATA, &responseBuffer);
    curl_easy_setopt(curlHandle, CURLOPT_TIMEOUT, HTTP_REQUEST_TIMEOUT);
    // Enforce TLS 1.2 or higher
    curl_easy_setopt(curlHandle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
     // Allow only AEAD ciphers with forward secrecy
    curl_easy_setopt(curlHandle, CURLOPT_SSL_CIPHER_LIST, SECURE_CIPHER_LIST);
    curl_easy_setopt(curlHandle, CURLOPT_TLS13_CIPHERS, TLS13_CIPHER_LIST);

    CURLcode curlResult = curl_easy_perform(curlHandle);
    if (curlResult != CURLE_OK) {
        SCAN_HILOGE("HTTP request failed: %{public}s", curl_easy_strerror(curlResult));
        curl_easy_cleanup(curlHandle);
        return false;
    }

    long httpStatusCode = 0;
    curl_easy_getinfo(curlHandle, CURLINFO_RESPONSE_CODE, &httpStatusCode);
    curl_easy_cleanup(curlHandle);

    if (httpStatusCode != HTTP_STATUS_OK) {
        SCAN_HILOGE("HTTP request failed with status code: %{public}ld", httpStatusCode);
        return false;
    }
    return true;
}

} // namespace OHOS::Scan
