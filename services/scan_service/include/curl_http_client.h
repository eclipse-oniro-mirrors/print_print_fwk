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

#ifndef CURL_HTTP_CLIENT_H
#define CURL_HTTP_CLIENT_H

#include <string>

namespace OHOS::Scan {
class CurlHttpClient {
public:
    static bool PerformHttpRequest(const std::string& url, std::string& responseBuffer);

private:
    class CurlGlobalInitializer {
    public:
        static CurlGlobalInitializer& GetInstance();
        ~CurlGlobalInitializer();
    private:
        CurlGlobalInitializer();
        CurlGlobalInitializer(const CurlGlobalInitializer&) = delete;
        CurlGlobalInitializer& operator=(const CurlGlobalInitializer&) = delete;
    };

    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp);
};

} // namespace OHOS::Scan

#endif // CURL_HTTP_CLIENT_H
