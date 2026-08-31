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

#include "command_output.h"

#include <iostream>

#include "print_log.h"

namespace OHOS {
namespace Print {
void OutputSuccess(const Json::Value& data, std::string& output)
{
    PRINT_HILOGI("OutputSuccessInfo.");
    Json::Value response;
    response["type"] = "result";
    response["status"] = "success";
    response["data"] = data.isNull() ? Json::Value(Json::objectValue) : data;
    Json::StreamWriterBuilder wBuilder;
    wBuilder["indentation"] = "";
    output = Json::writeString(wBuilder, response);
}

void OutputError(const std::string& code, const std::string& message,
    const std::string& suggestion, std::string& output)
{
    PRINT_HILOGI("OutputErrorInfo.");
    Json::Value response;
    response["type"] = "result";
    response["status"] = "failed";
    response["errCode"] = code;
    response["errMsg"] = message;
    response["suggestion"] = suggestion;
    Json::StreamWriterBuilder wBuilder;
    wBuilder["indentation"] = "";
    output = Json::writeString(wBuilder, response);
}
}  // namespace Print
}  // namespace OHOS
