/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef PRINT_JSON_UTIL_H
#define PRINT_JSON_UTIL_H

 #include <string>
 #include <memory>
 #include <json/json.h>
 #include <print_log.h>

namespace OHOS::Print {

class PrintJsonUtil {
public:
    static bool IsMember(const Json::Value &jsonObject, const std::string &key);
    static bool Parse(const std::string &root, Json::Value &jsonObject);
    static bool ParseFromStream(Json::IStream &ifs, Json::Value &jsonObject);
    static std::string WriteString(const Json::Value &jsonObject);
    static std::string WriteStringUTF8(const Json::Value &jsonObject);
};

/*
 Json::Value 非object对象直接调用isMember会程序崩溃
 */
inline bool PrintJsonUtil::IsMember(const Json::Value &jsonObject, const std::string &key)
{
    if (jsonObject.isObject() || jsonObject.isNull()) {
        return jsonObject.isMember(key);
    }
    return false;
}

/*
简单string对象，不包含数组，或者对象格式，使用此方法转换
*/
inline bool PrintJsonUtil::Parse(const std::string &root, Json::Value &jsonObject)
{
    static const Json::CharReaderBuilder rBuilder;
    static const std::unique_ptr<Json::CharReader> reader(rBuilder.newCharReader());
    JSONCPP_STRING err;
    if (!reader->parse(root.c_str(), root.c_str() + root.length(), &jsonObject, &err)) {
        PRINT_HILOGE("PrintJsonUtil string parse error!");
        return false;
    }
    return true;
}

/*
复杂string对象，包含[]或{}，使用此方法转换
*/
inline bool PrintJsonUtil::ParseFromStream(Json::IStream &ifs, Json::Value &jsonObject)
{
    Json::OStringStream ssin;
    ssin << ifs.rdbuf();
    Json::String doc = ssin.str();
    static const Json::CharReaderBuilder rBuilder;
    static const std::unique_ptr<Json::CharReader> reader(rBuilder.newCharReader());
    JSONCPP_STRING err;
    if (!reader->parse(doc.data(), doc.data() + doc.size(), &jsonObject, &err)) {
        PRINT_HILOGE("PrintJsonUtil stream parse error!");
        return false;
    }
    return true;
}

inline std::string PrintJsonUtil::WriteString(const Json::Value &jsonObject)
{
    static Json::StreamWriterBuilder wBuilder;
    wBuilder["indentation"] = "";
    return Json::writeString(wBuilder, jsonObject);
}

inline std::string PrintJsonUtil::WriteStringUTF8(const Json::Value &jsonObject)
{
    static Json::StreamWriterBuilder wBuilder;
    wBuilder["indentation"] = "";
    wBuilder["emitUTF8"] = true;
    return Json::writeString(wBuilder, jsonObject);
}
}

#endif // HARMONYOSDEV_PRINT_JSON_HELPER_H