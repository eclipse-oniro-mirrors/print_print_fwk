/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef VENDOR_HELPER_H
#define VENDOR_HELPER_H

#include <string>
#include "printer_info.h"
#include "vendor_extension.h"

namespace OHOS {
namespace Print {
char *CopyString(const std::string &source);
bool ConvertStringToLong(const char *src, long &dst);
bool ConvertColorMode(const Print_ColorMode &code, uint32_t &dst);
bool ConvertDuplexMode(const Print_DuplexMode &code, uint32_t &dst);
bool ConvertQuality(const Print_Quality &code, uint32_t &dst);
bool ConvertStringToPrinterState(const std::string &stateData, Print_PrinterState &state);
void LogDiscoveryItem(const Print_DiscoveryItem *discoveryItem);
void LogPageCapability(const Print_PrinterCapability *capability);
void LogOtherCapability(const Print_PrinterCapability *capability);
void LogDefaultValue(const Print_DefaultValue *defaultValue);
void LogProperties(const Print_PropertyList *propertyList);
bool UpdateResolutionDefaultValue(PrinterCapability &printerCap, const Print_DefaultValue *defaultValue);
bool UpdateCopiesCapability(PrinterCapability &printerCap, const Print_PrinterCapability *capability,
                            const Print_DefaultValue *defaultValue);
bool UpdateOrientationCapability(PrinterCapability &printerCap, const Print_PrinterCapability *capability,
                                 const Print_DefaultValue *defaultValue);
bool UpdateMediaCapability(PrinterCapability &printerCap, const Print_PrinterCapability *capability,
                           const Print_DefaultValue *defaultValue);
bool UpdateMarginCapability(PrinterCapability &printerCap, const Print_DefaultValue *defaultValue);
std::shared_ptr<std::string> FindPropertyFromPropertyList(const Print_PropertyList *propertyList,
                                                          const std::string &keyName);
bool UpdatePrinterDetailInfoToJson(Json::Value &option, const std::string &detailInfo);
std::string getScheme(std::string &printerUri);
bool UpdatePrinterInfoWithDiscovery(PrinterInfo &info, const Print_DiscoveryItem *discoveryItem);
bool UpdatePrinterInfoWithCapability(PrinterInfo &info, const Print_DiscoveryItem *discoveryItem,
                                     const Print_PrinterCapability *capability, const Print_DefaultValue *defaultValue);
std::shared_ptr<PrinterInfo> ConvertVendorCapabilityToPrinterInfo(const Print_DiscoveryItem *printer,
                                                                  const Print_PrinterCapability *capability,
                                                                  const Print_DefaultValue *defaultValue);
bool ConvertStringVectorToStringList(const std::vector<std::string> &stringVector, Print_StringList &stringList);
void ReleaseStringList(Print_StringList &stringList);
}  // namespace Print
}  // namespace OHOS
#endif  // VENDOR_HELPER_H
