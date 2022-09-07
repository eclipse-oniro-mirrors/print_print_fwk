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
#ifndef PRINTER_CAPABILITY_H
#define PRINTER_CAPABILITY_H

#include <mutex>
#include <string>
#include <vector>

#include "iremote_broker.h"
#include "iremote_proxy.h"
#include "napi/native_api.h"
#include "print_margin.h"
#include "print_page_size.h"
#include "print_resolution.h"

namespace OHOS::Print {
class PrinterCapability {
public:
  explicit PrinterCapability();
  PrinterCapability(const PrinterCapability &right);
  PrinterCapability &operator=(const PrinterCapability &right);
  ~PrinterCapability();

  void SetMinMargin(const PrintMargin &minMargin);

  void SetPageSize(const std::vector<PrintPageSize> &pageSizeList);

  void SetResolution(const std::vector<PrintResolution> &resolutionList);

  void SetColorMode(uint32_t colorMode);

  void SetDuplexMode(uint32_t duplexMode);

  void GetMinMargin(PrintMargin &margin) const;

  void GetPageSize(std::vector<PrintPageSize> &pageSizeList) const;

  void GetResolution(std::vector<PrintResolution> &resolutionList) const;

  [[nodiscard]] uint32_t GetColorMode() const;

  [[nodiscard]] uint32_t GetDuplexMode() const;

  void ConvertToParcel(MessageParcel &reply) const;

  void BuildFromParcel(MessageParcel &data);

  void ConvertToJs(napi_env env, napi_value *result) const;

  void BuildFromJs(napi_env env, napi_value capValue);

  void Dump();

private:
  bool ParseResolution(napi_env env, napi_value reValue,
                       PrintResolution &resolution);

  bool ParseResolutionParam(napi_env env, napi_value reValue,
                            PrintResolution &resolution);

  bool ParsePageSize(napi_env env, napi_value capValue,
                     PrintPageSize &pageSize);

  bool ParseMargin(napi_env env, napi_value marginValue, PrintMargin &margin);

  bool ParseMarginParam(napi_env env, napi_value marginValue,
                        PrintMargin &margin);

  bool ParseCapabilityParam(napi_env env, napi_value capValue);

  bool ParseCapability(napi_env env, napi_value capValue);

  bool ParsePageSizeParam(napi_env env, napi_value capValue,
                          PrintPageSize &pageSize);

private:
  PrintMargin minMargin_;
  std::vector<PrintPageSize> pageSizeList_;
  std::vector<PrintResolution> resolutionList_;
  uint32_t colorMode_;
  uint32_t duplexMode_;
};
} // namespace OHOS::Print
#endif // PRINTER_CAPABILITY_H