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

/**
 * @addtogroup OH_Print
 * @{
 *
 * @brief Provides the definition of the C interface for the print vendor extension.
 *
 * @syscap SystemCapability.Print.PrintFramework
 *
 * @since 12
 * @version 1.0
 */

/**
 * @file vendor_extension.h
 *
 * @brief Declares the APIs to discover and manage vendor owned printers.
 *
 * @syscap SystemCapability.Print.PrintFramework
 * @since 12
 * @version 1.0
 */

#ifndef VENDOR_EXTENSION_H
#define VENDOR_EXTENSION_H

#include "ohprint.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    EXTENSION_ERROR_NONE = 0,
    EXTENSION_INVALID_PARAMETER = 401,
    EXTENSION_ERROR_CALLBACK_NULL = 24300100,
    EXTENSION_ERROR_CALLBACK_FAIL,
} Print_ExtensionError;

/**
 * @brief Indicates printer information.
 *
 * @since 12
 */
typedef struct {
    /** Printer id. */
    char *printerId;
    /** Printer name. */
    char *printerName;
    /** Printer description. */
    char *description;
    /** Printer location. */
    char *location;
    /** Printer make and model information. */
    char *makeAndModel;
    /** Printer Uri. */
    char *printerUri;
    /** Printer UUID. */
    char *printerUuid;
    /** Detail information in json format. */
    char *detailInfo;
} Print_DiscoveryItem;

#define PRINTER_PROPERTY_KEY_DEVICE_STATE "printer_device_state" // 非IPP机器需要，无法查打印任务状态
#define PRINTER_PROPERTY_KEY_DEVICE_VENDOR "printer_device_vendor" // json字符串，支持传多个字符串。厂商名称 型号等
#define PRINTER_PROPERTY_KEY_DEVICE_CAPABILITY "printer_device_capability" // json字符串 打印机能力
#define PRINTER_PROPERTY_KEY_DEVICE_DEFAULT_VALUE "printer_device_default_value" // json字符串 打印机默认值
#define PRINTER_PROPERTY_KEY_DEVICE_SUPPLIES "printer_device_supplies" // json字符串 耗材信息，支持多个墨盒
#define PRINTER_PROPERTY_KEY_CUPS_PPD_FILE "printer_cups_ppd_file" // 跟设备相关的PPD全文

typedef struct {
    int32_t (*addPrinterToDiscovery)(const Print_DiscoveryItem *discoveryItem);
    int32_t (*removePrinterFromDiscovery)(const char *printerId);
    int32_t (*addPrinterToCups)(const Print_DiscoveryItem *printer, const Print_PrinterCapability *capability,
        const Print_DefaultValue *defaultValue, const char *ppdData);
    int32_t (*removePrinterFromCups)(const char *printerId);
    int32_t (*onCapabilityQueried)(const Print_DiscoveryItem *printer,
        const Print_PrinterCapability *capability, const Print_DefaultValue *defaultValue);
    int32_t (*onPropertiesQueried)(const char *printerId, const Print_PropertyList *propertyList);
} Print_ServiceAbility;

typedef struct {
    int32_t (*onCreate)(const Print_ServiceAbility *context);
    int32_t (*onDestroy)();
    int32_t (*onStartDiscovery)();
    int32_t (*onStopDiscovery)();
    int32_t (*onConnectPrinter)(const char *printerId);
    int32_t (*onDisconnectPrinter)(const char *printerId);
    int32_t (*onQueryCapability)(const char *printerId);
    int32_t (*onQueryCapabilityByIp)(const char *printerIp, const char *protocol);
    int32_t (*onQueryProperties)(const char *printerId, const Print_StringList *propertyKeyList);
} Print_VendorExtension;

Print_VendorExtension* GetPrintVendorExtension();

#ifdef __cplusplus
}
#endif

#endif // VENDOR_EXTENSION_H
/** @} */