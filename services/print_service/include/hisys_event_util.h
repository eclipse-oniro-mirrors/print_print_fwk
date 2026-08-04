/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef HISYS_EVENT_UTIL_H
#define HISYS_EVENT_UTIL_H

#include <string>
#include <cstdint>
#include "print_job.h"

namespace OHOS::Print {

    enum class HisysEventType {
        PRINT_FAILURE,
        CONNECT_FAILURE,
        PRINT_PROCESS_FAULT
    };

    struct HisysEventParams {
        HisysEventType eventType;
        std::string resourceKey;
        uint32_t subState = 0;
        std::string printerModel;
    };

    class HisysEventUtil {
    public:
        static void reportBehaviorEvent(std::string name, int behaviorCode, const std::string &msg);
        static void ReportFailureEvent(const HisysEventParams &params);
        static void ReportIppRawData(const std::string &msg);
        static void ReportConnectFault(const std::string &scene, const std::string &msg);
        static void ReportPrintFailure(const std::string &resourceKey, uint32_t subState = 0);
        static void ReportConnectFailure(const std::string &resourceKey, const std::string &printerModel = "");
        static void ReportPrintProcessFault(const std::string &resourceKey, uint32_t subState = 0);
        static const int SEND_TASK = 1007;
    private:
        static constexpr char HW_PRINT_SPOOLER[] = "PRINT_UE";
        static constexpr char BEHAVIOR_DESCRIPTION[] = "ACTION_TIME";
        static constexpr char DEVICE_TYPE_VALUE[] = "PRINTER";
        static constexpr char INACTIVE[] = "0";
        static constexpr char CONNECT_EXCEPTION_FAULT_EVENT[] = "CONNECT_EXCEPTION";
        static constexpr char PRINT_DOMAIN[] = "PRINT";
        static constexpr char PRINT_EXCEPTION_FAULT_EVENT[] = "PRINT_EXCEPTION";
        static constexpr char FAULT_CONNECT_PRINT_EVENT[] = "FAULT_CONNECT_PRINT";
        static constexpr char PACKAGE_NAME[] = "PACKAGE_NAME";
        static constexpr char PROCESS_NAME[] = "PROCESS_NAME";
        static constexpr char BEHAVIOR_CODE[] = "BEHAVIOR_CODE";
        static constexpr char DEVICE_TYPE[] = "DEVICE_TYPE";
        static constexpr char ACTION[] = "ACTION";
        static constexpr char START_TIME[] = "START_TIME";
        static constexpr char END_TIME[] = "END_TIME";
        static constexpr char MSG[] = "MSG";
        static constexpr char PVERSIONID[] = "PVERSIONID";
        static constexpr char FAULT_CODE[] = "FAULT_CODE";
        static constexpr char SCENE[] = "SCENE";
    public:
        static constexpr char SCENE_BSUNI_CONNECT[] = "bsuni_connect";
        static constexpr char SCENE_IPP_RAW_DATA[] = "ipp_raw_data";
        static constexpr char BSUNI_CAPABILITY_INFO_NULL[] = "bsuni_capability_info_null";
        static constexpr char BSUNI_CAPABILITY_MANAGER_NULL[] = "bsuni_capability_manager_null";
        static constexpr char BSUNI_CAPABILITY_PROTOCOL_MISMATCH[] = "bsuni_capability_protocol_mismatch";
        static constexpr char BSUNI_CAPABILITY_NO_URI[] = "bsuni_capability_no_uri";
        static constexpr char BSUNI_CAPABILITY_IP_MISMATCH[] = "bsuni_capability_ip_mismatch";
        static constexpr char BSUNI_CAPABILITY_UNSUPPORTED_PROTOCOL[] = "bsuni_capability_unsupported_protocol";
        static constexpr char ADD_CUPS_SERVICE_NULL[] = "add_cups_service_null";
        static constexpr char ADD_CUPS_FAIL[] = "add_cups_fail";
        static constexpr char PPD_CALLBACK_NOT_CONNECTING[] = "ppd_callback_not_connecting";
        static constexpr char BSUNI_DRIVER_SUPPORT_CONNECT_FAIL[] = "bsuni_driver_support_connect_fail";
        static constexpr char NO_VENDOR_SUPPORT[] = "no_vendor_support";
        static constexpr char BUILD_JOB_PARAMS_FAILED[] = "build_job_params_failed";
        static constexpr char MONITOR_HTTP_CREATE_FAILED[] = "monitor_http_create_failed";
        static constexpr char USB_PRINTER_DISCONNECTED[] = "usb_printer_disconnected";
        static constexpr char CHECK_PRINT_JOB_FAILED[] = "check_print_job_failed";
        static constexpr char RESTART_CACHE_MISSING[] = "restart_cache_missing";
    };
}   // namespace OHOS::Print
#endif // HISYS_EVENT_UTIL_H