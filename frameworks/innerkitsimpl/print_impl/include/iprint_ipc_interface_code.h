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

#ifndef PRINT_IPC_INTERFACE_CODE_H
#define PRINT_IPC_INTERFACE_CODE_H

 /* SAID: 3707 */
namespace OHOS::Print {
    enum IPrintInterfaceCode {
        CMD_START_PRINT,
        CMD_STOP_PRINT,
        CMD_CONNECTPRINTER,
        CMD_DISCONNECTPRINTER,
        CMD_STARTDISCOVERPRINTER,
        CMD_STOPDISCOVERPRINTER,
        CMD_QUERYALLEXTENSION,
        CMD_STARTPRINTJOB,
        CMD_CANCELPRINTJOB,
        CMD_ADDPRINTERS,
        CMD_REMOVEPRINTERS,
        CMD_UPDATEPRINTERS,
        CMD_UPDATEPRINTERSTATE,
        CMD_UPDATEPRINTJOBSTATE,
        CMD_UPDATEEXTENSIONINFO,
        CMD_REQUESTPREVIEW,
        CMD_QUERYPRINTERCAPABILITY,
        CMD_ON,
        CMD_OFF,
        CMD_REG_EXT_CB,
        CMD_UNREG_EXT_CB,
        CMD_LOAD_EXT,
        CMD_QUERYALLPRINTJOB,
        CMD_QUERYPRINTJOBBYID,
        CMD_ADDPRINTERTOCUPS,
        CMD_QUERYPRINTERCAPABILITYBYURI,
        CMD_STARTPRINTJOB_BY_ADAPTER,
        CMD_START_GET_FILE,
        CMD_NOTIFY_PRINT_SERVICE,
    };
} // namespace OHOS:Print
#endif // PRINT_SERVICE_INTERFACE_H
