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

#ifndef SCAN_CONSTANT_H
#define SCAN_CONSTANT_H

#include <string>

namespace OHOS::Scan {

#define SCAN_RET_NONE
#define SCAN_MAX_COUNT 1000

#define SCAN_ASSERT_BASE(env, assertion, message, retVal)  \
    do {                                                    \
        if (!(assertion)) {                                 \
            SCAN_HILOGE(message);                          \
            return retVal;                                  \
        }                                                   \
    } while (0)

#define SCAN_ASSERT(env, assertion, message) SCAN_ASSERT_BASE(env, assertion, message, nullptr)

#define SCAN_ASSERT_RETURN_VOID(env, assertion, message) SCAN_ASSERT_BASE(env, assertion, message, SCAN_RET_NONE)

#define SCAN_CALL_BASE(env, theCall, retVal)   \
    do {                                        \
        if ((theCall) != napi_ok) {             \
            return retVal;                      \
        }                                       \
    } while (0)

#define SCAN_CALL(env, theCall) SCAN_CALL_BASE(env, theCall, nullptr)

#define SCAN_CALL_RETURN_VOID(env, theCall) SCAN_CALL_BASE(env, theCall, SCAN_RET_NONE)

#define DELETE_AND_NULLIFY(ptr) \
    if ((ptr) != nullptr) { \
        delete (ptr); \
        (ptr) = nullptr; \
    }

#define DELETE_ARRAY_AND_NULLIFY(ptr) \
    if ((ptr) != nullptr) { \
        delete[] (ptr); \
        (ptr) = nullptr; \
    }

#define FREE_AND_NULLPTR(ptr) \
    if ((ptr) != nullptr) { \
        free (ptr); \
        (ptr) = nullptr; \
    }

#define INIT_CALLBACK_PARAMS \
        uv_loop_s *loop = nullptr; \
        bool flag = true; \
        napi_get_uv_event_loop(env_, &loop); \
        CHECK_AND_CREATE(loop, "Failed to get uv event loop", flag); \
        uv_work_t *work = nullptr; \
        CallbackParam *param = nullptr; \
        CallbackContext *context = nullptr; \
        CreateCallbackParam(work, param, context, flag) \

#define CHECK_AND_CREATE(pointer, error_message, flag) \
    if ((pointer) == nullptr) { \
        SCAN_HILOGE(error_message); \
        (flag) = false; \
    }

#define CREATE_PRC_MESSAGE \
    MessageParcel data; \
    MessageParcel reply; \
    MessageOption option; \
    data.WriteInterfaceToken(GetDescriptor()) \

#define CHECK_IS_EXCEED_SCAN_RANGE_BASE(count, retVal)                                             \
    do {                                                                                            \
        if ((count) > SCAN_MAX_COUNT) {                                                      \
            SCAN_HILOGW("input val is exceed scan max range:%{public}d", SCAN_MAX_COUNT);  \
            return retVal;                                                                          \
        }                                                                                           \
    } while (0)

#define CHECK_IS_EXCEED_SCAN_RANGE(count)          CHECK_IS_EXCEED_SCAN_RANGE_BASE(count, nullptr)
#define CHECK_IS_EXCEED_SCAN_RANGE_BOOL(count)     CHECK_IS_EXCEED_SCAN_RANGE_BASE(count, false)
#define CHECK_IS_EXCEED_SCAN_RANGE_VOID(count)     CHECK_IS_EXCEED_SCAN_RANGE_BASE(count, E_SCAN_NONE)
#define CHECK_IS_EXCEED_SCAN_RANGE_INT(count)      CHECK_IS_EXCEED_SCAN_RANGE_BASE(count, E_SCAN_INVALID_PARAMETER)

enum ScanErrorCode {
    // FWK ERROR
    E_SCAN_NONE = 0, // no error
    E_SCAN_NO_PERMISSION = 201, // no permission
    E_SCAN_INVALID_PARAMETER = 401, // invalid parameter
    E_SCAN_GENERIC_FAILURE = 13100001, // generic failure of scan
    E_SCAN_RPC_FAILURE = 13100002, // RPC failure
    E_SCAN_SERVER_FAILURE = 13100003, // failure of scan service

    // DEVICE ERROR
    E_SCAN_GOOD = 13200000,  /* everything A-OK */
    E_SCAN_UNSUPPORTED = 13200001,  /* operation is not supported */
    E_SCAN_CANCELLED = 13200002,  /* operation was cancelled */
    E_SCAN_DEVICE_BUSY = 13200003,  /* device is busy; try again later */
    E_SCAN_INVAL = 13200004,  /* data is invalid (includes no dev at open) */
    E_SCAN_EOF = 13200005,  /* no more data available (end-of-file) */
    E_SCAN_JAMMED = 13200006,  /* document feeder jammed */
    E_SCAN_NO_DOCS = 13200007,  /* document feeder out of documents */
    E_SCAN_COVER_OPEN = 13200008,  /* scanner cover is open */
    E_SCAN_IO_ERROR = 13200009,  /* error during device I/O */
    E_SCAN_NO_MEM = 13200010,  /* out of memory */
    E_SCAN_ACCESS_DENIED = 13200011,  /* access to resource has been denied */
};

const uint32_t SCAN_INVALID_ID = 0xFFFFFFFF;   // -1
const uint16_t USB_VALUE_DESCRIPTOR_INDEX_SERIAL_NUMBER = 0X03;
const uint8_t USB_REQUESTTYPE_DEVICE_TO_HOST = 0X80;
const uint8_t USB_REQUEST_GET_DESCRIPTOR = 0X06;
const uint16_t USB_VALUE_DESCRIPTOR_TYPE_STRING = 0X03;
const int HTTP_COMMON_CONST_VALUE_8 = 8;
const uint16_t USB_INDEX_LANGUAGE_ID_ENGLISH = 0X409;
const int HTTP_COMMON_CONST_VALUE_500 = 500;
const int HTTP_COMMON_CONST_VALUE_100 = 100;
const int HTTP_COMMON_CONST_VALUE_2 = 2;
const int USB_DEVICEID_FIRSTID_LEN_3 = 3;

enum ScanFrame  {
    SCAN_FRAME_GRAY = 0,  /* band covering human visual range */
    SCAN_FRAME_RGB = 1,  /* pixel-interleaved red/green/blue bands */
    SCAN_FRAME_RED = 2,  /* red band only */
    SCAN_FRAME_GREEN = 3,  /* green band only */
    SCAN_FRAME_BLUE = 4,  /* blue band only */
};

enum ScanExtensionState {
    SCAN_EXTENSION_UNLOAD,
    SCAN_EXTENSION_LOADING,
    SCAN_EXTENSION_LOADED,
};

enum ScanParamStatus {
    SCAN_PARAM_NOT_SET,
    SCAN_PARAM_OPT,
    SCAN_PARAM_SET,
};

enum ScanOptionOpType {
    SCAN_ACTION_GET_VALUE = 0,
    SCAN_ACTION_SET_VALUE,
    SCAN_ACTION_SET_AUTO
};

enum ScanOptionValueType {
    SCAN_VALUE_BOOL = 0,
    SCAN_VALUE_NUM,
    SCAN_VALUE_FIXED,
    SCAN_VALUE_STR,
    SCAN_VALUE_BUTTON,
    SCAN_VALUE_GROUP
};

enum ScanConstraintType {
    SCAN_CONSTRAINT_NONE = 0,
    SCAN_CONSTRAINT_RANGE = 1,
    SCAN_CONSTRAINT_WORD_LIST = 2,
    SCAN_CONSTRAINT_STRING_LIST = 3,
};

enum ScannerState {
    SCANNER_READY = 0,
    SCANNER_SCANING = 1,
    SCANNER_SEARCHING = 2,
    SCANNER_CANCELING = 3,
};

enum PhysicalUnit {
    SCANNER_UNIT_NONE = 0, // the value is unit-less (e.g., # of scans)
    SCANNER_UNIT_PIXEL, // value is number of pixels
    SCANNER_UNIT_BIT, // value is number of bits
    SCANNER_UNIT_MM, // value is millimeters
    SCANNER_UNIT_DPI, // value is resolution in dots/inch
    SCANNER_UNIT_PERCENT, // value is a percentage
    SCANNER_UNIT_MICROSECOND // value is micro seconds
};
} // namespace OHOS::Scan
#endif // SCAN_CONSTANT_H
