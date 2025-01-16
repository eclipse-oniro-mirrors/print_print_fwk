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

#ifndef SANE_INFO_H
#define SANE_INFO_H

namespace OHOS::Scan {
constexpr int32_t INVALID_DATA = -1;
constexpr int32_t MAX_BUFLEN = 1024 * 1024 * 1024; // 1G
enum SaneStatus {
    SANE_STATUS_GOOD = 0, // everything A-OK
    SANE_STATUS_UNSUPPORTED, // operation is not supported
    SANE_STATUS_CANCELLED, // operation was cancelled
    SANE_STATUS_DEVICE_BUSY, // device is busy; try again later
    SANE_STATUS_INVAL, // data is invalid (includes no dev at open)
    SANE_STATUS_EOF, // no more data available (end-of-file)
    SANE_STATUS_JAMMED, // document feeder jammed
    SANE_STATUS_NO_DOCS, // document feeder out of documents
    SANE_STATUS_COVER_OPEN, // scanner cover is open
    SANE_STATUS_IO_ERROR, // error during device I/O
    SANE_STATUS_NO_MEM, // out of memory
    SANE_STATUS_ACCESS_DENIED, // access to resource has been denied
    SANE_STATUS_NO_PERMISSION = 201, // no permission
    SANE_STATUS_INVALID_PARAMETER = 401, // invalid parameter
    SANE_STATUS_GENERIC_FAILURE = 13100001, // generic failure of sane service
    SANE_STATUS_RPC_FAILURE = 13100002, // RPC failure
    SANE_STATUS_SERVER_FAILURE = 13100003, // failure of sane service
};

enum SaneAction {
    SANE_ACTION_GET_VALUE = 0,
    SANE_ACTION_SET_VALUE,
    SANE_ACTION_SET_AUTO
};

enum SaneConstraintType {
    SANE_CONSTRAINT_NONE = 0,
    SANE_CONSTRAINT_RANGE,
    SANE_CONSTRAINT_WORD_LIST,
    SANE_CONSTRAINT_STRING_LIST,
};

enum SaneFrame {
    SANE_FRAME_GRAY = 0, // band covering human visual range
    SANE_FRAME_RGB, // pixel-interleaved red/green/blue bands
    SANE_FRAME_RED, // red band only
    SANE_FRAME_GREEN, // green band only
    SANE_FRAME_BLUE // blue band only
};
} // namespace OHOS::SCAN
#endif // SANE_INFO_H