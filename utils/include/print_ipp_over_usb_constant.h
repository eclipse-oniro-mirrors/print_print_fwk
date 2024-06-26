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
 
#ifndef IPP_USB_HTTP_CONST_VALUE_H
#define IPP_USB_HTTP_CONST_VALUE_H

namespace OHOS::Print {
const std::string LOCAL_HOST = "127.0.0.1";
const std::string HTTP_CONTENT_LENGTH = "Content-Length";
const std::string HTTP_TRANSFER_ENCODING = "Transfer-Encoding";
const std::string HTTP_EXPECT = "Expect";
const std::string HTTP_CHUNKED = "chunked";
const std::string HTTP_POST = "POST /ipp/print HTTP/1.1\r\n";
const std::string HTTP_MSG_STRING_R_AND_N = "\r\n";
const std::string HTTP_MSG_STRING_CHUNK_END = "0\r\n\r\n";
const std::string HTTP_OPERATION_GET_ATTR = "GetAttr";
const std::string HTTP_OPERATION_SEND_DOC = "SendDoc";
const std::string HTTP_OPERATION_COMMON = "Common";
const std::string PRINTER_ID_PREFIX = "USB-";
const std::string HTTP_100_CONTINUE = "HTTP/1.1 100";

const int HTTP_REQUEST_GET_ATTR = 11;
const int HTTP_REQUEST_SEND_DOC = 6;

const int HTTP_RESPONSE_STATUS_100 = 100;
const int HTTP_RESPONSE_STATUS_101 = 101;
const int HTTP_RESPONSE_STATUS_102 = 102;
const int HTTP_RESPONSE_STATUS_103 = 103;
const int HTTP_RESPONSE_STATUS_200 = 200;
const int HTTP_RESPONSE_STATUS_201 = 201;
const int HTTP_RESPONSE_STATUS_202 = 202;
const int HTTP_RESPONSE_STATUS_203 = 203;
const int HTTP_RESPONSE_STATUS_204 = 204;
const int HTTP_RESPONSE_STATUS_205 = 205;
const int HTTP_RESPONSE_STATUS_206 = 206;
const int HTTP_RESPONSE_STATUS_207 = 207;
const int HTTP_RESPONSE_STATUS_208 = 208;
const int HTTP_RESPONSE_STATUS_226 = 226;
const int HTTP_RESPONSE_STATUS_300 = 300;
const int HTTP_RESPONSE_STATUS_301 = 301;
const int HTTP_RESPONSE_STATUS_302 = 302;
const int HTTP_RESPONSE_STATUS_303 = 303;
const int HTTP_RESPONSE_STATUS_304 = 304;
const int HTTP_RESPONSE_STATUS_305 = 305;
const int HTTP_RESPONSE_STATUS_306 = 306;
const int HTTP_RESPONSE_STATUS_307 = 307;
const int HTTP_RESPONSE_STATUS_308 = 308;
const int HTTP_RESPONSE_STATUS_400 = 400;
const int HTTP_RESPONSE_STATUS_401 = 401;
const int HTTP_RESPONSE_STATUS_402 = 402;
const int HTTP_RESPONSE_STATUS_403 = 403;
const int HTTP_RESPONSE_STATUS_404 = 404;
const int HTTP_RESPONSE_STATUS_405 = 405;
const int HTTP_RESPONSE_STATUS_406 = 406;
const int HTTP_RESPONSE_STATUS_407 = 407;
const int HTTP_RESPONSE_STATUS_408 = 408;
const int HTTP_RESPONSE_STATUS_409 = 409;
const int HTTP_RESPONSE_STATUS_410 = 410;
const int HTTP_RESPONSE_STATUS_411 = 411;
const int HTTP_RESPONSE_STATUS_412 = 412;
const int HTTP_RESPONSE_STATUS_413 = 413;
const int HTTP_RESPONSE_STATUS_414 = 414;
const int HTTP_RESPONSE_STATUS_415 = 415;
const int HTTP_RESPONSE_STATUS_416 = 416;
const int HTTP_RESPONSE_STATUS_417 = 417;
const int HTTP_RESPONSE_STATUS_418 = 418;
const int HTTP_RESPONSE_STATUS_421 = 421;
const int HTTP_RESPONSE_STATUS_422 = 422;
const int HTTP_RESPONSE_STATUS_423 = 423;
const int HTTP_RESPONSE_STATUS_424 = 424;
const int HTTP_RESPONSE_STATUS_425 = 425;
const int HTTP_RESPONSE_STATUS_426 = 426;
const int HTTP_RESPONSE_STATUS_428 = 428;
const int HTTP_RESPONSE_STATUS_429 = 429;
const int HTTP_RESPONSE_STATUS_431 = 431;
const int HTTP_RESPONSE_STATUS_451 = 451;
const int HTTP_RESPONSE_STATUS_501 = 501;
const int HTTP_RESPONSE_STATUS_502 = 502;
const int HTTP_RESPONSE_STATUS_503 = 503;
const int HTTP_RESPONSE_STATUS_504 = 504;
const int HTTP_RESPONSE_STATUS_505 = 505;
const int HTTP_RESPONSE_STATUS_506 = 506;
const int HTTP_RESPONSE_STATUS_507 = 507;
const int HTTP_RESPONSE_STATUS_508 = 508;
const int HTTP_RESPONSE_STATUS_510 = 510;
const int HTTP_RESPONSE_STATUS_511 = 511;
const int HTTP_RESPONSE_STATUS_500 = 500;

const int HTTP_COMMON_CONST_VALUE_0 = 0;
const int HTTP_COMMON_CONST_VALUE_1 = 1;
const int HTTP_COMMON_CONST_VALUE_2 = 2;
const int HTTP_COMMON_CONST_VALUE_3 = 3;
const int HTTP_COMMON_CONST_VALUE_4 = 4;
const int HTTP_COMMON_CONST_VALUE_5 = 5;
const int HTTP_COMMON_CONST_VALUE_6 = 6;
const int HTTP_COMMON_CONST_VALUE_8 = 8;
const int HTTP_COMMON_CONST_VALUE_9 = 9;
const int HTTP_COMMON_CONST_VALUE_10 = 10;
const int HTTP_COMMON_CONST_VALUE_11 = 11;
const int HTTP_COMMON_CONST_VALUE_12 = 12;
const int HTTP_COMMON_CONST_VALUE_14 = 14;
const int HTTP_COMMON_CONST_VALUE_15 = 15;
const int HTTP_COMMON_CONST_VALUE_16 = 16;
const int HTTP_COMMON_CONST_VALUE_18 = 18;
const int HTTP_COMMON_CONST_VALUE_25 = 25;
const int HTTP_COMMON_CONST_VALUE_31 = 31;
const int HTTP_COMMON_CONST_VALUE_33 = 33;
const int HTTP_COMMON_CONST_VALUE_47 = 47;
const int HTTP_COMMON_CONST_VALUE_50 = 50;
const int HTTP_COMMON_CONST_VALUE_100 = 100;
const int HTTP_COMMON_CONST_VALUE_300 = 300;
const int HTTP_COMMON_CONST_VALUE_500 = 500;
const int HTTP_COMMON_CONST_VALUE_1000 = 1000;

const int INDEX_0 = 0;
const int INDEX_1 = 1;
const int INDEX_2 = 2;
const int INDEX_3 = 3;
const int INDEX_4 = 4;
const int INDEX_5 = 5;
const int INDEX_6 = 6;
const int INDEX_7 = 7;
const int INDEX_8 = 8;
const int INDEX_9 = 9;
const int INDEX_10 = 10;
const int INDEX_11 = 11;

const size_t HTTP_SERVER_MAX_LENGTH = 1024 * 1024 * 512;
const int HTTP_MIN_PORT = 60000;
const int HTTP_MAX_PORT = 65535;
const int HTTP_SERVER_LISTEN_PORT = 60000;
const size_t USB_DATA_MAX_LENGTH = 1024 * 16;
const size_t USB_ENDPOINT_MAX_LENGTH = 512;
const int USB_INTERFACE_MIN_COUNT = 2;
const int INVAILD_VALUE = -1;
const int RESPONSE_RETRY_MAX_TIMES = 300;
const int READ_RETRY_MAX_TIMES = 200;
const int RESPONSE_RETRY_INTERVAL = 100;
const int USB_BULKTRANSFER_WRITE_TIMEOUT = 500;
const int USB_BULKTRANSFER_WRITE_SLEEP = 1000;
const int WRITE_RETRY_MAX_TIMES = 20;
const int USB_BULKTRANSFER_READ_TIMEOUT = 500;
const int USB_READ_INTERVAL = 50;
const int USB_WRITE_INTERVAL = 50;
const int CPP_HTTP_OK = 1;
const int CPP_HTTP_FAIL = 0;
const int REQID_OPERAID_LEN = 8;

const char HTTP_MSG_CHAR_1 = '1';
const char HTTP_MSG_CHAR_2E = '.';
const char HTTP_MSG_CHAR_A = 'A';
const char HTTP_MSG_CHAR_0 = '0';
const char HTTP_MSG_CHAR_A_S = 'a';
const char HTTP_MSG_CHAR_F_S = 'f';
const char HTTP_MSG_CHAR_F = 'F';
const char HTTP_MSG_CHAR_R0 = '\0';
const char HTTP_MSG_CHAR_20 = ' ';
const char HTTP_MSG_CHAR_2B = '+';
const char HTTP_MSG_CHAR_0D = '\r';
const char HTTP_MSG_CHAR_0A = '\n';
const char HTTP_MSG_CHAR_27 = '\'';
const char HTTP_MSG_CHAR_2C = ',';
const char HTTP_MSG_CHAR_3B = ';';
const char HTTP_MSG_CHAR_BAI_FEN = '%';
const char SPLIT_VALUE_COLON = ':';

const uint8_t HTTP_SPLIT_R_CODE = 13;                // '\r'
const uint8_t HTTP_SPLIT_N_CODE = 10;                // '\n'
const uint8_t CODE_SPLIT_VALUE_COLON = 58;             // ':' 冒号分隔符
const uint8_t IPP_END_SPLIT_VALUE = 3;               // ipp协议分割符号
const uint8_t HTTP_RESPONSE_H = 72;                  // 'H'
const uint8_t HTTP_RESPONSE_T = 84;                  // 'T'
const uint8_t HTTP_RESPONSE_P = 80;                  // 'P'
const uint8_t HTTP_RESPONSE_VERSION_SPLIT_GANG = 47; // '/'
const int32_t USB_DEVICE_CLASS_PRINT = 7;     // class is 7 the device is printer
const int32_t USB_DEVICE_SUBCLASS_PRINT = 1;  // subclass is 1 the device is printer
const int32_t USB_DEVICE_PROTOCOL_PRINT = 4;  // can support ipp usb
const int32_t USB_DEVICE_INTERFACE_COUNT = 2; // can support ipp usb
const int32_t EORROR_HDF_DEV_ERR_TIME_OUT = -7;
const int32_t EORROR_HDF_DEV_ERR_NO_DEVICE = -202;
const uint8_t USB_REQUESTTYPE_HOST_TO_DEVICE = 0X00;
const uint8_t USB_REQUESTTYPE_DEVICE_TO_HOST = 0X80;
const uint8_t USB_REQUEST_SET_CONFIGURATION = 0X09;
const uint8_t USB_REQUEST_GET_DESCRIPTOR = 0X06;
const uint16_t USB_VALUE_DESCRIPTOR_TYPE_STRING = 0X03;
const uint16_t USB_VALUE_DESCRIPTOR_INDEX_PRODUCT_NAME = 0X02;
const uint16_t USB_VALUE_DESCRIPTOR_INDEX_SERIAL_NUMBER = 0X03;
const uint16_t USB_INDEX_0 = 0X00;
const uint16_t USB_INDEX_LANGUAGE_ID_ENGLISH = 0X409;
}
#endif