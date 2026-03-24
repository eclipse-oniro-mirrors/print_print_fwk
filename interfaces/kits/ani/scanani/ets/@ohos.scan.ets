/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import {BusinessError, Callback, AsyncCallback} from '@ohos.base';

export class CallbackWrapper<T> {
  private myFun_: Callback<T> = (data: T) => {};

  constructor(myFun: Callback<T>) {
    this.myFun_ = myFun;
  }

  invoke(data: T): void {
    this.myFun_(data);
  }
}

export class AsyncCallbackWrapper<T, E = void> {
  private myFun_:AsyncCallback<T, E> = (err: BusinessError<E> | null, data: T | undefined) => {}

  constructor(myFun:AsyncCallback<T, E>){
    this.myFun_ = myFun;
  }

  invoke(err: BusinessError<E> | null, data: T | undefined) : void {
    this.myFun_(err, data);
  }
}

export class AsyncCallbackArrayWrapper<T> {
  myFun_: AsyncCallback<Array<T>, void> = (err: BusinessError<void> | null, data: Array<T> | undefined) => {};

  constructor(myFun: AsyncCallback<Array<T>, void>) {
    this.myFun_ = myFun;
  }

  invoke(err: BusinessError<void> | null, data: Array<T> | undefined): void {
    this.myFun_(err, data);
  }
}

export default namespace scan {
    loadLibrary("scan_ani");

    export enum ScanErrorCode {
        SCAN_ERROR_NO_PERMISSION = 201,
        SCAN_ERROR_NOT_SYSTEM_APPLICATION = 202,
        SCAN_ERROR_INVALID_PARAMETER = 401,
        SCAN_ERROR_GENERIC_FAILURE = 13100001,
        SCAN_ERROR_RPC_FAILURE = 13100002,
        SCAN_ERROR_SERVER_FAILURE = 13100003,
        SCAN_ERROR_UNSUPPORTED = 13100004,
        SCAN_ERROR_CANCELED = 13100005,
        SCAN_ERROR_DEVICE_BUSY = 13100006,
        SCAN_ERROR_INVALID = 13100007,
        SCAN_ERROR_JAMMED = 13100008,
        SCAN_ERROR_NO_DOCS = 13100009,
        SCAN_ERROR_COVER_OPEN = 13100010,
        SCAN_ERROR_IO_ERROR = 13100011,
        SCAN_ERROR_NO_MEMORY = 13100012,
    }

    export enum ConstraintType {
        SCAN_CONSTRAINT_NONE = 0,
        SCAN_CONSTRAINT_RANGE = 1,
        SCAN_CONSTRAINT_WORD_LIST = 2,
        SCAN_CONSTRAINT_STRING_LIST = 3,
    }

    export enum PhysicalUnit {
        SCAN_UNIT_NONE = 0,
        SCAN_UNIT_PIXEL = 1,
        SCAN_UNIT_BIT = 2,
        SCAN_UNIT_MM = 3,
        SCAN_UNIT_DPI = 4,
        SCAN_UNIT_PERCENT = 5,
        SCAN_UNIT_MICROSECOND = 6,
    }

    export enum OptionValueType {
        SCAN_TYPE_BOOL = 0,
        SCAN_TYPE_INT = 1,
        SCAN_TYPE_FIXED = 2,
        SCAN_TYPE_STRING = 3,
    }

    export enum ScannerSyncMode {
        UPDATE_STR = 'update',
        DELETE_STR = 'delete',
    }

    export enum ScannerDiscoveryMode {
        TCP_STR = 'TCP',
        USB_STR = 'USB',
    }

    export interface Range {
        minValue: int;
        maxValue: int;
        quantValue: int;
    }

    export interface ScannerParameter {
        optionName: string;
        optionIndex: int;
        optionTitle: string;
        optionDesc: string;
        optionType: OptionValueType;
        optionUnit: PhysicalUnit;
        optionConstraintType: ConstraintType;
        optionConstraintString?: string[];
        optionConstraintInt?: int[];
        optionConstraintRange?: Range;
    }

    export interface ScannerOptionValue {
        valueType: OptionValueType;
        numValue?: int;
        strValue?: string;
        boolValue?: boolean;
    }

    export interface PictureScanProgress {
        progress: int;
        pictureFd: int;
        isFinal: boolean;
    }

    export interface ScannerDevice {
        scannerId: string;
        discoveryMode: ScannerDiscoveryMode;
        uniqueId: string;
        manufacturer: string;
        model: string;
        deviceName: string;
    }

    export interface ScannerSyncDevice {
        scannerId: string;
        discoveryMode: ScannerDiscoveryMode;
        uniqueId: string;
        syncMode: ScannerSyncMode;
        oldScannerId?: string;
    }

    export function init(): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                initNative(myCall);
            });
        });
    }

    export function exit(): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                exitNative(myCall);
            });
        });
    }

    export function startScannerDiscovery(): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                startScannerDiscoveryNative(myCall);
            });
        });
    }

    export function openScanner(scannerId: string): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                openScannerNative(scannerId, myCall);
            });
        });
    }

    export function closeScanner(scannerId: string): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                closeScannerNative(scannerId, myCall);
            });
        });
    }

    export function getScannerParameter(scannerId: string): Promise<ScannerParameter[]> {
        return new Promise<ScannerParameter[]>((resolve: (data: ScannerParameter[])=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackArrayWrapper<ScannerParameter>((err: BusinessError<void> | null, data: Array<ScannerParameter> | undefined) => {
                if ((err === null || err.code == 0) && data !== undefined) {
                    resolve(data);
                } else {
                    reject(err as BusinessError);
                }
            });
            taskpool.execute((): void => {
                getScannerParameterNative(scannerId, myCall);
            });
        });
    }

    export function setScannerParameter(scannerId: string, optionIndex: int, value: ScannerOptionValue): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                setScannerParameterNative(scannerId, optionIndex, value, myCall);
            });
        });
    }

    export function setScanAutoOption(scannerId: string, optionIndex: int): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                setScanAutoOptionNative(scannerId, optionIndex, myCall);
            });
        });
    }

    export function getScannerCurrentSetting(scannerId: string, optionIndex: int): Promise<ScannerOptionValue> {
        return new Promise<ScannerOptionValue>((resolve: (data: ScannerOptionValue)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<ScannerOptionValue>((err: BusinessError<void> | null, data: ScannerOptionValue | undefined) => {
                if ((err === null || err.code == 0) && data !== undefined) {
                    resolve(data);
                } else {
                    reject(err as BusinessError);
                }
            });
            taskpool.execute((): void => {
                getScannerCurrentSettingNative(scannerId, optionIndex, myCall);
            });
        });
    }

    export function startScan(scannerId: string, batchMode: boolean): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                startScanNative(scannerId, batchMode, myCall);
            });
        });
    }

    export function cancelScan(scannerId: string): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                cancelScanNative(scannerId, myCall);
            });
        });
    }

    export function getPictureScanProgress(scannerId: string): Promise<PictureScanProgress> {
        return new Promise<PictureScanProgress>((resolve: (data: PictureScanProgress)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<PictureScanProgress>((err: BusinessError<void> | null, data: PictureScanProgress | undefined) => {
                if ((err === null || err.code == 0) && data !== undefined) {
                    resolve(data);
                } else {
                    reject(err as BusinessError);
                }
            });
            taskpool.execute((): void => {
                getPictureScanProgressNative(scannerId, myCall);
            });
        });
    }

    export function addScanner(uniqueId: string, discoveryMode: ScannerDiscoveryMode): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                addScannerNative(uniqueId, discoveryMode, myCall);
            });
        });
    }

    export function deleteScanner(uniqueId: string, discoveryMode: ScannerDiscoveryMode): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                deleteScannerNative(uniqueId, discoveryMode, myCall);
            });
        });
    }

    export function getAddedScanners(): Promise<ScannerDevice[]> {
        return new Promise<ScannerDevice[]>((resolve: (data: ScannerDevice[])=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackArrayWrapper<ScannerDevice>((err: BusinessError<void> | null, data: Array<ScannerDevice> | undefined) => {
                if ((err === null || err.code == 0) && data !== undefined) {
                    resolve(data);
                } else {
                    reject(err as BusinessError);
                }
            });
            taskpool.execute((): void => {
                getAddedScannersNative(myCall);
            });
        });
    }

    export function onScanDeviceFound(callback: Callback<ScannerDevice>): void {
        let myCall = new CallbackWrapper<ScannerDevice>(callback);
        taskpool.execute((): void => {
            onScanDeviceFoundNative(myCall);
        });
    }

    export function offScanDeviceFound(callback?: Callback<ScannerDevice>): void {
        taskpool.execute((): void => {
            offScanDeviceFoundNative("scanDeviceFound");
        });
    }

    export function onScanDeviceSync(callback: Callback<ScannerSyncDevice>): void {
        let myCall = new CallbackWrapper<ScannerSyncDevice>(callback);
        taskpool.execute((): void => {
            onScanDeviceSyncNative(myCall);
        });
    }

    export function offScanDeviceSync(callback?: Callback<ScannerSyncDevice>): void {
        taskpool.execute((): void => {
            offScanDeviceSyncNative("scanDeviceSync");
        });
    }

    export function onScanDeviceAdd(callback: Callback<ScannerDevice>): void {
        let myCall = new CallbackWrapper<ScannerDevice>(callback);
        taskpool.execute((): void => {
            onScanDeviceAddNative(myCall);
        });
    }

    export function offScanDeviceAdd(callback?: Callback<ScannerDevice>): void {
        taskpool.execute((): void => {
            offScanDeviceAddNative("scanDeviceAdd");
        });
    }

    export function onScanDeviceDel(callback: Callback<ScannerDevice>): void {
        let myCall = new CallbackWrapper<ScannerDevice>(callback);
        taskpool.execute((): void => {
            onScanDeviceDelNative(myCall);
        });
    }

    export function offScanDeviceDel(callback?: Callback<ScannerDevice>): void {
        taskpool.execute((): void => {
            offScanDeviceDelNative("scanDeviceDel");
        });
    }

    native function initNative(callback: AsyncCallbackWrapper<void>): void;
    native function exitNative(callback: AsyncCallbackWrapper<void>): void;
    native function startScannerDiscoveryNative(callback: AsyncCallbackWrapper<void>): void;
    native function openScannerNative(scannerId: string, callback: AsyncCallbackWrapper<void>): void;
    native function closeScannerNative(scannerId: string, callback: AsyncCallbackWrapper<void>): void;
    native function getScannerParameterNative(scannerId: string, callback: AsyncCallbackArrayWrapper<ScannerParameter>): void;
    native function setScannerParameterNative(scannerId: string, optionIndex: int, value: ScannerOptionValue, callback: AsyncCallbackWrapper<void>): void;
    native function setScanAutoOptionNative(scannerId: string, optionIndex: int, callback: AsyncCallbackWrapper<void>): void;
    native function getScannerCurrentSettingNative(scannerId: string, optionIndex: int, callback: AsyncCallbackWrapper<ScannerOptionValue>): void;
    native function startScanNative(scannerId: string, batchMode: boolean, callback: AsyncCallbackWrapper<void>): void;
    native function cancelScanNative(scannerId: string, callback: AsyncCallbackWrapper<void>): void;
    native function getPictureScanProgressNative(scannerId: string, callback: AsyncCallbackWrapper<PictureScanProgress>): void;
    native function addScannerNative(uniqueId: string, discoveryMode: ScannerDiscoveryMode, callback: AsyncCallbackWrapper<void>): void;
    native function deleteScannerNative(uniqueId: string, discoveryMode: ScannerDiscoveryMode, callback: AsyncCallbackWrapper<void>): void;
    native function getAddedScannersNative(callback: AsyncCallbackArrayWrapper<ScannerDevice>): void;
    native function onScanDeviceFoundNative(callback: CallbackWrapper<ScannerDevice>): void;
    native function offScanDeviceFoundNative(type: string): void;
    native function onScanDeviceSyncNative(callback: CallbackWrapper<ScannerSyncDevice>): void;
    native function offScanDeviceSyncNative(type: string): void;
    native function onScanDeviceAddNative(callback: CallbackWrapper<ScannerDevice>): void;
    native function offScanDeviceAddNative(type: string): void;
    native function onScanDeviceDelNative(callback: CallbackWrapper<ScannerDevice>): void;
    native function offScanDeviceDelNative(type: string): void;
}
