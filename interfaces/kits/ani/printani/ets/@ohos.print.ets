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
import {BusinessError, Callback, AsyncCallback } from '@ohos.base';
import Context from 'application.Context';

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

export default namespace print {
    loadLibraryWithPermissionCheck("print_ani", "@ohos.print");

    export interface PrinterExtensionInfo {
        extensionId: string;
        vendorId: string;
        vendorName: string;
        vendorIcon: int;
        version: string;
    }

    export class PrinterExtensionInfoImpl implements PrinterExtensionInfo {
        extensionId: string;
        vendorId: string;
        vendorName: string;
        vendorIcon: int;
        version: string;
    }

    export interface PrintPageRange {
        startPage?: int;
        endPage?: int;
        pages?: Array<int>;
    }

    export interface PrintAttributes {
        copyNumber?: int;
        pageRange?: PrintPageRange;
        pageSize?: PrintPageSize | PrintPageType;
        directionMode?: PrintDirectionMode;
        colorMode?: PrintColorMode;
        duplexMode?: PrintDuplexMode;
    }

    export interface PrintDocumentAdapter {
        onStartLayoutWrite(jobId: string, oldAttrs: PrintAttributes, newAttrs: PrintAttributes, fd: int,
        writeResultCallback: (jobId: string, writeResult: PrintFileCreationState) => void): void;
        onJobStateChanged(jobId: string, state: PrintDocumentAdapterState): void;
    }

    export enum PrintDuplexMode {
        DUPLEX_MODE_NONE = 0,
        DUPLEX_MODE_LONG_EDGE = 1,
        DUPLEX_MODE_SHORT_EDGE = 2,
    }

    export enum PrintColorMode {
        COLOR_MODE_MONOCHROME = 0,
        COLOR_MODE_COLOR = 1,
    }

    export enum PrintDirectionMode {
        DIRECTION_MODE_AUTO = 0,
        DIRECTION_MODE_PORTRAIT = 1,
        DIRECTION_MODE_LANDSCAPE = 2,
    }

    export interface PrintPageSize {
        id: string;
        name: string;
        width: int;
        height: int;
    }

    export class PrintPageSizeImp implements PrintPageSize {
        id: string = '';
        name: string = '';
        width: int = 0;
        height: int = 0;
    }

    export enum PrintPageType {
        PAGE_ISO_A3 = 0,
        PAGE_ISO_A4 = 1,
        PAGE_ISO_A5 = 2,
        PAGE_JIS_B5 = 3,
        PAGE_ISO_C5 = 4,
        PAGE_ISO_DL = 5,
        PAGE_LETTER = 6,
        PAGE_LEGAL = 7,
        PAGE_PHOTO_4X6 = 8,
        PAGE_PHOTO_5X7 = 9,
        PAGE_INT_DL_ENVELOPE = 10,
        PAGE_B_TABLOID = 11,
    }

    export enum PrintDocumentAdapterState {
        PREVIEW_DESTROY = 0,
        PRINT_TASK_SUCCEED = 1,
        PRINT_TASK_FAIL = 2,
        PRINT_TASK_CANCEL = 3,
        PRINT_TASK_BLOCK = 4,
    }

    export enum PrintFileCreationState {
        PRINT_FILE_CREATED = 0,
        PRINT_FILE_CREATION_FAILED = 1,
        PRINT_FILE_CREATED_UNRENDERED = 2,
    }

    export enum PrinterState {
        PRINTER_ADDED = 0,
        PRINTER_REMOVED = 1,
        PRINTER_CAPABILITY_UPDATED = 2,
        PRINTER_CONNECTED = 3,
        PRINTER_DISCONNECTED = 4,
        PRINTER_RUNNING = 5
    }

    export enum PrintJobState {
        PRINT_JOB_PREPARE = 0,
        PRINT_JOB_QUEUED = 1,
        PRINT_JOB_RUNNING = 2,
        PRINT_JOB_BLOCKED = 3,
        PRINT_JOB_COMPLETED = 4
    }

    export enum PrintJobSubState {
        PRINT_JOB_COMPLETED_SUCCESS = 0,
        PRINT_JOB_COMPLETED_FAILED = 1,
        PRINT_JOB_COMPLETED_CANCELLED = 2,
        PRINT_JOB_COMPLETED_FILE_CORRUPTED = 3,
        PRINT_JOB_BLOCK_OFFLINE = 4,
        PRINT_JOB_BLOCK_BUSY = 5,
        PRINT_JOB_BLOCK_CANCELLED = 6,
        PRINT_JOB_BLOCK_OUT_OF_PAPER = 7,
        PRINT_JOB_BLOCK_OUT_OF_INK = 8,
        PRINT_JOB_BLOCK_OUT_OF_TONER = 9,
        PRINT_JOB_BLOCK_JAMMED = 10,
        PRINT_JOB_BLOCK_DOOR_OPEN = 11,
        PRINT_JOB_BLOCK_SERVICE_REQUEST = 12,
        PRINT_JOB_BLOCK_LOW_ON_INK = 13,
        PRINT_JOB_BLOCK_LOW_ON_TONER = 14,
        PRINT_JOB_BLOCK_REALLY_LOW_ON_INK = 15,
        PRINT_JOB_BLOCK_BAD_CERTIFICATE = 16,
        PRINT_JOB_BLOCK_DRIVER_EXCEPTION = 17,
        PRINT_JOB_BLOCK_ACCOUNT_ERROR = 18,
        PRINT_JOB_BLOCK_PRINT_PERMISSION_ERROR = 19,
        PRINT_JOB_BLOCK_PRINT_COLOR_PERMISSION_ERROR = 20,
        PRINT_JOB_BLOCK_NETWORK_ERROR = 21,
        PRINT_JOB_BLOCK_SERVER_CONNECTION_ERROR = 22,
        PRINT_JOB_BLOCK_LARGE_FILE_ERROR = 23,
        PRINT_JOB_BLOCK_FILE_PARSING_ERROR = 24,
        PRINT_JOB_BLOCK_SLOW_FILE_CONVERSION = 25,
        PRINT_JOB_RUNNING_UPLOADING_FILES = 26,
        PRINT_JOB_RUNNING_CONVERTING_FILES = 27,
        PRINT_JOB_BLOCK_FILE_UPLOADING_ERROR = 30,
        PRINT_JOB_BLOCK_DRIVER_MISSING = 34,
        PRINT_JOB_BLOCK_INTERRUPT = 35,
        PRINT_JOB_BLOCK_PRINTER_UNAVAILABLE = 98,
        PRINT_JOB_BLOCK_UNKNOWN = 99
    }

    export enum PrintErrorCode {
        E_PRINT_NONE = 0,
        E_PRINT_NO_PERMISSION = 201,
        E_PRINT_INVALID_PARAMETER = 401,
        E_PRINT_GENERIC_FAILURE = 13100001,
        E_PRINT_RPC_FAILURE = 13100002,
        E_PRINT_SERVER_FAILURE = 13100003,
        E_PRINT_INVALID_EXTENSION = 13100004,
        E_PRINT_INVALID_PRINTER = 13100005,
        E_PRINT_INVALID_PRINT_JOB = 13100006,
        E_PRINT_FILE_IO = 13100007
    }

    export enum ApplicationEvent {
        APPLICATION_CREATED = 0,
        APPLICATION_CLOSED_FOR_STARTED = 1,
        APPLICATION_CLOSED_FOR_CANCELED = 2
    }

    export interface PrinterInformation {
        printerId: string;
        printerName: string;
        printerStatus: PrinterStatus;
        description?: string;
        capability?: PrinterCapabilities;
        uri?: string;
        printerMake?: string;
        preferences?: PrinterPreferences;
        alias?: string;
        options?: string;
    }

    export class PrinterInformationImp implements PrinterInformation {
        printerId: string = '';
        printerName: string = '';
        printerStatus: PrinterStatus = PrinterStatus.PRINTER_BUSY;
        description?: string = undefined;
        capability?: PrinterCapabilities = undefined;
        uri?: string = undefined;
        printerMake?: string = '';
        preferences?: PrinterPreferences = undefined;
        alias?: string = undefined;
        options?: string = undefined;
    }

    export interface PrinterCapability {
        colorMode: int;
        duplexMode: int;
        pageSize: Array<PrintPageSize>;
        resolution?: Array<PrintResolution>;
        minMargin?: PrintMargin;
        options?: Object;
    }

    export class PrinterCapabilityImpl implements PrinterCapability {
        colorMode: int;
        duplexMode: int;
        pageSize: Array<PrintPageSize>;
        resolution?: Array<PrintResolution>;
        minMargin?: PrintMargin;
        supportedPageSizes: Array<PrintPageSize>;
        supportedColorModes: Array<PrintColorMode>;
        supportedDuplexModes: Array<PrintDuplexMode>;
        supportedMediaTypes?: Array<string>;
        supportedQualities?: Array<PrintQuality>;
        supportedOrientations?: Array<PrintOrientationMode>;
        options?: Object;
    }

    export interface PrintMargin {
        top?: int;
        bottom?: int;
        left?: int;
        right?: int;
    }

    export class PrintMarginImp implements PrintMargin {
        top?: int = undefined;
        bottom?: int = undefined;
        left?: int = undefined;
        right?: int = undefined;
    }

    export interface PrintResolution {
        id: string;
        horizontalDpi: int;
        verticalDpi: int;
    }

    export interface PrinterRange {
        startPage?: int;
        endPage?: int;
        pages?: Array<int>;
    }

    export class PrinterRangeImp implements PrinterRange {
        startPage?: int = undefined;
        endPage?: int = undefined;
        pages?: Array<int> = undefined;
    }

    export interface PreviewAttribute {
        previewRange: PrinterRange;
        result?: int;
    }

    export class PreviewAttributeImp implements PreviewAttribute {
        previewRange: PrinterRange;
        result?: int = undefined;
    }

    export interface PrintJob {
        fdList: Array<int>;
        jobId: string;
        printerId: string;
        jobState: PrintJobState;
        jobSubstate: PrintJobSubState;
        copyNumber: int;
        pageRange: PrinterRange;
        isSequential: boolean;
        pageSize: PrintPageSize;
        isLandscape: boolean;
        colorMode: int;
        duplexMode: int;
        margin?: PrintMargin;
        preview?: PreviewAttribute;
        options?: Object;
    }

    export class PrintJobImp implements PrintJob {
        fdList: Array<int> = new Array<int>();
        jobId: string = '';
        printerId: string = '';
        jobState: PrintJobState = PrintJobState.PRINT_JOB_BLOCKED;
        jobSubstate: PrintJobSubState = PrintJobSubState.PRINT_JOB_COMPLETED_SUCCESS;
        copyNumber: int = 0;
        pageRange: PrinterRange = {
            startPage: undefined,
            endPage: undefined,
            pages: undefined
        };
        isSequential: boolean = false;
        pageSize: PrintPageSize = {
            id: '',
            name: '',
            width: 0,
            height: 0
        };
        isLandscape: boolean = false;
        colorMode: int = 0;
        duplexMode: int = 0;
        margin?: PrintMargin;
        preview?: PreviewAttribute;
        options?: Object;
    }

    export interface PrinterInfo {
        printerId: string;
        printerName: string;
        printerState: PrinterState;
        printerIcon?: int;
        description?: string;
        capability?: PrinterCapability;
        options?: Object;
    }

    export interface PrinterCapabilities {
        supportedPageSizes: Array<PrintPageSize>;
        supportedColorModes: Array<PrintColorMode>;
        supportedDuplexModes: Array<PrintDuplexMode>;
        supportedMediaTypes?: Array<string>;
        supportedQualities?: Array<PrintQuality>;
        supportedOrientations?: Array<PrintOrientationMode>;
        options?: string;
    }

    export class PrinterInfoImpl implements PrinterInfo {
        printerId: string = '';
        printerName: string = '';
        printerState: PrinterState = PrinterState.PRINTER_ADDED;
        printerIcon?: int = undefined;
        description?: string = undefined;
        capability?: PrinterCapability = undefined;
        options?: Object = undefined;
    }

    export interface PrinterPreferences {
        defaultDuplexMode?: PrintDuplexMode;
        defaultPrintQuality?: PrintQuality;
        defaultMediaType?: string;
        defaultPageSizeId?: string;
        defaultOrientation?: PrintOrientationMode;
        borderless?: boolean;
        options?: string;
    }

    class PrinterPreferencesImpl implements PrinterPreferences {
        defaultDuplexMode?: PrintDuplexMode;
        defaultPrintQuality?: PrintQuality;
        defaultMediaType?: string;
        defaultPageSizeId?: string;
        defaultOrientation?: PrintOrientationMode;
        borderless?: boolean;
        options?: string;
    }

    enum PrintQuality {
        QUALITY_DRAFT = 3,
        QUALITY_NORMAL = 4,
        QUALITY_HIGH = 5,
    }

    enum PrintOrientationMode {
        ORIENTATION_MODE_PORTRAIT = 0,
        ORIENTATION_MODE_LANDSCAPE = 1,
        ORIENTATION_MODE_REVERSE_LANDSCAPE = 2,
        ORIENTATION_MODE_REVERSE_PORTRAIT = 3,
        ORIENTATION_MODE_NONE = 4,
    }

    export enum PrinterStatus {
        PRINTER_IDLE = 0,
        PRINTER_BUSY = 1,
        PRINTER_UNAVAILABLE = 2,
    }

    export enum PrinterEvent {
      PRINTER_EVENT_ADDED,
      PRINTER_EVENT_DELETED,
      PRINTER_EVENT_STATE_CHANGED,
      PRINTER_EVENT_INFO_CHANGED,
      PRINTER_EVENT_PREFERENCE_CHANGED,
      PRINTER_EVENT_LAST_USED_PRINTER_CHANGED,
    }

    export interface PrintAttributesParameter {
        jobName: string;
        printAdapter : PrintDocumentAdapter;
        printAttributes : PrintAttributes;
        context : Context;
    }

    type printerStateChangeCallback = (state: PrinterState, printerInfo: PrinterInfo) => void;

    type jobStateChangeCallback = (state: PrintJobState, job: PrintJob) => void;

    type extInfoChangeCallback = (extensionId: string, info: string) => void;

    type printerChangeCallback = (event: PrinterEvent, info: PrinterInfo) => void;

    native function printNative(files: Array<string>, callback: AsyncCallbackWrapper<PrintTask>): void;

    native function printWithContextNative(files: Array<string>, context: Context, callback: AsyncCallbackWrapper<PrintTask>): void;

    native function printWithAttributesNative(para : PrintAttributesParameter, callback: AsyncCallbackWrapper<PrintTask>): void;

    native function onNative(type: string, callback: CallbackWrapper<void>) : int;

    native function onPrinterStateChangeNative(type: 'printerStateChange', callback: PrinterStateChangeWrapper) : int;

    native function onJobStateChangeNative(type: 'jobStateChange', callback: JobStateChangeWrapper) : int;

    native function onExtInfoChangeNative(type: 'extInfoChange', callback: ExtInfoChangeWrapper) : int;
    
    native function onPrintTask(type: string, callback: CallbackWrapper<void>, task : PrintTaskImpl) : void;

    native function offPrintTask(type: string, callback: CallbackWrapper<void>, task : PrintTaskImpl) : void;

    native function offNative(type: string, callback: CallbackWrapper<void>) : int;
    
    native function queryAllPrinterExtensionInfosNative(callback: AsyncCallbackArrayWrapper<PrinterExtensionInfo>): void;
    
    native function startDiscoverPrinterNative(extensionList: Array<string>, callback: AsyncCallbackWrapper<void>): void;

    native function stopDiscoverPrinterNative(callback: AsyncCallbackWrapper<void>): void;

    native function connectPrinterNative(printerId: string, callback: AsyncCallbackWrapper<void>): void;

    native function disconnectPrinterNative(printerId: string, callback: AsyncCallbackWrapper<void>): void;

    native function queryPrinterCapabilityNative(printerId: string, callback: AsyncCallbackWrapper<void>): void;

    native function startPrintJobNative(jobInfo: PrintJob, callback: AsyncCallbackWrapper<void>): void;

    native function cancelPrintJobNative(jobId: string, callback: AsyncCallbackWrapper<void>): void;

    native function requestPrintPreviewNative(jobInfo: PrintJob, callback: CallbackWrapper<int>): void;

    native function requestPrintPreviewCallbackNative(jobInfo: PrintJob, callback: CallbackWrapper<int>): void;

    native function requestPrintPreviewAsyncCallbackNative(jobInfo: PrintJob, callback: AsyncCallbackWrapper<int>): void;

    native function addPrintersNative(printers: Array<PrinterInfo>, callback: AsyncCallbackWrapper<void>): void;

    native function removePrintersNative(printerIds: Array<string>, callback: AsyncCallbackWrapper<void>): void;

    native function updatePrintersNative(printers: Array<PrinterInfo>, callback: AsyncCallbackWrapper<void>): void;

    native function updatePrinterStateNative(printerId: string, state: PrinterState, callback: AsyncCallbackWrapper<void>): void;

    native function updatePrintJobStateNative(jobId: string, state: PrintJobState, subState: PrintJobSubState, callback: AsyncCallbackWrapper<void>): void;

    native function updateExtensionInfoNative(info: string, callback: AsyncCallbackWrapper<void>): void;

    native function queryAllPrintJobsNative(callback: AsyncCallbackWrapper<void>): void;

    native function queryPrintJobListNative(callback: AsyncCallbackArrayWrapper<PrintJob>): void;

    native function queryPrintJobByIdNative(jobId: string, callback: AsyncCallbackWrapper<PrintJob>): void;

    native function startGettingPrintFileNative(jobId: string, printAttributes: PrintAttributes, fd: int, callback: CallbackWrapper<PrintFileCreationState>): void;

    native function notifyPrintServiceNative(jobId: string, type:string, callback: AsyncCallbackWrapper<void>): void;

    native function notifyPrintServiceWithStateNative(jobId: string, state: int, callback: AsyncCallbackWrapper<void>): void;

    native function getAddedPrintersNative(callback: AsyncCallbackArrayWrapper<string>): void;

    native function getPrinterInfoByIdNative(printerId: string, callback: AsyncCallbackWrapper<PrinterInfo>): void;

    native function notifyPrintServiceEventNative(event: ApplicationEvent, callback: AsyncCallbackWrapper<void>): void;

    native function addPrinterToDiscoveryNative(printerInformation: PrinterInformation, callback: AsyncCallbackWrapper<void>): void;

    native function updatePrinterInDiscoveryNative(printerInformation: PrinterInformation, callback: AsyncCallbackWrapper<void>): void;
    
    native function removePrinterFromDiscoveryNative(printerId: string, callback: AsyncCallbackWrapper<void>): void;

    native function getPrinterInformationByIdNative(printerId: string, callback: AsyncCallbackWrapper<PrinterInformation>): void;

    export interface PrintTask {
        on(type: 'block' | 'succeed' | 'fail' | 'cancel', callback: Callback<void>): void;
        off(type: 'block' | 'succeed' | 'fail' | 'cancel', callback?: Callback<void>): void;
    }

    export class PrintTaskImpl implements PrintTask {
        private  nativeTask: long = 0;
        constructor(task: long) {
            if(this.nativeTask == 0){
                this.nativeTask = task;
            }
        }
        on(type: 'block' | 'succeed' | 'fail' | 'cancel', callback: Callback<void>): void {
            let myCall = new CallbackWrapper<void>(callback);
            onPrintTask(type, myCall, this);
        }
        off(type: 'block' | 'succeed' | 'fail' | 'cancel', callback?: Callback<void>): void {
            let myCall = new CallbackWrapper<void>(() => {});
            
            if (callback !== undefined) {
                myCall = new CallbackWrapper<void>(callback);
            }
            offPrintTask(type, myCall, this);
        }
    }

    export function print(files: Array<string>, callback: AsyncCallback<PrintTask, void>): void {
        let myCall = new AsyncCallbackWrapper<PrintTask>(callback);
        taskpool.execute((): void => {
            printNative(files, myCall);
        })
    }

    export function print(files: Array<string>): Promise<PrintTask> {
        let p:Promise<PrintTask> =
            new Promise<PrintTask>((resolve: (data: PrintTask | undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<PrintTask>((err: BusinessError<void> | null, data: PrintTask | undefined)=>{
                if (err === null || err.code == 0) {
                    resolve(data);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                printNative(files, myCall);
            });
        });
        return p;
    }

    export function print(files: Array<string>, context: Context, callback: AsyncCallback<PrintTask>): void {
        let myCall = new AsyncCallbackWrapper<PrintTask>(callback);
        taskpool.execute((): void => {
            printWithContextNative(files, context, myCall);
        })
    }

    export function print(files: Array<string>, context: Context): Promise<PrintTask> {
        let p:Promise<PrintTask> =
            new Promise<PrintTask>((resolve: (data: PrintTask | undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<PrintTask>((err: BusinessError<void> | null, data: PrintTask | undefined)=>{
                if (err === null || err.code == 0) {
                    resolve(data);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                printWithContextNative(files, context, myCall);
            });
        });
        return p;
    }

    export function print(jobName: string, printAdapter: PrintDocumentAdapter, printAttributes: PrintAttributes,
    context: Context): Promise<PrintTask> {
        let p:Promise<PrintTask> =
            new Promise<PrintTask>((resolve: (data: PrintTask | undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<PrintTask>((err: BusinessError<void> | null, data: PrintTask | undefined)=>{
                if (err === null || err.code == 0) {
                    resolve(data);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                let para: PrintAttributesParameter = {
                    jobName: jobName,
                    printAdapter: printAdapter,
                    printAttributes: printAttributes,
                    context: context
                };
                printWithAttributesNative(para, myCall);
            });
        });
        return p;
    }

    export function queryAllPrinterExtensionInfos(callback: AsyncCallback<Array<PrinterExtensionInfo>>): void {
        let myCall = new AsyncCallbackArrayWrapper<PrinterExtensionInfo>(callback);
        taskpool.execute((): void => {
            queryAllPrinterExtensionInfosNative(myCall);
        })
    }

    export function queryAllPrinterExtensionInfos(): Promise<Array<PrinterExtensionInfo>> {
        let p:Promise<Array<PrinterExtensionInfo>> =
            new Promise<Array<PrinterExtensionInfo>>((resolve: (data: Array<PrinterExtensionInfo> | undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackArrayWrapper<PrinterExtensionInfo>((err: BusinessError<void> | null, data: Array<PrinterExtensionInfo> | undefined)=>{
                if (err === null || err.code == 0) {
                    resolve(data);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                queryAllPrinterExtensionInfosNative(myCall);
            });
        });
        return p;
    }

    export function startDiscoverPrinter(extensionList: Array<string>, callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            startDiscoverPrinterNative(extensionList, myCall);
        });
    }

    export function startDiscoverPrinter(extensionList: Array<string>): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });

            taskpool.execute((): void => {
                startDiscoverPrinterNative(extensionList, myCall);
            });
        });
    }

    export function stopDiscoverPrinter(callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            stopDiscoverPrinterNative(myCall);
        });
    }

    export function stopDiscoverPrinter(): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                stopDiscoverPrinterNative(myCall);
            });
        });
    }

    export function connectPrinter(printerId: string, callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            connectPrinterNative(printerId, myCall);
        });
    }

    export function connectPrinter(printerId: string): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                connectPrinterNative(printerId, myCall);
            });
        });
    }

    export function disconnectPrinter(printerId: string, callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            disconnectPrinterNative(printerId, myCall);
        });
    }

    export function disconnectPrinter(printerId: string): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                disconnectPrinterNative(printerId, myCall);
            });
        });
    }

    export function queryPrinterCapability(printerId: string, callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            queryPrinterCapabilityNative(printerId, myCall);
        });
    }

    export function queryPrinterCapability(printerId: string): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                queryPrinterCapabilityNative(printerId, myCall);
            });
        });
    }

    export function startPrintJob(jobInfo: PrintJob, callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            startPrintJobNative(jobInfo, myCall);
        });
    }

    export function startPrintJob(jobInfo: PrintJob): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                startPrintJobNative(jobInfo, myCall);
            });
        });
    }

    export function cancelPrintJob(jobId: string, callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            cancelPrintJobNative(jobId, myCall);
        });
    }

    export function cancelPrintJob(jobId: string): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                cancelPrintJobNative(jobId, myCall);
            });
        });
    }

    export function requestPrintPreview(jobInfo: PrintJob, callback: Callback<int>): void {
        let myCall = new CallbackWrapper<int>(callback);
        taskpool.execute((): void => {
            requestPrintPreviewCallbackNative(jobInfo, myCall);
        });
    }

    export function requestPrintPreview(jobInfo: PrintJob): Promise<int> {
        return new Promise<int>((resolve: (data:int | undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<int>((err, data) => {
                if (err === null || err.code == 0) {
                    resolve(data);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                requestPrintPreviewAsyncCallbackNative(jobInfo, myCall);
            });
        });
    }

    

    export class PrinterStateChangeWrapper {
        private myFun_: (state: PrinterState, info: PrinterInfo) => void;

        constructor(myFun: (state: PrinterState, info: PrinterInfo) => void) {
            this.myFun_ = myFun;
        }

        invoke(state: PrinterState, info: PrinterInfo): void {
            this.myFun_(state, info);
        }
    }

    export class JobStateChangeWrapper {
        private myFun_: (state: PrintJobState, job: PrintJob) => void;

        constructor(myFun: (state: PrintJobState, job: PrintJob) => void) {
            this.myFun_ = myFun;
        }

        invoke(state: PrintJobState, job: PrintJob): void {
            this.myFun_(state, job);
        }
    }

    export class ExtInfoChangeWrapper {
        private myFun_: (extensionId: string, info: string) => void;

        constructor(myFun: (extensionId: string, info: string) => void) {
            this.myFun_ = myFun;
        }

        invoke(extensionId: string, info: string): void {
            this.myFun_(extensionId, info);
        }
    }

    export function on(type: 'printerStateChange|jobStateChange|extInfoChange',
        callback: printerStateChangeCallback | jobStateChangeCallback | extInfoChangeCallback): void {
        switch (type) {
            case 'printerStateChange': {
                const typedCallback = callback as (state: PrinterState, info: PrinterInfo) => void;
                const myCall = new PrinterStateChangeWrapper(typedCallback);
                taskpool.execute((): void => {
                    onPrinterStateChangeNative(type as 'printerStateChange', myCall);
                });
                break;
            }
            case 'jobStateChange': {
                const typedCallback = callback as (state: PrintJobState, job: PrintJob) => void;
                const myCall = new JobStateChangeWrapper(typedCallback);
                taskpool.execute((): void => {
                    onJobStateChangeNative(type as 'jobStateChange', myCall);
                });
                break;
            }
            case 'extInfoChange': {
                const typedCallback = callback as (extensionId: string, info: string) => void;
                const myCall = new ExtInfoChangeWrapper(typedCallback);
                taskpool.execute((): void => {
                    onExtInfoChangeNative(type as 'extInfoChange', myCall);
                });
                break;
            }
            default:
                throw new Error(`Unknown event type: ${type}`);
        }
    }

    export function off(type: 'printerStateChange' | 'jobStateChange' | 'extInfoChange', callback?: Callback<void>): void {
        let myCall = new CallbackWrapper<void>(() => {});
        
        if (callback !== undefined) {
            myCall = new CallbackWrapper<void>(callback);
        }
        
        taskpool.execute((): void => {
            offNative(type, myCall);
        });
    }

    export function addPrinters(printers: Array<PrinterInfo>, callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            addPrintersNative(printers, myCall);
        });
    }

    export function addPrinters(printers: Array<PrinterInfo>): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                addPrintersNative(printers, myCall);
            });
        });
    }

    export function removePrinters(printerIds: Array<string>, callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            removePrintersNative(printerIds, myCall);
        });
    }

    export function removePrinters(printerIds: Array<string>): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                removePrintersNative(printerIds, myCall);
            });
        });
    }

    export function updatePrinters(printers: Array<PrinterInfo>, callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            updatePrintersNative(printers, myCall);
        });
    }

    export function updatePrinters(printers: Array<PrinterInfo>): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                updatePrintersNative(printers, myCall);
            });
        });
    }

    export function updatePrinterState(printerId: string, state: PrinterState, callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            updatePrinterStateNative(printerId, state, myCall);
        });
    }

    export function updatePrinterState(printerId: string, state: PrinterState): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                updatePrinterStateNative(printerId, state, myCall);
            });
        });
    }

    export function updatePrintJobState(jobId: string, state: PrintJobState, subState: PrintJobSubState, callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            updatePrintJobStateNative(jobId, state, subState, myCall);
        });
    }

    export function updatePrintJobState(jobId: string, state: PrintJobState, subState: PrintJobSubState): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                updatePrintJobStateNative(jobId, state, subState, myCall);
            });
        });
    }

    export function updateExtensionInfo(info: string, callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            updateExtensionInfoNative(info, myCall);
        });
    }

    export function updateExtensionInfo(info: string): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                updateExtensionInfoNative(info, myCall);
            });
        });
    }

    export function queryAllPrintJobs(callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            queryAllPrintJobsNative(myCall);
        });
    }

    export function queryAllPrintJobs(): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                queryAllPrintJobsNative(myCall);
            });
        });
    }

    export function queryPrintJobList(callback: AsyncCallback<Array<PrintJob>>): void {
        let myCall = new AsyncCallbackArrayWrapper<PrintJob>(callback);
        taskpool.execute((): void => {
            queryPrintJobListNative(myCall);
        });
    }

    export function queryPrintJobList(): Promise<Array<PrintJob>> {
        return new Promise<Array<PrintJob>>((resolve: (data: Array<PrintJob> | undefined)=>void, reject:(err: BusinessError<void> | null)=>void): void => {
            let myCall = new AsyncCallbackArrayWrapper<PrintJob>((err : BusinessError<void> | null, data : Array<PrintJob>|undefined) => {
                if (err === null || err.code == 0) {
                    resolve(data);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                queryPrintJobListNative(myCall);
            });
        });
    }

    export function queryPrintJobById(jobId: string, callback: AsyncCallback<PrintJob>): void {
        let myCall = new AsyncCallbackWrapper<PrintJob>(callback);
        taskpool.execute((): void => {
            queryPrintJobByIdNative(jobId, myCall);
        });
    }

    export function queryPrintJobById(jobId: string): Promise<PrintJob> {
        return new Promise<PrintJob>((resolve: (data: PrintJob | undefined)=>void, reject:(err: BusinessError<void> | null)=>void): void => {
            let myCall = new AsyncCallbackWrapper<PrintJob>((err : BusinessError<void> | null, data : PrintJob|undefined) => {
                if (err === null || err.code == 0) {
                    resolve(data);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                queryPrintJobByIdNative(jobId, myCall);
            });
        });
    }

    export function startGettingPrintFile(jobId: string, printAttributes: PrintAttributes, fd: int, callback: Callback<PrintFileCreationState>): void {
        let myCall = new CallbackWrapper<PrintFileCreationState>(callback);
        taskpool.execute((): void => {
            startGettingPrintFileNative(jobId, printAttributes, fd, myCall);
        });
    }


    export function notifyPrintService(jobId: string, type: string, callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            notifyPrintServiceNative(jobId, type, myCall);
        });
    }

    export function notifyPrintService(jobId: string, type: string): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                notifyPrintServiceNative(jobId, type, myCall);
            });
        });
    }

    export function getAddedPrinters(): Promise<Array<string>> {
        return new Promise<Array<string>>((resolve: (data: Array<string> | undefined)=>void, reject:(err: BusinessError<void> | null)=>void): void => {
            let myCall = new AsyncCallbackArrayWrapper<string>((err : BusinessError<void> | null, data : Array<string> | undefined) => {
                if (err === null || err.code == 0) {
                    resolve(data);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                getAddedPrintersNative(myCall);
            });
        });
    }

    export function getPrinterInfoById(printerId: string): Promise<PrinterInfo> {
        return new Promise<PrinterInfo>((resolve: (data: PrinterInfo | undefined)=>void, reject:(err: BusinessError<void> | null)=>void): void => {
            let myCall = new AsyncCallbackWrapper<PrinterInfo>((err : BusinessError<void> | null, data : PrinterInfo | undefined) => {
                if (err === null || err.code == 0) {
                    resolve(data);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                getPrinterInfoByIdNative(printerId, myCall);
            });
        });
    }

    export function notifyPrintServiceEvent(event: ApplicationEvent): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                notifyPrintServiceEventNative(event, myCall);
            });
        });
    }

    export function addPrinterToDiscovery(printerInformation: PrinterInformation): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                addPrinterToDiscoveryNative(printerInformation, myCall);
            });
        });
    }

    export function updatePrinterInDiscovery(printerInformation: PrinterInformation): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError<void> | null) => {
                if (err === null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                updatePrinterInDiscoveryNative(printerInformation, myCall);
            });
        });
    }

    export function removePrinterFromDiscovery(printerId: string): Promise<void> {
        return new Promise<void>((resolve: (data:undefined)=>void, reject:(err: BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err : BusinessError | null) => {
                if (err == null || err.code == 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                removePrinterFromDiscoveryNative(printerId, myCall);
            });
        });
    }

    export function getPrinterInformationById(printerId: string): Promise<PrinterInformation> {
        return new Promise<PrinterInformation>((resolve: (data: PrinterInformation | undefined)=>void, reject:(err: BusinessError<void> | null)=>void): void => {
            let myCall = new AsyncCallbackWrapper<PrinterInformation>((err : BusinessError<void> | null, data : PrinterInformation | undefined) => {
                if (err === null || err.code == 0) {
                    resolve(data);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                getPrinterInformationByIdNative(printerId, myCall);
            });
        });
    }
}