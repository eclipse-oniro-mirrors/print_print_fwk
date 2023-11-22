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
import type { AsyncCallback } from './@ohos.base';
import type Context from './application/Context';

/**
 * System print
 * @syscap SystemCapability.Print.PrintFramework
 * @import import print from '@ohos.app.print';
 * @since 10
 */
declare namespace print {

  interface PrintTask {
    /**
     * Register event callback when the current print task is in process.
     * @since 10
     * @param type block Indicates the print task has been blocked.
     *        type succeed Indicates the print task succeed.
     *        type fail Indicates the print task has completed with failure.
     *        type cancel Indicates the print task has been cancelled.
     * @param callback The callback function for print task change event
     * @permission {@code ohos.permission.PRINT}
     * @return -
     */
    on(type: 'block' | 'succeed' | 'fail' | 'cancel', callback: () => void): void;

    /**
     * Unregister event callback when the current print task is in process.
     * @since 10
     * @param type block Indicates the print task has been blocked.
     *        type succeed Indicates the print task succeed.
     *        type fail Indicates the print task has completed with failure.
     *        type cancel Indicates the print task has been cancelled.
     * @param callback The callback function for print task change event
     * @permission {@code ohos.permission.PRINT}
     * @return -
     */
    off(type: 'block' | 'succeed' | 'fail' | 'cancel', callback?: (boolean) => void): void;
  }

  interface PrintDocumentAdapter {
    /**
     * Implement this function to update the print file.
     * 
     * @since 11
     * @param jobId Indicates print job id.
     * @param oldAttrs Indicates old print attributes.
     * @param newAttrs Indicates new print attributes.
     * @param fd Indicates print file fd.
     * @param writeResultCallback Indicates this function should execute after the file is updated.
     * @permission {@code ohos.permission.PRINT}
     * @return -
     */
    onStartLayoutWrite(jobId: string, oldAttrs: PrintAttributes, newAttrs: PrintAttributes, fd: number,
      writeResultCallback: (jobId: string, writeResult: PrintFileCreatedInfoCode) => void): void;

    /**
     * Implement this function to Listen job status change.
     * 
     * @since 11
     * @param jobId Indicates print job id.
     * @param state Indicates job changes to this state.
     * @permission {@code ohos.permission.PRINT}
     * @return -
     */
    onJobStateChanged(jobId: string, state: PrintAdapterListeningState): void;
  }

  /**
   * Start new print task for App.
   * @since 10
   * @param files Indicates the filepath list to be printed. Only pdf and picture filetype are supported.
   * @param callback The callback function for print task.
   * @permission {@code ohos.permission.PRINT}
   * @return -
   */
  function print(files: Array<string>, callback: AsyncCallback<PrintTask>): void;
  function print(files: Array<string>): Promise<PrintTask>;

  /**
   * Start new print task for App.
   * @since 10
   * @param files Indicates the filepath list to be printed. Only pdf and picture filetype are supported.
   * @param { Context } context - The ability context that initiates the call print request.
   * @param callback The callback function for print task.
   * @permission {@code ohos.permission.PRINT}
   * @return -
   */
  function print(files: Array<string>, context: Context, callback: AsyncCallback<PrintTask>): void;
  function print(files: Array<string>, context: Context): Promise<PrintTask>;

  /**
   * Start new print task for App And the App need update print file.
   * @since 11
   * @param jobName Indicates print file name.
   * @param printAdapter Indicates functions implemented by the app.
   * @param printAttributes Indicates print attributes.
   * @param { Context } context - The ability context that initiates the call print request.
   * @param callback The callback function for print task.
   * @permission {@code ohos.permission.PRINT}
   * @return -
   */
  function print(jobName: string, printAdapter: PrintDocumentAdapter, printAttributes: PrintAttributes,
    context: Context, callback: AsyncCallback<PrintTask>): void;
  function print(jobName: string, printAdapter: PrintDocumentAdapter, printAttributes: PrintAttributes,
    context: Context): Promise<PrintTask>;

  /**
   * public interface
   */
  interface PrintAttributes {
    copyNumber?: number; // copies of document list
    pageRange?: PrinterRange; // range size to be printed
    pageSize? : PrintPageSize | PrintPageTypeCode; // page size
    directionMode? : PrintDirectionModeCode; // print direction
    colorMode? : PrintColorModeCode; // color mode
    duplexMode? : PrintDuplexModeCode; // duplex mode
  }

  /**
   * public interface
   */
  interface PrinterRange {
    startPage?: number; // start page of sequence
    endPage?: number; // end page of sequence
    pages?: Array<number>; // discrete page of sequence
  }

  /**
   * public interface
   */
  interface PrintPageSize {
    id: string; // page size id
    name: string; // page size name
    width: number; // unit: millimeter
    height: number; // unit: millimeter
  }

  /**
   * public enum
   */
  enum PrintDirectionModeCode {
    DIRECTION_MODE_AUTO = 0,
    DIRECTION_MODE_PORTRAIT = 1,
    DIRECTION_MODE_LANDSCAPE = 2,
  }

  /**
   * public enum
   */
  enum PrintColorModeCode {
    COLOR_MODE_MONOCHROME = 0,
    COLOR_MODE_COLOR = 1,
  }

  /**
   * public enum
   */
  enum PrintDuplexModeCode {
    DUPLEX_MODE_NONE = 0,
    DUPLEX_MODE_LONG_EDGE = 1,
    DUPLEX_MODE_SHORT_EDGE = 2,
  }

  /**
   * public enum
   */
  enum PrintPageTypeCode {
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

  /**
   * public enum
   */
  enum PrintAdapterListeningState {
    PREVIEW_ABILITY_DESTROY = 0,
    PRINT_TASK_SUCCEED = 1,
    PRINT_TASK_FAIL = 2,
    PRINT_TASK_CANCEL = 3,
    PRINT_TASK_BLOCK = 4,
  }

  /**
   * public enum
   */
  enum PrintFileCreatedInfoCode {
    PRINT_FILE_CREATED_SUCCESS = 0,
    PRINT_FILE_CREATED_FAIL = 1,
    PRINT_FILE_CREATED_SUCCESS_UNRENDERED = 2,
  }

  interface PrintMargin {
    top?: number; // top margin
    bottom?: number; // bottom margin
    left?: number; // left side margin
    right?: number; // right side margin
  }

  interface PreviewAttribute {
    previewRange: PrinterRange; // preview page range
    result?: number; // preview file
  }

  interface PrintResolution {
    id: string; // resolution id
    horizontalDpi: number; // horizontal DPI
    verticalDpi: number; // vertical DPI
  }

  interface PrinterCapability {
    /* Printer Capability */
    colorMode: number; // color mode
    duplexMode: number; // duplex mode
    pageSize: Array<PrintPageSize>; // the page size list supported by the printer
    resolution?: Array<PrintResolution>; // the resolution list supported by the printer
    minMargin?: PrintMargin; // min margin of printer
    option?: string; // json object string
  }

  interface PrinterInfo {
    printerId: string; // printer id
    printerName: string; // printer name
    printerState: PrinterState; // current printer state
    printerIcon?: number; // resource id of printer icon
    description?: string; // printer description
    capability?: PrinterCapability; // printer capability
    option?: string; // json object string
  }

  interface PrintJob {
    fdList: Array<number>; // document fd list to be printed
    jobId: string; // job id
    printerId: string; // printer id to take charge of printing
    jobState: PrintJobState; // current print job state
    jobSubstate: PrintJobSubState; // current print job sub state.
    copyNumber: number; // copies of document list
    pageRange: PrinterRange; // range size to be printed
    isSequential: boolean; // sequential print
    pageSize: PrintPageSize; // the selected page size
    isLandscape: boolean; // vertical printing
    colorMode: number; // color mode
    duplexMode: number; // duplex mode
    margin?: PrintMargin; // current margin setting
    preview?: PreviewAttribute; // preview setting
    option?: string; // json object string
  }

  enum PrinterState {
    PRINTER_ADDED = 0, // new printers arrival
    PRINTER_REMOVED = 1, // printers lost
    PRINTER_UPDATE_CAP = 2, // printers update
    PRINTER_CONNECTED = 3, // printer has been connected
    PRINTER_DISCONNECTED = 4, // printer has been disconnected
    PRINTER_RUNNING = 5, // printer is working
  }

  enum PrintJobState {
    PRINT_JOB_PREPARE = 0, // initial state of print job
    PRINT_JOB_QUEUED = 1, // deliver print job to the printer
    PRINT_JOB_RUNNING = 2, // executing print job
    PRINT_JOB_BLOCKED = 3, // print job has been blocked
    PRINT_JOB_COMPLETED = 4, // print job cmpleted
  }

  enum PrintJobSubState {
    PRINT_JOB_COMPLETED_SUCCESS = 0, // print job succeed
    PRINT_JOB_COMPLETED_FAILED = 1, // print job fail
    PRINT_JOB_COMPLETED_CANCELLED = 2, // print job has been cancelled
    PRINT_JOB_COMPLETED_FILE_CORRUPT = 3, // print job has been corrupted
    PRINT_JOB_BLOCK_OFFLINE = 4, // printer is offline
    PRINT_JOB_BLOCK_BUSY = 5, // printer is occupied by other process
    PRINT_JOB_BLOCK_CANCELLED = 6, // print job has been cancelled
    PRINT_JOB_BLOCK_OUT_OF_PAPER = 7, // out of paper
    PRINT_JOB_BLOCK_OUT_OF_INK = 8, // out of ink
    PRINT_JOB_BLOCK_OUT_OF_TONER = 9, // out of toner
    PRINT_JOB_BLOCK_JAMMED = 10, // paper jam
    PRINT_JOB_BLOCK_DOOR_OPEN = 11, // cover open
    PRINT_JOB_BLOCK_SERVICE_REQUEST = 12, // service request
    PRINT_JOB_BLOCK_LOW_ON_INK = 13, // low on ink
    PRINT_JOB_BLOCK_LOW_ON_TONER = 14, // low on toner
    PRINT_JOB_BLOCK_REALLY_LOW_ON_INK = 15, // really low on ink
    PRINT_JOB_BLOCK_BAD_CERTIFICATE = 16, // bad certification
    PRINT_JOB_BLOCK_ACCOUNT_ERROR = 18, // An error occurred when printing the account.
    PRINT_JOB_BLOCK_PRINT_PERMISSION_ERROR = 19, // The printing permission is abnormal.
    PRINT_JOB_BLOCK_PRINT_COLOR_PERMISSION_ERROR = 20, // Color printing permission exception
    PRINT_JOB_BLOCK_NETWORK_ERROR = 21, // The device is not connected to the network.
    PRINT_JOB_BLOCK_SERVER_CONNECTION_ERROR = 22, // Unable to connect to the server
    PRINT_JOB_BLOCK_LARGE_FILE_ERROR = 23, // Large file exception
    PRINT_JOB_BLOCK_FILE_PARSING_ERROR = 24, // File parsing exception.
    PRINT_JOB_BLOCK_SLOW_FILE_CONVERSION = 25, // The file conversion is too slow.

    PRINT_JOB_RUNNING_UPLOADING_FILES = 26, // Uploading file...
    PRINT_JOB_RUNNING_CONVERTING_FILES = 27, // Converting files...
    PRINT_JOB_BLOCK_UNKNOWN = 99, // unknown issue
  }

  enum PrintErrorCode {
    E_PRINT_NONE = 0, // no error
    E_PRINT_NO_PERMISSION = 201, // no permission
    E_PRINT_INVALID_PARAMETER = 401, // invalid parameter
    E_PRINT_GENERIC_FAILURE = 13100001, // generic failure of print
    E_PRINT_RPC_FAILURE = 13100002, // RPC failure
    E_PRINT_SERVER_FAILURE = 13100003, // failure of print service
    E_PRINT_INVALID_EXTENSION = 13100004, // invalid print extension
    E_PRINT_INVALID_PRINTER = 13100005, // invalid printer
    E_PRINT_INVALID_PRINTJOB = 13100006, // invalid print job
    E_PRINT_FILE_IO = 13100007, // file i/o error
  }

  interface PrinterExtensionInfo {
    extensionId: string; // extension id of printer extension
    vendorId: string; // vendor id of extension
    vendorName: string; // vendor name
    vendorIcon: number; // resource id of vendor
    version: string; // version of current printer extension
  }

  /**
   * Get all printer extension installed.
   *
   * @since 10
   * @param callback The callback function for handling the extension list found.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function queryAllPrinterExtensionInfos(callback: AsyncCallback<Array<PrinterExtensionInfo>>): void;
  function queryAllPrinterExtensionInfos(): Promise<Array<PrinterExtensionInfo>>;

  /**
   * Load the specific printer extension and start to discover printer.
   *
   * @since 10
   * @param extensionList Indicates the list of printer extension.
   *        empty list of extensionList Indicates to find printer with all installed extension.
   * @param callback The callback function for indcating the result of API execution.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function startDiscoverPrinter(extensionList: Array<string>, callback: AsyncCallback<boolean>): void;
  function startDiscoverPrinter(extensionList: Array<string>): Promise<boolean>;

  /**
   * Stop discovering the printer with specific printer extension.
   *
   * @since 10
   * @param extensionList Indicates the list of printer extension.
   *        empty list of extensionList Indicates to find printer with all installed extension.
   * @param callback The callback function for indcating the result of API execution.
   * @permission {@ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function stopDiscoverPrinter(callback: AsyncCallback<boolean>): void;
  function stopDiscoverPrinter(): Promise<boolean>;

  /**
  * Connect the specific printer.
  *
  * @since 10
  * @param printerId Indicates id of the printer.
  * @param callback The callback function for indcating the result of API execution.
  * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
  * @systemapi Hide this for inner system use.
  * @return -
  */
  function connectPrinter(printerId: string, callback: AsyncCallback<boolean>): void;
  function connectPrinter(printerId: string): Promise<boolean>;

  /**
  * Disconnect the specific printer.
  *
  * @since 10
  * @param printerId Indicates id of the printer.
  * @param callback The callback function for indcating the result of API execution.
  * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
  * @systemapi Hide this for inner system use.
  * @return -
  */
  function disconnectPrinter(printerId: string, callback: AsyncCallback<boolean>): void;
  function disconnectPrinter(printerId: string): Promise<boolean>;

  /**
   * Query capability for the specific printer.
   *
   * @since 10
   * @param printerId Indicates id of the printer.
   * @param callback The callback function for capability from printer.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function queryPrinterCapability(printerId: string, callback: AsyncCallback<boolean>): void;
  function queryPrinterCapability(printerId: string): Promise<boolean>;

  /**
   * Start print job.
   *
   * @since 10
   * @param jobInfo Indicates the information of print job.
   * @param callback The callback function for indcating the result of API execution.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function startPrintJob(jobInfo: PrintJob, callback: AsyncCallback<boolean>): void;
  function startPrintJob(jobInfo: PrintJob): Promise<boolean>;

  /**
   * Cancel the print job has been sent to printer.
   *
   * @since 10
   * @param jobId Indicates the specific print job.
   * @param callback The callback function for indcating the result of API execution.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function cancelPrintJob(jobId: string, callback: AsyncCallback<boolean>): void;
  function cancelPrintJob(jobId: string): Promise<boolean>;

  /**
   * Request preview of the print job.
   *
   * @since 10
   * @param jobInfo Indicates the information of print job.
   * @param callback The callback function for preview result from printer.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function requestPrintPreview(jobInfo: PrintJob, callback: (result: number) => void): void;
  function requestPrintPreview(jobInfo: PrintJob): Promise<number>;

  /**
   * Register event callback for the state change of printer.
   *
   * @since 10
   * @param printerStateChange Indicates state change of printer.
   * @param callback The callback function for state change of printer.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function on(type: 'printerStateChange', callback: (state: PrinterState, info: PrinterInfo) => void): void;

  /**
   * Unregister event callback for the state change of printer.
   *
   * @since 10
   * @param printerStateChange Indicates state change of printer.
   * @param callback The callback function for state change of printer.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function off(type: 'printerStateChange', callback?: (boolean) => void): void;

  /**
   * Register event callback for the state change of print job.
   *
   * @since 10
   * @param jobStateChange Indicates state change of print job.
   * @param callback The callback function for state change of print job.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function on(type: 'jobStateChange', callback: (state: PrintJobState, job: PrintJob) => void): void;

  /**
  * Unregister event callback for the state change of print job.
  *
  * @since 10
  * @param printerStateChange Indicates state change of print job.
  * @param callback The callback function for state change of print job.
  * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
  * @systemapi Hide this for inner system use.
  * @return -
  */
  function off(type: 'jobStateChange', callback?: (boolean) => void): void;

  /**
   * Register event callback for the information change of print extension.
   *
   * @since 10
   * @param extInfoChange Indicates information change of print extension.
   * @param callback The callback function for information change of print extension.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function on(type: 'extInfoChange', callback: (extensionId: string, info: string) => void): void;

  /**
  * Unregister event callback for the information change of print extension.
  *
  * @since 10
  * @param extInfoChange Indicates information change of print extension.
  * @param callback The callback function for information change of print extension.
  * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
  * @systemapi Hide this for inner system use.
  * @return -
  */
  function off(type: 'extInfoChange', callback?: (boolean) => void): void;

  /**
   * New printers have been found and notify Print SA.
   *
   * @since 10
   * @param printers Indicates new arrived printer lists.
   * @param callback The callback function for indcating the result of API execution.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function addPrinters(printers: Array<PrinterInfo>, callback: AsyncCallback<boolean>): void;
  function addPrinters(printers: Array<PrinterInfo>): Promise<boolean>;

  /**
   * Printers have been lost and notify Print SA.
   *
   * @since 10
   *
   * @param printerIds Indicates the lost printer lists.
   * @param callback The callback function for indcating the result of API execution.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function removePrinters(printerIds: Array<string>, callback: AsyncCallback<boolean>): void;
  function removePrinters(printerIds: Array<string>): Promise<boolean>;

  /**
   * Update the information of the specific printers
   *
   * @since 10
   * @param printers Indicates to be updated printer lists.
   * @param callback The callback function for indcating the result of API execution.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function updatePrinters(printers: Array<PrinterInfo>, callback: AsyncCallback<boolean>): void;
  function updatePrinters(printers: Array<PrinterInfo>): Promise<boolean>;

  /**
   * Notify Print SA the state of printer has been changed.
   *
   * @since 10
   * @param printerId Indicates id of the printer.
   * @param state Indicates new state of printer.
   * @param callback The callback function for indcating the result of API execution.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function updatePrinterState(printerId: string, state: PrinterState, callback: AsyncCallback<boolean>): void;
  function updatePrinterState(printerId: string, state: PrinterState): Promise<boolean>;

  /**
   * Notify Print SA the state of print job has been changed.
   *
   * @since 10
   * @param jobId Indicates id of the print job.
   * @param state Indicates new state of print job.
   * @param subState Indicates sub state of print job.
   * @param callback The callback function for indcating the result of API execution.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function updatePrintJobState(jobId: string, state: PrintJobState, subState: PrintJobSubState, callback: AsyncCallback<boolean>): void;
  function updatePrintJobState(jobId: string, state: PrintJobState, subState: PrintJobSubState): Promise<boolean>;

  /**
   * Notify Print SA the state of print extension has been changed.
   *
   * @since 10
   * @param info Indicates changed information of print extension.
   * @param callback The callback function for indcating the result of API execution.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function updateExtensionInfo(info: string, callback: AsyncCallback<boolean>): void;
  function updateExtensionInfo(info: string): Promise<boolean>;

  /**
   * Get all the printJobs in the queue.
   *
   * @since 10
   * @param callback The callback function for handling the printJob list found.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */

  function queryAllPrintJobs(callback: AsyncCallback<Array<PrintJob>>): void;
  function queryAllPrintJobs(): Promise<Array<PrintJob>>;

  /**
   * Get printJob by jobId.
   *
   * @since 10
   * @param callback The callback function for get printJob by jobId.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */

  function queryPrintJobById(jobId: string, callback: AsyncCallback<PrintJob>): void;
  function queryPrintJobById(jobId: string): Promise<PrintJob>;

  /**
   * query printerCapability by printerUri.
   *
   * @since 10
   * @param callback The callback function for query printerCapability by printerUri..
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */

  function queryPrinterCapabilityByUri(printerUri: string, callback: AsyncCallback<PrinterCapability>): void;
  function queryPrinterCapabilityByUri(printerUri: string): Promise<PrinterCapability>;

  /**
   * add printer to cups.
   *
   * @since 10
   * @param callback The callback function for add printer to cups.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */

  function addPrinterToCups(printerUri: string, printerName: string, printerMake :string, callback: AsyncCallback<boolean>): void;
  function addPrinterToCups(printerUri: string, printerName: string, printerMake :string): Promise<boolean>;

  /**
   * Start get print file.
   *
   * @since 11
   * @param jobId Indicates print job id.
   * @param printAttributes Indicates print attributes.
   * @param fd Indicates print file fd.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function startGetPrintFile(jobId: string, printAttributes: PrintAttributes, fd: number,
    onFileStateChanged: (state: PrintFileCreatedInfoCode) => void): void;

  /**
   * Notify print service the information.
   *
   * @since 11
   * @param jobId Indicates print job id.
   * @param type Indicates notify information.
   * @param callback The callback function for indcating the result of API execution.
   * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
   * @systemapi Hide this for inner system use.
   * @return -
   */
  function notifyPrintService(jobId: string, type: string, callback: AsyncCallback<void>);
  function notifyPrintService(jobId: string, type: string): Promise<void>;
}

export default print;