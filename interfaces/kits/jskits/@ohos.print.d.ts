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
import {AsyncCallback} from './basic';

/**
 * System print
 * @sysCap SystemCapability.Print.print
 * @import import print from '@ohos.app.print';
 * @since 9
 */
declare namespace print {
	
	interface PrintTask {
		/**
		 * Register event callback when the current print task is in process.
		 * @since 9
		 * @param type block Indicates the print task has been blocked.
		 *  	  type success Indicates the print task succeed. .
		 * 	      type fail Indicates the print task has completed with failure.
		 *        type cancel Indicates the print task has been cancelled.		 
		 * @param callback The callback function for print task change event
		 * @permission {@code ohos.permission.PRINT}
		 * @return -
		 */	
		on(type:'block'| 'success'|  'fail' | 'cancel', callback:() => void): void;
		
		/**
		 * Unregister event callback when the current print task is in process.
		 * @since 9
		 * @param type block Indicates the print task has been blocked.
		 *  	  type success Indicates the print task succeed. .
		 * 	      type fail Indicates the print task has completed with failure.
		 *        type cancel Indicates the print task has been cancelled.		 
		 * @param callback The callback function for print task change event
		 * @permission {@code ohos.permission.PRINT}
		 * @return -
		 */			
		off(type:'block'| 'success'|  'fail' | 'cancel', callback?:() => void): void;
	}
	
	/**
	 * Start new print task for App.
	 * @since 9
	 * @param files Indicates the document list to be printed. 
	 * @param callback The callback function for print task
	 * @permission {@code ohos.permission.PRINT}
	 * @return -
	 */
	function print(files: Array<string>, callback: AsyncCallback<PrintTask>): void;
	function print(files: Array<string>): Promise<PrintTask>;

	interface PrintMargin {
		top: number;	// top margin
		bottom: number;	// bottom margin
		left: number;	// left side margin
		right: number;	// right side margin
	}
	
	interface PrinterRange {
		startPage: number;	// start page of sequence
		endPage: number;	// end page of sequence
		pages: Array<number>;	// discrete page of sequence
	}
	interface PreviewAttribute {
		previewRange: PrinterRange;	// preview page range
		result: string;				// preview file
	}
	
	interface PrinterResolution {
		id: number;					// resolution id
		horizontalDpi: number		// horizontal DPI
		verticalDpi: number;		// vertical DPI
	}
	
	interface PrinterPageSize {
		id: number;		// page size id
		name: string;	// page size name
		width: number;	// unit: milimeter
		height: number;	// unit: milimeter
	}
	
	interface PrinterCapability {
		/* Printer Capability */
		minMargin: PrintMargin;	// min margin of printer
		pageSize: Array<PrinterPageSize>;		// the page size list supported by the printer
		resolution: Array<PrinterResolution>;	// the resolution list supported by the printer
		colorMode: number;						// color mode
		duplexMode: number;						// duplex mode
	}

	interface PrinterInfo {
		printerId: number;			// printer id
		printerName: string;		// printer name
		printerIcon: number;		// resource id of printer icon
		printerState: PrinterState;	// current printer state
		description: string;		// printer description
		capability: PrinterCapability;	// printer capability
	}
	
	interface PrintJob {
		files: Array<string>;		// document list to be printed
		/* job attributes */
		printerId: number;			// printer id to take charge of printing
		jobState: PrintJobState;	// current print job state
		copyNumber: number;			// copies of document list
		pageRange: PrinterRange;	// range size to be printed
		isSequential?: boolean;		// sequential print
		pageSize?: PrinterPageSize;	// the selected page size
		isLandscape?: boolean;			// vertical printing
		colorMode?: number;			// color mode
		duplexMode?: number;		// duplex mode
		margin?: PrintMargin;		// current margin setting
		preview?: PreviewAttribute;	// preview setting
	}

	enum PrinterState {
		PRINTER_ADD = 1,  // new printers arrival
		PRINTER_REMOVED = 2, // printers lost
		PRINTER_IDLE = 3,  // printer idle
		PRINTER_PRINTING = 4, // printer is working
		PRINTER_BLOCK = 5,	 // printer has been blocked
		PRINTER_BUSY = 6,	// printer is busy
		PRINTER_FAULT = 7	// printer failure
	}

	enum PrintJobState {
		PRINT_JOB_INIT = 1,		// initial state of print job
		PRINT_JOB_START = 2,	// start print job
		PRINT_JOB_PRINTING = 3,	// printing
		PRINT_JOB_BLOCK = 4,	// print job has been blocked
		PRINT_JOB_COMPLETE = 5,	// print completed
		PRINT_JOB_CANCEL = 6	// print job has been cancelled
	}
	
	interface PrinterExtensionInfo extends ExtensionAbilityInfo{
		extensionId: number;   // extesion id of printer extension
		vendorId: number;	  // vendor id of extension
		vendorName: string;	  // vendor name
		vendorIcon: number;	  // resource id of vendor
		version: string;	 // version of current printer extension
	}
	
	/**
	 * Get all printer extensin installed.
	 *
	 * @since 9
	 * @param callback The callback function for handling the extension list found
	 * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
     * @systemapi Hide this for inner system use.
	 * @return -
	 */
	function queryExtensionAbilityInfos(callback: AsyncCallback<Array<PrinterExtensionInfo>>): void;
	function queryExtensionAbilityInfos(): Promise<Array<PrinterExtensionInfo>>;
	
	/**
	 * Load the specific printer extension and start to discover printer.
	 *
	 * @since 9
	 * @param extensionList Indicates the list of printer extension
	 *        empty list of extensionList Indicates to find printer with all installed extension
	 * @param callback The callback function for indcating the result of API execution
	 * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
     * @systemapi Hide this for inner system use.
	 * @return -
	 */	
	function startDiscoverPrinter(extensionList:Array<number>, callback: AsyncCallback<boolean>): void;
	function startDiscoverPrinter(extensionList:Array<number>): Promise<boolean>;
	
	/**
	 * Stop discovering the printer with specific printer extension.
	 *
	 * @since 9
	 * @param extensionList Indicates the list of printer extension
	 *        empty list of extensionList Indicates to find printer with all installed extension
	 * @param callback The callback function for indcating the result of API execution
	 * @permission {@ohos.permission.MANAGE_PRINT_JOB}
     * @systemapi Hide this for inner system use.
	 * @return -
	 */	
	function stopDiscoverPrinter(callback: AsyncCallback<boolean>): void;
	function stopDiscoverPrinter(): Promise<boolean>;
	
	/**
	 * Start print job.
	 *
	 * @since 9
	 * @param jobInfo Indicates the information of print job.
	 * @param callback The callback function for indcating the result of API execution
	 * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
     * @systemapi Hide this for inner system use.
	 * @return -
	 */	
	function startPrintJob(jobinfo:PrintJob, callback:AsyncCallback<boolean>):void;
	function startPrintJob(jobinfo:PrintJob): Promise<boolean>;
	
	/**
	 * Cancel the print job has been sent to printer.
	 *
	 * @since 9
	 * @param jobInfo Indicates the information of print job.
	 * @param callback The callback function for indcating the result of API execution
	 * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
     * @systemapi Hide this for inner system use.
	 * @return -
	 */
	function cancelPrintJob(jobinfo:PrintJob, callback:AsyncCallback<boolean>):void;
	function cancelPrintJob(jobinfo:PrintJob): Promise<boolean>;	
	
	/**
	 * Request preview of the print job.
	 *
	 * @since 9
	 * @param jobInfo Indicates the information of print job.
	 * @param callback The callback function for preview result from printer
	 * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
     * @systemapi Hide this for inner system use.
	 * @return -
	 */
	function requestPrintPreview(jobinfo:PrintJob,  callback:(result:string) => void): void;
	function requestPrintPreview(jobinfo:PrintJob): Promise<string>;
	
	/**
	 * Query capability for the specific printer.
	 *
	 * @since 9
	 * @param printerId Indicates id of the printer
	 * @param callback The callback function for capability from printer
	 * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
     * @systemapi Hide this for inner system use.
	 * @return -
	 */
	function queryPrinterCapability(printerId:number, callback:AsyncCallback<PrinterCapability>):void;
	function queryPrinterCapability(printerId:number): Promise<PrinterCapability>
	
	/**
	 * Register event callback for the state change of printer.
	 *
	 * @since 9
	 * @param printerStateChange Indicates state change of printer
	 * @param callback The callback function for state change of printer.
	 * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
     * @systemapi Hide this for inner system use.
	 * @return -
	 */	
	on(type: 'printerStateChange', callback:(state: PrinterState, info: PrinterInfo) => void): void;
	off(type: 'printerStateChange', callback:(boolean) => void): void;
	
	/**
	 * Register event callback for the specific print job.
	 *
	 * @since 9
	 * @param jobStateChange Indicates state change of print job
	 * @param callback The callback function for state change of print job.
	 * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
     * @systemapi Hide this for inner system use.
	 * @return -
	 */	
	on(type: 'jobStateChange', callback:(state: PrintJobState, job: PrintJob) => void): void;
	off(type: 'jobStateChange', callback:(boolean) => void): void;
	
	/**
	 * New printers have been found and notify Print SA.
	 *
	 * @since 9
	 * @param printers Indicates new arrived printer lists.
	 * @param callback The callback function for indcating the result of API execution
	 * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
     * @systemapi Hide this for inner system use.
	 * @return -
	 */
	function addPrinters(printers: Array<PrinterInfo>, callback: AsyncCallback<boolean>): void;
	function addPrinters(printers: Array<PrinterInfo>): Promise<boolean>;
	
	/**
	 * Printers have been lost and notify Print SA.
	 *
	 * @since 9
	 * 
	 * @param printerId Indicates id of the printer
	 * @param callback The callback function for indcating the result of API execution
	 * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
     * @systemapi Hide this for inner system use.
	 * @return -
	 */	
	function removePrinters(printers: Array<PrinterInfo>, callback: AsyncCallback<boolean>): void;
	function removePrinters(printers: Array<PrinterInfo>): Promise<boolean>;
	
	/**
	 * Notify Print SA the state of printer has been changed.
	 *
	 * @since 9
	 * @param state Indicates new printer state	 
	 * @param printerId Indicates id of the printer
	 * @param callback The callback function for indcating the result of API execution
	 * @permission {@code ohos.permission.MANAGE_PRINT_JOB}	 
     * @systemapi Hide this for inner system use.
	 * @return -
	 */	
	function updatePrinterState(state: PrinterState, printerId: number, callback: AsyncCallback<boolean>): void;
	function updatePrinterState(state: PrinterState, printerId: number): Promise<boolean>;
	
	/**
	 * Notify Print SA the state of print job has been changed.
	 *
	 * @since 9
	 * @param state Indicates new printer state	 
	 * @param jobId Indicates id of the print job
	 * @param callback The callback function for indcating the result of API execution
	 * @permission {@code ohos.permission.MANAGE_PRINT_JOB}
     * @systemapi Hide this for inner system use.
	 * @return -
	 */
	function updatePrintJobState(state: PrintJobState, jobId: number, callback: AsyncCallback<boolean>): void;
	function updatePrintJobState(state: PrintJobState, jobId: number): Promise<boolean>;	
}

export default print;
