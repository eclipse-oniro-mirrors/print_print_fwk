// @ts-nocheck

/**
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
import { describe, it, expect } from "deccjsunit/index.ets";
import print from '@ohos.print';

export default function requestPrintJsunit() {
    describe('requestPrintTest', function () {
        let files = ['D:/dev/a.docx']
        let keyStr = 'print demo ';
        let PrintJobState = 2
        let jobId = 1
        let PrinterState = 1
        let uri = 'www.baidu.com'

        let PrinterRange = {
            startPage: 1, // start page of sequence
            endPage: 4, // end page of sequence
            pages: [1, 4], // discrete page of sequence
        }
        let PrinterPageSizeArr = [
            {
                id: 1, // page size id
                name: 'string', // page size name
                width: 200, // unit: milimeter
                height: 200, // unit: milimeter
            }
        ]
        let PrinterPageSize = {
            id: 1, // page size id
            name: 'string', // page size name
            width: 200, // unit: milimeter
            height: 200, // unit: milimeter
        }

        let PrintMargin = {
            top: 1, // top margin
            bottom: 2, // bottom margin
            left: 1, // left side margin
            right: 1, // right side margin
        }
        let PreviewAttribute = {
            previewRange: PrinterRange, // preview page range
            result: 'string', // preview file
        }
        let PrintJob = {
            files: ['D:/dev/a.docx'],
            jobId: 3,
            printerId: 2, // printer id to take charge of printing
            jobState: PrinterState, // current print job state
            copyNumber: 3, // copies of document list
            pageRange: PrinterRange,
            isSequential: false, // sequential print
            pageSize: PrinterPageSize, // the selected page size
            isLandscape: false, // vertical printing
            colorMode: 1, // color mode
            duplexMode: 1, // duplex mode
            margin: PrintMargin, // current margin setting
            preview: PreviewAttribute, // preview setting
        }

        let PrinterResolutionArr = [{
                                        id: 2, // resolution id
                                        horizontalDpi: 2, // horizontal DPI
                                        verticalDpi: 1, // vertical DPI
                                    }]
        let PrinterResolution = {
            id: 2, // resolution id
            horizontalDpi: 2, // horizontal DPI
            verticalDpi: 1, // vertical DPI
        }
        let PrinterCapability = {
            /* Printer Capability */
            minMargin: PrintMargin, // min margin of printer
            pageSize: PrinterPageSizeArr, // the page size list supported by the printer
            resolution: PrinterResolutionArr, // the resolution list supported by the printer
            colorMode: 1, // color mode
            duplexMode: 2, // duplex mode
        }
        let PrinterInfo = {
            printerId: 1, // printer id
            printerName: 'string', // printer name
            printerIcon: 1, // resource id of printer icon
            printerState: 1, // current printer state
            description: 'string', // printer description
            capability: PrinterCapability,
        }
        let PrinterInfo1 = {
            printerId: 2, // printer id
            printerName: 'char', // printer name
            printerIcon: 2, // resource id of printer icon
            printerState: 2, // current printer state
            description: 'char', // printer description
            capability: PrinterCapability,
        }
        let PrinterInfoArray = [PrinterInfo, PrinterInfo1]

        let file = ['11111', '123123', '12312']
        let printTaskObj = null
        let context
        let extensionList = [1, 2, 3, 4];
        let printerId = 3;
        let PrinterInfo2 = {
            printerName: 'string', // printer name
            printerIcon: 1, // resource id of printer icon
            printerState: 1, // current printer state
            description: 'string', // printer description
        }

        let TAG = "";

        /**
         * @tc.number  requestPrint_test_0100
         * @tc.name    addPrinters: New printers have been found and notify Print SA (by Promise)
         * @tc.desc    Function test
         * @tc.level   Level 0
         */
        it('requestPrint_test_0100', 0, async function (done) {
            TAG = "requestPrint_test_0100";
            await print.addPrinters(PrinterInfoArray).then((data) => {
                console.info(TAG + " result: " + JSON.stringify(data));
                expect(typeof (data)).assertEqual('boolean');
                expect(data).assertEqual(true);
                done();
            }).catch((error) => {
                console.info(TAG + " err: " + JSON.stringify(error));
                expect(false).assertTrue();
                done();
            });
        });

        /**
         * @tc.number  requestPrint_test_0200
         * @tc.name    addPrinters: New printers have been found and notify Print SA (by callback)
         * @tc.desc    Function test
         * @tc.level   Level 0
         */
        it('requestPrint_test_0200', 0, async function (done) {
            TAG = "requestPrint_test_0200";
            await print.addPrinters(PrinterInfoArray, (err, data) => {
                if (err) {
                    console.info(TAG + " err: " + JSON.stringify(err));
                    expect(false).assertTrue();
                } else {
                    console.info(TAG + " result: " + JSON.stringify(data));
                    expect(typeof (data)).assertEqual('boolean');
                    expect(data).assertEqual(true);
                    done();
                }
            });
        });

        /**
         * @tc.number  requestPrint_test_0300
         * @tc.name    removePrinters: Printers have been lost and notify Print SA (by Promise)
         * @tc.desc    Function test
         * @tc.level   Level 0
         */
        it('requestPrint_test_0300', 0, async function (done) {
            TAG = "requestPrint_test_0300";
            await print.removePrinters(PrinterInfoArray).then((data) => {
                console.info(TAG + " removePrinters result: " + JSON.stringify(data));
                expect(typeof (data)).assertEqual('boolean');
                expect(data).assertEqual(true);
                done();
            }).catch((error) => {
                console.info(TAG + " removePrinters err: " + JSON.stringify(error));
                expect(false).assertTrue();
                done();
            });
        });

        /**
         * @tc.number  requestPrint_test_0400
         * @tc.name    removePrinters: Printers have been lost and notify Print SA (by callback)
         * @tc.desc    Function test
         * @tc.level   Level 0
         */
        it('requestPrint_test_0400', 0, async function (done) {
            TAG = "requestPrint_test_0400";
            await print.removePrinters(PrinterInfoArray, (err, data) => {
                if (err) {
                    console.info(TAG + " removePrinters err: " + JSON.stringify(err));
                    expect(false).assertTrue();
                } else {
                    console.info(TAG + " removePrinters result: " + JSON.stringify(data));
                    expect(typeof (data)).assertEqual('boolean');
                    expect(data).assertEqual(true);
                    done();
                }
            });
        });

        /**
         * @tc.number  requestPrint_test_0500
         * @tc.name    updatePrinterState: Notify Print SA the state of printer has been changed (by Promise)
         * @tc.desc    Function test
         * @tc.level   Level 0
         */
        it('requestPrint_test_0500', 0, async function (done) {
            TAG = "requestPrint_test_0500";
            await print.updatePrinterState(printerId, PrinterState).then((data) => {
                console.info(TAG + " result: " + JSON.stringify(data));
                expect(typeof (data)).assertEqual('boolean');
                expect(data).assertEqual(true);
                done();
            }).catch((error) => {
                console.info(TAG + " err: " + JSON.stringify(error));
                expect(false).assertTrue();
                done();
            });
        });

        /**
         * @tc.number  requestPrint_test_0600
         * @tc.name    updatePrinterState: Notify Print SA the state of printer has been changed (by callback)
         * @tc.desc    Function test
         * @tc.level   Level 0
         */
        it('requestPrint_test_0600', 0, async function (done) {
            TAG = "requestPrint_test_0600";
            await print.updatePrinterState(printerId, PrinterState, (err, data) => {
                if (err) {
                    console.info(TAG + " err: " + JSON.stringify(err));
                    expect(false).assertTrue();
                } else {
                    console.info(TAG + " result: " + JSON.stringify(data));
                    expect(typeof (data)).assertEqual('boolean');
                    expect(data).assertEqual(true);
                    done();
                }
            });
        });

        /**
         * @tc.number  requestPrint_test_0700
         * @tc.name    updatePrintJobState: Notify Print SA the state of print job has been changed (by Promise)
         * @tc.desc    Function test
         * @tc.level   Level 0
         */
        it('requestPrint_test_0700', 0, async function (done) {
            TAG = "requestPrint_test_0700";
            await print.updatePrintJobState(jobId, PrintJobState).then((data) => {
                console.info(TAG + " result: " + JSON.stringify(data));
                expect(typeof (data)).assertEqual('boolean');
                expect(data).assertEqual(true);
                done();
            }).catch((error) => {
                console.info(TAG + " err: " + JSON.stringify(error));
                expect(false).assertTrue();
                done();
            });
        });

        /**
         * @tc.number  requestPrint_test_0800
         * @tc.name    updatePrintJobState: Notify Print SA the state of print job has been changed (by callback)
         * @tc.desc    Function test
         * @tc.level   Level 0
         */
        it('requestPrint_test_0800', 0, async function (done) {
            TAG = "requestPrint_test_0800";
            await print.updatePrintJobState(jobId, PrintJobState, (err, data) => {
                if (err) {
                    console.info(TAG + " err: " + JSON.stringify(err));
                    expect(false).assertTrue();
                } else {
                    console.info(TAG + " result: " + JSON.stringify(data));
                    expect(typeof (data)).assertEqual('boolean');
                    expect(data).assertEqual(true);
                    done();
                }
            });
        });
    })
}