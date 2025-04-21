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

interface BaseContext {
    readonly area: int;
    readonly filesDir: string;
    readonly tempDir: string;
}

abstract class Context implements BaseContext{
    area: int = 0;
    filesDir: string = "";
    tempDir: string = "";
}

type Callback = ()=> void;

class Result<T, E>{
  result:T;
  error:E;
  constructor(result: T , error: E) {
      this.result = result;
      this.error = error;
  }
}

type AsyncCallback<T> = (err: BusinessError<T>, data: T)=> void;

class BusinessError<T = void> {
    code: number;
    data: T;
    constructor(code: number = 0, data?: T) {
        this.code = code;
        this.data = data!;
    }
}

class printAni {
    native static printAsyncCallback(files: Array<string>): int;
    native static on(type: string) : int;
    native static off(type: string) : int;
}

function syncFunction(files: Array<string>):number{
    let ret : number = printAni.printAsyncCallback(files)
    return ret;
}

function syncOn(type: string):number{
    let ret : number = printAni.on(type)
    return ret;
}

function syncOff(type: string):number{
    let ret : number = printAni.off(type)
    return ret;
}

export default namespace print {
    loadLibrary("print_ani");

    export interface PrintTask {
        on(type: 'block' | 'succeed' | 'fail' | 'cancel', callback: Callback): void;
        off(type: 'block' | 'succeed' | 'fail' | 'cancel', callback?: Callback): void;
    }

    class PrintTaskImpl implements PrintTask {
        on(type: 'block' | 'succeed' | 'fail' | 'cancel', callback: Callback): void {
            printAni.on(type);
            callback();
        }
        off(type: 'block' | 'succeed' | 'fail' | 'cancel', callback?: Callback): void {
            printAni.off(type);
            if (callback != undefined) {
                callback();
            }
        }
    }

    export function print(files: Array<string>, callback: AsyncCallback<PrintTask>): void {
        printAni.printAsyncCallback(files);
        let err = new BusinessError<PrintTask>;
        let data = new PrintTaskImpl;
        callback(err, data);
    }

    export function print(files: Array<string>, context: Context): Promise<PrintTask> {
        printAni.printAsyncCallback(files);
        let printPromise = new Promise<PrintTask>((resolve: (v: PrintTask) => void) => {
        });
        return printPromise;
    }

    export interface PrintPageRange {
        startPage?: number;
        endPage?: number;
        pages?: Array<number>;
    }

    export interface PrintAttributes {
        copyNumber?: number;
        pageRange?: PrintPageRange;
        pageSize?: PrintPageSize | PrintPageType;
        directionMode?: PrintDirectionMode;
        colorMode?: PrintColorMode;
        duplexMode?: PrintDuplexMode;
    }

    export interface PrintDocumentAdapter {
        onStartLayoutWrite(jobId: string, oldAttrs: PrintAttributes, newAttrs: PrintAttributes, fd: number,
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
        width: number;
        height: number;
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
}
