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

class printNative {
    static { loadLibrary("aniprintmodule.z") }
    // 声明 native 方法
    native printAsyncCallback(files: Array<string>): int;
    native on(type: string) : int;
    native off(type: string) : int;
}

function syncFunction(files: Array<string>):number{
    console.println("syncFunction");
    let obj : printNative = new printNative();
    let ret : number = obj.printAsyncCallback(files)
    // let ret : number = 1;
    return ret;
}

function syncOn(type: string):number{
    console.println("syncOn");
    let obj : printNative = new printNative();
    let ret : number = obj.on(type)
    // let ret : number = 1;
    return ret;
}

function syncOff(type: string):number{
    console.println("syncOff");
    let obj : printNative = new printNative();
    let ret : number = obj.off(type)
    // let ret : number = 1;
    return ret;
}

export namespace print {
    export interface PrintTask {
        on(type: 'block' | 'succeed' | 'fail' | 'cancel', callback: Callback): void;
        off(type: 'block' | 'succeed' | 'fail' | 'cancel', callback?: Callback): void;
    }

    class PrintTaskImpl implements PrintTask {
        on(type: 'block' | 'succeed' | 'fail' | 'cancel', callback: Callback): void {
            let taskAsyn = taskpool.execute(syncOn, type);
            taskAsyn.then((e : NullishType) => {
                let r = e as number;
                console.println("r = " + r);
                callback();
            });
        }
        off(type: 'block' | 'succeed' | 'fail' | 'cancel', callback?: Callback): void {
            let taskAsyn = taskpool.execute(syncOff, type);
            taskAsyn.then((e : NullishType) => {
                let r = e as number;
                console.println("r = " + r);
                if (callback) {
                    callback();
                }
            });
        }
    }

    // print 接口的实现
    export function print(files: Array<string>, callback: AsyncCallback<PrintTask>): void {
        let taskAsyn = taskpool.execute(syncFunction, files);
        taskAsyn.then((e : NullishType) => {
            let r = e as number;
            console.println(r);
            let data  = new PrintTaskImpl();
            let err = new BusinessError<PrintTask>(0, data);
            callback(err, data);
        });
    }
}

function main() {
    let files:Array<string> = new Array<string>(2);
    files[0] = "file://data/print/a.png"
    files[1] = "file://data/print/b.png"

    print.print(files, (err, printTask) => {
        console.println("enter print callback");
        console.println("err.code = " + err.code);
        printTask.on('succeed', () => {
            console.println('succeed');
        })
    })
    let n = new printNative();
    let num = n.off("123");
    console.println('off = ' + num);
}
