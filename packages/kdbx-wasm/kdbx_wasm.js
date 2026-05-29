import * as wasm from "./kdbx_wasm_bg.wasm";
import { __wbg_set_wasm } from "./kdbx_wasm_bg.js";

__wbg_set_wasm(wasm);
wasm.__wbindgen_start();
export {
    JsFileInfo, JsHeaderInfo, JsKdfParams, JsMetadata, KdbxDatabase, getFileInfo, isKdbxFile, start
} from "./kdbx_wasm_bg.js";
