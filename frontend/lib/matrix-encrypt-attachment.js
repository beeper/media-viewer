function createCommonjsModule(fn, basedir, module) {
	return module = {
		path: basedir,
		exports: {},
		require: function (path, base) {
			return commonjsRequire(path, (base === undefined || base === null) ? module.path : base);
		}
	}, fn(module, module.exports), module.exports;
}

function commonjsRequire () {
	throw new Error('Dynamic requires are not currently supported by @rollup/plugin-commonjs');
}

var browserEncryptAttachment = createCommonjsModule(function (module, exports) {
(function(f){{module.exports=f();}})(function(){return (function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof commonjsRequire&&commonjsRequire;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t);}return n[i].exports}for(var u="function"==typeof commonjsRequire&&commonjsRequire,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
/*
Copyright 2021-2022 The Matrix.org Foundation C.I.C.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.decodeBase64 = exports.encodeBase64 = exports.decryptAttachment = exports.encryptAttachment = void 0;
function encryptAttachment(plaintextBuffer) {
    return __awaiter(this, void 0, void 0, function () {
        var ivArray, cryptoKey, exportedKey, ciphertextBuffer, sha256Buffer;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    ivArray = new Uint8Array(16);
                    window.crypto.getRandomValues(ivArray.subarray(0, 8));
                    return [4 /*yield*/, window.crypto.subtle.generateKey({ 'name': 'AES-CTR', 'length': 256 }, true, ['encrypt', 'decrypt'])];
                case 1:
                    cryptoKey = _a.sent();
                    return [4 /*yield*/, window.crypto.subtle.exportKey('jwk', cryptoKey)];
                case 2:
                    exportedKey = _a.sent();
                    return [4 /*yield*/, window.crypto.subtle.encrypt({ name: 'AES-CTR', counter: ivArray, length: 64 }, cryptoKey, plaintextBuffer)];
                case 3:
                    ciphertextBuffer = _a.sent();
                    return [4 /*yield*/, window.crypto.subtle.digest('SHA-256', ciphertextBuffer)];
                case 4:
                    sha256Buffer = _a.sent();
                    return [2 /*return*/, {
                            data: ciphertextBuffer,
                            info: {
                                v: 'v2',
                                key: exportedKey,
                                iv: encodeBase64(ivArray),
                                hashes: {
                                    sha256: encodeBase64(new Uint8Array(sha256Buffer)),
                                },
                            },
                        }];
            }
        });
    });
}
exports.encryptAttachment = encryptAttachment;
function decryptAttachment(ciphertextBuffer, info) {
    return __awaiter(this, void 0, void 0, function () {
        var ivArray, expectedSha256base64, cryptoKey, digestResult, counterLength;
        return __generator(this, function (_a) {
            switch (_a.label) {
                case 0:
                    if (info === undefined || info.key === undefined || info.iv === undefined
                        || info.hashes === undefined || info.hashes.sha256 === undefined) {
                        throw new Error('Invalid info. Missing info.key, info.iv or info.hashes.sha256 key');
                    }
                    if (info.v && !info.v.match(/^v[1-2]$/)) {
                        throw new Error("Unsupported protocol version: " + info.v);
                    }
                    ivArray = decodeBase64(info.iv);
                    expectedSha256base64 = info.hashes.sha256;
                    return [4 /*yield*/, window.crypto.subtle.importKey('jwk', info.key, { 'name': 'AES-CTR' }, false, ['encrypt', 'decrypt'])];
                case 1:
                    cryptoKey = _a.sent();
                    return [4 /*yield*/, window.crypto.subtle.digest('SHA-256', ciphertextBuffer)];
                case 2:
                    digestResult = _a.sent();
                    if (encodeBase64(new Uint8Array(digestResult)) != expectedSha256base64) {
                        throw new Error('Mismatched SHA-256 digest');
                    }
                    if (info.v == 'v1' || info.v == 'v2') {
                        // Version 1 and 2 use a 64 bit counter.
                        counterLength = 64;
                    }
                    else {
                        // Version 0 uses a 128 bit counter.
                        counterLength = 128;
                    }
                    return [2 /*return*/, window.crypto.subtle.decrypt({ name: 'AES-CTR', counter: ivArray, length: counterLength }, cryptoKey, ciphertextBuffer)];
            }
        });
    });
}
exports.decryptAttachment = decryptAttachment;
function encodeBase64(uint8Array) {
    // Misinterpt the Uint8Array as Latin-1.
    // window.btoa expects a unicode string with codepoints in the range 0-255.
    var latin1String = String.fromCharCode.apply(null, uint8Array);
    // Use the builtin base64 encoder.
    var paddedBase64 = window.btoa(latin1String);
    // Calculate the unpadded length.
    var inputLength = uint8Array.length;
    var outputLength = 4 * Math.floor((inputLength + 2) / 3) + (inputLength + 2) % 3 - 2;
    // Return the unpadded base64.
    return paddedBase64.slice(0, outputLength);
}
exports.encodeBase64 = encodeBase64;
function decodeBase64(base64) {
    // Pad the base64 up to the next multiple of 4.
    var paddedBase64 = base64 + '==='.slice(0, (4 - base64.length % 4) % 4);
    // Decode the base64 as a misinterpreted Latin-1 string.
    // window.atob returns a unicode string with codepoints in the range 0-255.
    var latin1String = window.atob(paddedBase64);
    // Encode the string as a Uint8Array as Latin-1.
    var uint8Array = new Uint8Array(latin1String.length);
    for (var i = 0; i < latin1String.length; i++) {
        uint8Array[i] = latin1String.charCodeAt(i);
    }
    return uint8Array;
}
exports.decodeBase64 = decodeBase64;

},{}]},{},[1])(1)
});

});

var decodeBase64 = browserEncryptAttachment.decodeBase64;
var decryptAttachment = browserEncryptAttachment.decryptAttachment;
var encodeBase64 = browserEncryptAttachment.encodeBase64;
export { decodeBase64, decryptAttachment, encodeBase64 };
