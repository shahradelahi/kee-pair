"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
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
exports.KeePair = exports.algorithms = void 0;
var crypto = require("crypto");
exports.algorithms = [
    {
        sid: 'rsa',
        name: 'rsa',
        module_length: 2048,
        public_encoding_type: 'spki',
        public_encoding_format: 'der',
        private_encoding_type: 'pkcs8',
        private_encoding_format: 'der'
    },
    {
        sid: 'dsa',
        name: 'dsa',
        module_length: 2048,
        divisor_length: 256,
        public_encoding_type: 'spki',
        public_encoding_format: 'der',
        private_encoding_type: 'pkcs8',
        private_encoding_format: 'der'
    },
    {
        sid: 'secp256k1',
        name: 'ec',
        named_curve: 'secp256k1',
        public_encoding_type: 'spki',
        public_encoding_format: 'der',
        private_encoding_type: 'sec1',
        private_encoding_format: 'der'
    },
];
var KeePair = /** @class */ (function () {
    function KeePair(publicKey, privateKey, algorithm) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        this.algorithm = algorithm;
    }
    KeePair.generate = function (algorithm) {
        return __awaiter(this, void 0, void 0, function () {
            var algorithmData, _a, publicKey, privateKey;
            return __generator(this, function (_b) {
                algorithmData = exports.algorithms.find(function (a) { return a.sid === algorithm.toLowerCase(); });
                if (!algorithmData) {
                    throw new Error("Algorithm \"".concat(algorithm, "\" is not supported."));
                }
                _a = crypto.generateKeyPairSync(algorithmData.name, __assign(__assign({ modulusLength: algorithmData.module_length }, (algorithmData.named_curve !== null ? { namedCurve: algorithmData.named_curve } : {})), (algorithmData.divisor_length !== null ? { divisorLength: algorithmData.divisor_length } : {}))), publicKey = _a.publicKey, privateKey = _a.privateKey;
                return [2 /*return*/, new KeePair(publicKey.export({
                        type: algorithmData.public_encoding_type,
                        format: (algorithmData.public_encoding_format)
                    }).toString('hex'), privateKey.export({
                        type: algorithmData.private_encoding_type,
                        format: (algorithmData.private_encoding_format)
                    }).toString('hex'), algorithm)];
            });
        });
    };
    KeePair.fromPrivateKey = function (privateKey, algorithm) {
        return __awaiter(this, void 0, void 0, function () {
            var algorithmData, key, publicKey;
            return __generator(this, function (_a) {
                algorithmData = exports.algorithms.find(function (a) { return a.sid === algorithm.toLowerCase(); });
                if (!algorithmData) {
                    throw new Error("Algorithm for private key \"".concat(privateKey, "\" is not supported."));
                }
                key = crypto.createPrivateKey({
                    key: Buffer.from(privateKey, 'hex'),
                    type: algorithmData.private_encoding_type,
                    format: (algorithmData.private_encoding_format),
                });
                publicKey = crypto.createPublicKey(key).export({
                    type: algorithmData.public_encoding_type,
                    format: (algorithmData.public_encoding_format)
                }).toString('hex');
                return [2 /*return*/, new KeePair(publicKey, privateKey, algorithm)];
            });
        });
    };
    KeePair.prototype.sign = function (data, algorithm) {
        var _this = this;
        var algorithmData = exports.algorithms.find(function (a) { return a.sid === _this.algorithm.toLowerCase(); });
        if (!algorithmData) {
            throw new Error("Algorithm \"".concat(this.algorithm, "\" is not supported."));
        }
        var key = crypto.createPrivateKey({
            key: Buffer.from(this.privateKey, 'hex'),
            type: algorithmData.private_encoding_type,
            format: (algorithmData.private_encoding_format),
        });
        return crypto
            .createSign(algorithm.toLowerCase())
            .update(data)
            .sign(key)
            .toString('hex');
    };
    KeePair.prototype.verify = function (data, signature, algorithm) {
        var _this = this;
        var algorithmData = exports.algorithms.find(function (a) { return a.sid === _this.algorithm.toLowerCase(); });
        if (!algorithmData) {
            throw new Error("Algorithm \"".concat(this.algorithm, "\" is not supported."));
        }
        var key = crypto.createPublicKey({
            key: Buffer.from(this.publicKey, 'hex'),
            type: (algorithmData.public_encoding_type),
            format: (algorithmData.public_encoding_format),
        });
        return crypto
            .createVerify(algorithm.toLowerCase())
            .update(data)
            .verify(key, Buffer.from(signature, 'hex'));
    };
    return KeePair;
}());
exports.KeePair = KeePair;
