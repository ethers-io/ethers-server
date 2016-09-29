'use strict';

var crypto = require('crypto');
var http = require('http');
var https = require('https');

var BN = require('ethereumjs-util').BN;

function isHexString(value, length) {
    if (typeof(value) !== 'string' || !value.match(/^0x([0-9A-Fa-f][0-9A-Fa-f])*$/)) {
        return false;
    }
    if (length && value.length != 2 + length * 2) {
        return false;
    }

    return true;
}

function isAddress(value) {
    return isHexString(value, 20);
}

function hexOrBuffer(value, name) {
    if (Buffer.isBuffer(value)) {
        return value;
    }

    if (isHexString(value)) {
        value = value.substring(2);
        if (value.length % 2) { value = '0' + value; }
        return new Buffer(value, 'hex');
    }

    throw new Error('invalid ' + (name ? name: 'value'));
}

function ensureHexString(value, length) {
    if (!isHexString(value, length)) { throw new Error('invalid hex: ' + value); }
    return value;
}

function ensureAddress(value) {
    return ensureHexString(value, 20);
}

function ensureNumber(value) {
    if (typeof(value) !== 'number') { throw new Error('invalid number'); }
    return value;
}

function ensureBlockNumber(value) {
    if (value == null) { return 'latest'; }
    if (value !== 'latest' && value !== 'pending' && typeof(value) !== 'number') {
        throw new Error('invalid blockNumber');
    }
    return value;
}

var ensureTransaction = (function() {
    var properties = {
        to: ensureAddress,
        from: ensureAddress,

        data: ensureHexString,
        gasLimit: ensureHexString,
        gasPrice: ensureHexString,
        value: ensureHexString,

        nonce: ensureNumber,
    };

    return (function(transaction) {
        for (var key in transaction) {
            var func = properties[key];
            if (!func) { throw new Error('invalid transaction'); }
            func(transaction[key]);
        }
        return transaction;
    });
})();

function hexlify(value) {
    if (typeof(value) === 'string') {
        if (value.substring(0, 2) === '0x') { value = value.slice(2); }

        if (!value.match(/^[0-9A-Fa-f]*$/)) {
            throw new Error('invalid hex string');
        }

    } else if (typeof(value) === 'number') {
        if (parseInt(value) != value) {
            throw new Error('not an integer');
        }
        value = (new BN(value)).toString(16);

    } else if (Buffer.isBuffer(value)) {
        value = value.toString('hex');

    } else if (value && value.modulo) {

        // BigNumber
        value = value.toString(16);

    } else {
        console.log('cannot hexlify: ' + value)
        throw new Error('unknown type');
    }

    // Even-length pad it
    if ((value.length % 2) !== 0) { value = '0' + value; }

    // Prefix it with a 0x
    return '0x' + value;
}
/*
function getFileHash(filename, callback) {
    var hasher = crypto.createHash('sha256');

    var readBuffer = new Buffer(2 * (1 << 20));
    var readOffset = 0;
    fs.open(filename, function (error, fd) {
        if (error) {
            return callback(error);
        }

        var readChunk = function(error, bytesRead, buffer) {
            if (error) {
                return callback(error);;
            }

            if (bytesRead === 0) {
                return callback(null, hasher.digest());
            }

            if (buffer.length != bytesRead) { buffer = buffer.slice(0, bytesRead); }
            hasher.update(buffer);

            fs.read(fd, readBuffer, 0, readBuffer.length, readOffset, readChunk);
        }
        fs.read(fd, readBuffer, 0, readBuffer.length, readOffset, readChunk);
    });
}
*/
function fetchUrl(url) {
    var lib = (url.substring(0, 8) === 'https://') ? https: http;

    return new Promise(function(resolve, reject) {
        lib.get(url, function(response) {
            var data = new Buffer(0);

            response.on('data', function(chunk) {
                data = Buffer.concat([data, chunk])
            })

            response.on('end', function() {
                try {
                    resolve(data.toString());
                } catch (error) {
                    reject(error);
                }
            });
        }, function(error) {
            reject(error);
        });
    });
}
/*
function sha256(data) {
    if (!Buffer.isBuffer(data)) {
        throw new Error('data must be a Buffer');
    }

    var hasher = crypto.createHash('sha256');
    hasher.update(data);
    return hasher.digest();
}
*/
// @TODO: permit verbatim argument by using bare "--"
// @TODO: Copy flags; we modify the passed in value; bad encapsulation
function getopts(options, flags) {
    var error = false;

    var args = [];

    for (var i = 2; i < process.argv.length; i++) {
        var param = process.argv[i];
        if (param.substring(0, 2) !== '--') {
            args.push(param);
            continue;
        }
        var key = param.substring(2);

        if (flags[key] === false) {
            flags[key] = true;
            continue;
        }

        if (options[key] == undefined) {
            error = 'unknown option: ' + key;
            break;
        }

        var value = process.argv[++i];
        if (value === undefined) {
            error = 'missing value for option: ' + key;
            break;
        }

        if (options[key].push) {
            options[key].push(value);

        } else {
            options[key] = value;
        }
    }

    return {
        args: args,
        error: error,
        flags: flags,
        options: options,
    }
}

function defineProperty(object, name, value) {
    Object.defineProperty(object, name, {
        enumerable: true,
        value: value
    });
}

function defineValue(object, name, value) {
    Object.defineProperty(object, name, {
        enumerable: true,
        get: function() { return value; }
    });
    return function(newValue) { value = newValue; }
}

function getWeb3Promise(web3) {
/*
    var callError = null;
    try {
        throw new Error('fencepost');
    } catch (error) {
        callError = error;
    }
*/
    return (function (method) {
        var params = Array.prototype.slice.call(arguments, 1);
        return new Promise(function(resolve, reject) {
            params.push(function(error, result) {
                if (error) {
                    error._web3 = params.slice();
                    error._web3.unshift(method);
                    //console.log(error);
                    //console.trace(callError);
                    //self.emit('web3Error', wrapError(error));
                    return reject(error);
                }
                resolve(result);
            });
            web3.eth[method].apply(web3, params);
        });
    });
}

module.exports = {
    isAddress: isAddress,
    isHexString: isHexString,

    ensureAddress: ensureAddress,
    ensureHexString: ensureHexString,
    ensureNumber: ensureNumber,
    ensureBlockNumber: ensureBlockNumber,
    ensureTransaction: ensureTransaction,

    hexOrBuffer: hexOrBuffer,

    defineProperty: defineProperty,
    defineValue: defineValue,

    getopts: getopts,
    fetchUrl: fetchUrl,

    hexlify: hexlify,

    getWeb3Promise: getWeb3Promise,
    //getFileHash: getFileHash,
    //sha256: sha256,
};
