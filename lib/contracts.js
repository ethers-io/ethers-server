/**
 *  This module is mainly for looking up source code by bytecode
 *
 *  Idea 2
 *    - Map ("S" + sha3(source) => (gistId, url))
 *    - Map ("A" + sha(address, bytecode, network) => (gistId, url))
 *
 *    - Optionally include a 'source' attribute in "a" keys if not from ethers.io?
 */

var awsSdk = require('aws-sdk');
var ethereumUtil = require('ethereumjs-util');
var GitHubAPI = require('github');

var version = require('../package.json').version;
var util = require('./util.js');


// http://ethereum.stackexchange.com/questions/760/how-is-the-address-of-an-ethereum-contract-computed
function getContractAddress(transaction) {
    var sender = '0x' + transaction.from.toString('hex');
    var nonce = '0x' + transaction.nonce.toString('hex');
    return '0x' + ethereumUtil.sha3(ethereumUtil.rlp.encode([sender, nonce])).slice(12).toString('hex');
}

function getBuffer(object) {
    if (typeof(object) === 'string') {
        if (object.slice(0, 2) === '0x') {
            object = object.slice(2);
        }
        if (!object.match(/^([0-9A-Fa-f][0-9A-Fa-f])*$/)) {
            throw new Error('invalid hex');
        }
        return (new Buffer(object, 'hex'));

    } else if (Buffer.isBuffer(object)) {
        return object;
    }

    throw new Error('invalid hex');
}

function setupMethods (soljson){

    var compileJSON = soljson.cwrap("compileJSON", "string", ["string", "number"]);
    var compileJSONMulti =
        '_compileJSONMulti' in soljson ?
        soljson.cwrap("compileJSONMulti", "string", ["string", "number"]) :
        null;

    var compileJSONCallback = null;
    if ('_compileJSONCallback' in soljson)
    {
        /// TODO: Allocating memory and copying the strings over
        /// to the emscripten runtime does not seem to work.
        var copyString = function(str, ptr) {
            var buffer = soljson._malloc(str.length + 1);
            soljson.writeStringToMemory(str, buffer);
            soljson.setValue(ptr, buffer, '*');
        };
        var wrapCallback = function(callback) {
            return soljson.Runtime.addFunction(function(path, contents, error) {
                // path is char*, contents is char**, error is char**
                // TODO copying the results does not seem to work.
                // This is not too bad, because most of the requests
                // cannot be answered synchronously anyway.
                var result = callback(soljson.Pointer_stringify(path));
                if (typeof(result.contents) === typeof(''))
                    copyString(result.contents, contents);
                if (typeof(result.error) === typeof(''))
                    copyString(result.error, error);
            });
        };
        var compileInternal = soljson.cwrap("compileJSONCallback", "string", ["string", "number", "number"]);
        compileJSONCallback = function(input, optimize, readCallback) {
            var cb = wrapCallback(readCallback);
            var output = compileInternal(input, optimize, cb);
            soljson.Runtime.removeFunction(cb);
            return output;
        };
    }

    var compile = function(input, optimise, callback) {
        if (!optimise) { console.log('WARNING: optimise disabled'); }

        var result = null;
        if (callback !== undefined && compileJSONCallback !== null) {
            result = compileJSONCallback(JSON.stringify(input), optimise, function () {});
        } else if (typeof(input) != typeof('') && compileJSONMulti !== null) {
            result = compileJSONMulti(JSON.stringify(input), optimise);
        } else {
            result = compileJSON(input.sources['contract.solc'], optimise);
        }

        result = JSON.parse(result);

        if (result && result.contracts) {
            console.log('Contracts:', Object.keys(result.contracts));
        }

        setImmediate(function() { callback(result); });
    }

    compile.version = soljson.cwrap("version", "string", []);

    return compile;
}

function makeCompile(compilerVersion) {
    var soljson = require('../solidity/soljson-' + compilerVersion + '.js');
    var _compile = setupMethods(soljson);
    //console.log(compilerVersion, _compile.version());
    //var _compile = soljson.cwrap("compileJSONCallback", "string", ["string", "number", "number"]);

    var optimise = 1;

    var compile = function(source, deploymentTarget, callback) {
        _compile({sources: {"contract.solc": source}}, optimise, function (compiled) {
            var errors = [], warnings = [];
            if (compiled.errors) {
                for (var i = 0; i < compiled.errors.length; i++) {
                    if (compiled.errors[i].indexOf(' Warning:') >= 0) {
                        warnings.push(compiled.errors[i]);
                    } else {
                        errors.push(compiled.errors[i]);
                    }
                }

                if (warnings.length === 0) { warnings = null; }

                if (errors.length) {
                    var error = new Error('compiler error');
                    error.errors = errors;
                    callback(error, null, warnings);
                    return;
                }
            }

            if (!compiled || !compiled.contracts || !compiled.contracts[deploymentTarget]) {
                callback(new Error('invalid deployment target'), null, warnings);
                return;
            }

            var interfaces = {};
            for (var name in compiled.contracts) {
                interfaces[name] = JSON.parse(compiled.contracts[name].interface);
            }

            var target = compiled.contracts[deploymentTarget];
            var contract = {
                bytecode: '0x' + target.bytecode,
                compilerVersion: compilerVersion,
                deploymentTarget: deploymentTarget,
                interfaces: interfaces,
                runtimeBytecode: '0x' + target.runtimeBytecode,
                source: source,
            }

            callback(null, contract, warnings);
        });
    }

    Object.defineProperty(compile, 'compilerVersion', {
        value: compilerVersion
    });

    return compile;
}
var compile = makeCompile('v0.3.1-2016-03-31-c67926c');


function NullContracts() {
}

NullContracts.prototype.store = function(transaction, network, contract, callback) {
    setImmediate(function() { callback(null, {}); });
}

NullContracts.prototype.fetch = function(address, network, bytecode, callback) {
    setImmediate(function() { callback(null, {}); });
}



function GitHubAWSContracts(options) {
    this._simpledb = new awsSdk.SimpleDB({
        apiVersion: '2016-04-01',
        region: 'us-east-1',

        accessKeyId: options.aws.accessKey,
        secretAccessKey: options.aws.secretAccessKey,
    });

    this._domain = options.aws.domain;

    this._github = new GitHubAPI({
        version: "3.0.0",
        debug: false,
        protocol: 'https',
        host: 'api.github.com',
        headers: {
            'User-Agent': 'ethers.io/' + version
        }
    });
    this._github.authenticate({type: 'token', token: options.github.token});
}


GitHubAWSContracts.getSourceKey = function(source) {
    return ('S-' + ethereumUtil.sha3(new Buffer(source)).slice(12).toString('hex'));
}

GitHubAWSContracts.getAddressKey = function(address, network, bytecode) {
    return 'A-' + ethereumUtil.sha3(Buffer.concat([
        getBuffer(address),
        getBuffer(network),
        getBuffer(bytecode),
    ])).slice(12).toString('hex');
}

GitHubAWSContracts.prototype._getAttributes = function(key, callback) {
    var self = this;
    this._simpledb.getAttributes({
        DomainName: self._domain,
        ItemName: key,
    }, function(error, data) {
        if (error) {
            console.log('SimpleDB Error:', error);
            callback(new Error('database read error'));
            return;
        }

        var info = null;
        if (data.Attributes && data.Attributes.length) {
            info = {};
            for (var i = 0; i < data.Attributes.length; i++) {
                var attribute = data.Attributes[i];
                info[attribute.Name] = attribute.Value;
            }
        }
        callback(null, info);
    });
}

GitHubAWSContracts.prototype._setAttributes = function(key, values, callback) {
    var attributes = [{Name: 'createdDate', Value: String((new Date()).getTime()), Replace: true}];
    for (var name in values) {
        attributes.push({Name: name, Value: values[name], Replace: true});
    }

    this._simpledb.putAttributes({
        Attributes: attributes,
        DomainName: this._domain,
        ItemName: key,
        Expected: {
            Exists: false,
            Name: 'gistId',
        }
    }, function (error, result) {
        if (error && error.code !== 'ConditionalCheckFailed') {
            console.log('SimpleDB Error:', error);
            callback(new Error('database write error'));
            return;
        }
        callback(null);
    });
}

GitHubAWSContracts.prototype.store = function(transaction, network, contract, callback) {
    var self = this;

    var contractAddress = getContractAddress(transaction)
    var addressKey = GitHubAWSContracts.getAddressKey(contractAddress, network, contract.runtimeBytecode);
    var sourceKey = GitHubAWSContracts.getSourceKey(contract.source);

    // Save the address to sourceKey mapping
    var saveAddress = function(info) {
        self._setAttributes(addressKey, {
            address: contractAddress,
            network: network.substring(2, 10),

            compilerVersion: contract.compilerVersion,
            optimized: 'yes',
            sourceKey: sourceKey,

            gistId: info.gistId,

            sourceUrl: info.sourceUrl,
            sourceHash: info.sourceHash,

            interfacesUrl: info.interfacesUrl,
            interfacesHash: info.interfacesHash,

        }, function (error) {
            if (error) {
                callback(error);
                return;
            }

            info.address = contractAddress;
            callback(null, info);
        });
    }

    // Save the source to github and sourceKey to gistId as necessary
    this._getAttributes(sourceKey, function(error, info) {
        if (error) {
            callback(error);
            return;
        }

        // Already have the source stored
        if (info) {
            saveAddress(info)
            return;
        }

        var sourceData = contract.source;
        var interfacesData = JSON.stringify(contract.interfaces);

        self._github.gists.create({
            description: ('ethers.io - Contract ' + sourceKey),
            public: false,
            files: {
                'contract.solc': {
                    content: sourceData,
                },
                'interfaces.json': {
                    content: interfacesData,
                }
            },
        }, function(error, result) {

            if (error) {
                console.log('GitHub Error:', error);
                callback(new Error('github create error'));
                return;
            }

            var info = {
                gistId: result.id,
                sourceUrl: result.files['contract.solc'].raw_url,
                sourceHash: ('0x' + ethereumUtil.sha3(new Buffer(sourceData)).toString('hex')),
                interfacesUrl: result.files['interfaces.json'].raw_url,
                interfacesHash: ('0x' + ethereumUtil.sha3(new Buffer(interfacesData)).toString('hex')),
            };

            self._setAttributes(sourceKey, info, function (error) {
                if (error) {
                    callback(error);
                    return;
                }

                saveAddress(info);
            });
        });
    });
}


GitHubAWSContracts.prototype.fetch = function(address, network, bytecode, callback) {
    var addressKey = GitHubAWSContracts.getAddressKey(address, network, bytecode);
    this._getAttributes(addressKey, function(error, info) {
        if (error) {
            console.log('simpledb.getAttributes:', error);
            callback(new Error('server error'));
            return;
        }

        callback(null, info);
    });
}


function Contracts(options) {
    var contracts = null;
    console.log(options);

    if (options == null) {
        contracts = new NullContracts()
    } else {
        contracts = new GitHubAWSContracts(options)
    }

    Object.defineProperty(this, 'store', {
        value: function(transaction, network, contract, callback) {
            if (!util.isHexString(network, 32)) {
                setImmediate(function() { callback(new Error('invalid network')); });
                return;
            }
            contracts.store(transaction, network, contract, callback);
        }
    });

    Object.defineProperty(this, 'fetch', {
        value: function(address, network, bytecode, callback) {
            if (!util.isAddress(address)) { throw new Error('invalid address'); }
            if (!util.isHexString(network, 32)) { throw new Error('invalid network'); }
            if (!util.isHexString(bytecode)) { throw new Error('invalid bytecode'); }
            contracts.fetch(address, network, bytecode, callback);
        }
    });
}

Contracts.compile = compile;
Contracts.getAddress = getContractAddress;
Contracts.makeCompile = makeCompile;

module.exports = Contracts;
