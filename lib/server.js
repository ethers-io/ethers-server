"use strict";

var EventEmitter = require('events').EventEmitter;
var net = require('net');
var urlParse = require('url').parse;
var inherits = require('util').inherits;

var Web3 = require('web3');
var ws = require("nodejs-websocket");
var ethereumTx = require('ethereumjs-tx');

var BN = require('ethereumjs-util').BN;

var Contracts = require('./contracts.js');
var util = require('./util.js');

String.prototype.hasPrefix = function(prefix) {
    return (prefix.length <= this.length) && (this.substring(0, prefix.length) === prefix);
};

String.prototype.hasSuffix = function(suffix) {
    return (suffix.length <= this.length) && (this.substring(this.length - suffix.length) === suffix);
}

function getHexString(value) {
    if (typeof(value) === 'number') {
        if (value === 0) { return '0x00'; }
        value = (new BN(value));

    } else if (util.isHexString(value)) {
        if (value === '0x') { return '0x00'; }
        return value;

    } else if (Buffer.isBuffer(value)) {
        if (value.length === 0) { return '0x00'; }
        return '0x' + value.toString('hex');
    }

    if (value.mod) {
        value = value.toString(16);
        if ((value.length % 2) === 1) {
            value = '0' + value;
        }

        return '0x' + value;
    }

    throw new Error('invalid hex value');
}

/*
 *  Networks (block(1).hash)
 *
 *  We use the 2nd block's hash since many people may start their own private network
 *  from an existing genesis.json; which will all have the same genesis block hash.
 */

var networks = {
    '0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6': 'homestead',
    '0xad47413137a753b2061ad9b484bf7b0fc061f654b951b562218e9f66505be6ce': 'morden',
};

/*
var networkHashes = {
    morden: '0xad47413137a753b2061ad9b484bf7b0fc061f654b951b562218e9f66505be6ce',
    homestead: '0x88e96d4537bea4d9c05d12549907b32561d3bf31f45aae734cdc119f13406cb6',
}
*/
function getNetworkName(blockHash1) {
    var result = networks[blockHash1];
    if (!result) { result = 'unknown-' + blockHash1; }
    return result;
}


/**
 *  Filters
 *
 *  Since we are using a websocket, we can be a little more optimal in how we
 *  handle filters. We introduce the following new methods:
 *
 *  - ethers_startFilter [filter, filterId]
 *  - ethers_stopFilter [filterId]
 *
 *  Which install and uninstall filters on the server side, which is then
 *  shuttled across the network when the filter returns anything intereting.
 */


// Creates a new error, adding properties to it.
function makeError(message, properties) {
    var error = new Error(message);
    for (var property in properties) {
        error[property] = properties[property];
    }
    return error;
}

function wrapError(error) {
    try {
        throw new Error('fencepost');
    } catch(e) {
        e.originalError = error;
        return e;
    }
}

// JSON-RPC Errors
// See: http://www.jsonrpc.org/specification#error_object
var errors = {
    ParseError: makeError('parse error', {code: -32700}),
    InvalidRequest: makeError('invalid request', {code: -32600}),
    MethodNotFound: makeError('method not found', {code: -32601}),
    InvalidParameters: makeError('invalid parameters', {code: -32602}),
    InternalError: makeError('internal error', {code: -32603}),
    ServerError: makeError('server error', {code: -32000}),
    NotImplemented: makeError('not implemented', {code: -32001}),
}


// Convert a URL into a provider; Currently http:// and ipc:// are supported.
function getProvider(rpc) {
    if (rpc.substring(0, 7) === 'http://') {
        return new Web3.providers.HttpProvider(rpc);
    } else if (rpc.substring(0, 4) === 'ipc:') {
        return new Web3.providers.IpcProvider(rpc.substring(4), net);
    }

    throw new Error('unsupported RPC url: ' + rpc);
}


function Server(options) {
    if (!(this instanceof Server)) {
        throw Error('Server must be instanitated with `new`');
    }

    this._rpc = options.rpc || 'http://localhost:8545';
    this._port = options.port || 8000;
    this._debug = options.debug || false;

    // The storage syste for contracts
    this._contracts = new Contracts(options.contractConfig);

    // Check the RPC url is at least a little ok (we have a provider that can handle it)
    getProvider(this._rpc);

    // Web3, the timer to attempt reconnecting and the latest block filter
    this._web3Connected = false;
    this._retryTimer = null;
    this._latestFilter = null;

    // The name of the network
    this._network = null;
    this._networkHash = null;

    // Some things we track on block change (so we can access them synchronously)
    this._gasPrice = null;
    this._blockNumber = 0;

    // @TODO: Add a .stop() and use this
    this._stopped = false;

    var self = this;

    var nextClientId = 1;

    // Prepare method for creating a websocket server (SSL or otherwise)
    var createServer = ws.createServer;
    if (options.privateKey) {
        createServer = function(callback) {
            var secureOptions = {
                cert: options.certificate,
                key: options.privateKey,
                secure: true,
            };

            if (options.intermediateCertificate) {
                secureOptions.ca = options.intermediateCertificate
            }

            return ws.createServer(secureOptions, callback);
        };
    }

    Object.defineProperty(this, 'port', {
        get: function() { return self._port; }
    });

    Object.defineProperty(this, 'network', {
        get: function() { return self._network; }
    });

    // We poll for this every 5 seconds (i.e. is only approximate)
    this._connections = 0;
    Object.defineProperty(this, 'connections', {
        get: function() { return self._connections; }
    });

    Object.defineProperty(this, 'totalConnections', {
        get: function() { return (nextClientId - 1); }
    });

    var clients = {};

    // Create the server
    this._server = createServer(function (client) {
        client.ethersClientId = 'cid-' + (nextClientId++);
        clients[client.ethersClientId] = client;

        // Maps the client's local filterId to the actual filter
        client.ethersFilters = {};
        client.ethersNextFilterId = (function() {
            var filterPrefix = '0x' + self._web3.sha3(client.ethersClientId).substring(0, 8);
            var nextFilterId = 1;
            return function() {
                var value = self._web3.toHex((nextFilterId++)).substring(2);
                if (value.length % 2) { value = '0' + value; }
                return filterPrefix + value;
            };
        })();

        // Where is this request coming from?
        var origin = null;
        if (client.headers && client.headers.origin) {
            var hostname = urlParse(client.headers.origin).hostname;
            if (hostname) {
                origin = hostname;
            }
        }

        // Make sure we set up an error handler before doing anything
        // (uncaught erros will kill the server)
        client.on('error', function(error) {
            self.emit('debug', 'clientError', wrapError(error));
        });

        self.emit('debug', 'connection - ' + origin);

        // Send errors to the client
        client._ethersSendError = function(messageId, error, data, closeOnComplete) {
            var payload = {
                id: messageId,
                payload: JSON.stringify({
                    message: error.message,
                    code: error.code,
                    data: data,
                })
            };

            var callback = undefined;
            if (closeOnComplete) { callback = (function() { client.close(); }); }
            client.send(JSON.stringify(payload), callback);
        }

        // We are not on good terms with our web3 right now
        if (!self._network) {
            client._ethersSendError(0, errors.ServerError, null, true);
            return;
        }

        // Check the basics (i.e. /v1/NETWORK)
        var comps = (client.path || '').split('/');
        if (comps.length !== 3 || comps[0] !== '' || comps[1] !== 'v1') {
            client._ethersSendError(0, errors.InvalidRequest, {invalidPath: client.path}, true);
            return;
        }

        // They want a network we aren't serving
        if (comps[2] !== self._network) {
            client._ethersSendError(0, errors.InvalidRequest, {network: comps[2], expectedNetwork: self._network}, true);
            return;
        }

        function handleText(text) {
            // Parse the request and make sure it is valid
            var messageId = 0;
            try {
                var payload = JSON.parse(text);
                messageId = payload.id;

                var request = JSON.parse(payload.payload);
                if (!request || request.jsonrpc !== '2.0' || typeof(request.id) !== 'number') {
                    throw new Error('invalid JSON-RPC');
                }
                if (typeof(request.method) !== 'string' || !Array.isArray(request.params)) {
                    throw new Error('invalid JSON-RPC');
                }

            } catch (error) {
                self.emit('debug', text, wrapError(error));
                client._ethersSendError(messageId, errors.ParseError, null, true);
                return;
            }

            // Process the request
            self._handleRequest(client, request.method, request.params, function(error, result) {
                if (error) {
                    client._ethersSendError(messageId, error);

                } else {
                    client.send(JSON.stringify({
                        id: messageId,
                        payload: JSON.stringify({
                            id: request.id,
                            result: result,
                            jsonrpc: '2.0',
                        })
                    }));
                }
            });
        }
        client.on("text", handleText);

        client.on("close", function (code, reason) {
            self._handleClose(client, code, reason);
            delete clients[client.ethersClientId];
        });
    });

    this.on('web3Connect', function(url, network) {
        console.log('web3.connect(' + url + ', ' + network + ')');

        // Start watching for new blocks
        self._resetLatestFilter(false);
    });

    this.on('web3Error', function(error) {
        // No longer have a valid network
        self._network = null;
        self._networkHash = null;

        // Stop watching for new blocks
        self._resetLatestFilter(true);
        self._web3.reset();

        // First failure, notify anyone who cares
        if (self._web3Connected) {
            self._web3Connected = false;
            self.emit('web3Disconnect');
        }

        // Try reconnecting (may already be trying, it will figure that out)
        self._reconnectWeb3();
    });

    this.on('web3Disconnect', function() {
        console.log('web3.disconnect()');

        // Notify and disconnect all clients
        for (var clientId in clients) {
            clients[clientId]._ethersSendError(0, errors.ServerError, null, true);
        }
        clients = {};
    });

    // If debugging is enabled, show all debug info (@TODO add verbosity?)
    if (this._debug) {
        this.on('debug', function(message, error) {
            console.log('DEBUG: ' + message);
            if (error && error.message === 'fencepost') {
                console.log('DEBUG:    ' + error.originalError.message);
                if (error.stack) {
                    console.log(error.stack);
                }
            }
        });
    }
}
inherits(Server, EventEmitter);

Server.prototype._updateLatestBlock = function() {
    var self = this;

    // Get the blockNumber
    this._web3.eth.getBlockNumber(function(error, blockNumber) {
        if (error) {
            self.emit('web3Error', wrapError(error));
            return;
        }

        if (self._blockNumber === blockNumber) { return; }

        //self.emit('debug', 'blockNumber=' + blockNumber);
        self._blockNumber = blockNumber;
    })

    // Get the gasPrice
    this._web3.eth.getGasPrice(function(error, gasPrice) {
        if (error) {
            self.emit('web3Error', wrapError(error));
            return;
        }

        if (self._gasPrice === gasPrice) { return; }

        //self.emit('debug', 'gasPrice=' + gasPrice);
        self._gasPrice = gasPrice;
    });
}

Server.prototype._resetLatestFilter = function(disable) {

    // Remove any existing latest filter
    if (this._latestFilter) {
        this._latestFilter.stopWatching();
        this._latestFilter = null;
    }

    if (disable) { return; }

    // Start a new latest filter
    var self = this;
    this._latestFilter = self._web3.eth.filter('latest', function(error, blockHash) {
        if (error) {
            self.emit('web3Error', wrapError(error));
            return;
        }

        self._updateLatestBlock();
    });

    // Update our internal knowledge of the blockchain
    this._updateLatestBlock();
}

Server.prototype._reconnectWeb3 = function() {
    // Already inflight attempt to reconnect
    if (this._retryTimer) { return; }

    // The following "retry" should ONLY be scheduled against this._retryTimer.
    // i.e. Inside it, the _retryTimer is defined, has fired and is expired.
    var self = this;
    var retry = function () {
        self._web3.eth.getBlock(1, function (error, block) {

            // Try reconnecting to web3
            if (error) {
                self.emit('debug', 'Error connecting to Web3 (retrying in 1s)');

                self._retryTimer = setTimeout(retry, 1000);
                self._retryTimer.unref();

                return;
            }

            // We are connected!
            self._networkHash = block.hash;
            self._network = getNetworkName(block.hash);

            // Maybe we reconnected due to a timeout, so never technically disconnected
            if (!self._web3Connected) {
                self._web3Connected = true;
                self.emit('web3Connect', self._rpc, self._network);
            }

            // No longer retrying
            self._retryTimer = null;

            // Start watching for new blocks again
            self._resetLatestFilter(false);
        });
    }

    // Try to connect immediately (but use timeout, so clearTimeout works)
    this._retryTimer = setTimeout(retry, 0);
    this._retryTimer.unref();
}

Server.prototype.start = function(callback) {

    // Already started
    if (this._web3) {
        this.emit('debug', 'start - already started');
        return;
    }

    // Our Web3 connection
    this._web3 = new Web3(getProvider(this._rpc));
    this._reconnectWeb3();

    var self = this;

    // Count how many connections we have
    var countConnectionsTimer = setInterval(function() {
        if (self._stopped) {
            return clearInterval(countConnectionsTimer);
        }

        self._server.socket.getConnections(function(error, count) {
            if (error) {
                self.emit('debug', 'getConnections errror', wrapError(error));
                return;
            }
            self._connections = count;
        })
    }, 5000);
    countConnectionsTimer.unref();

    // Start listening
    this._server.listen(this._port, function() {
        self._startTime = (new Date()).getTime();
        self.emit('listen');
        callback();
    });
}

Server.prototype._handleClose = function(client, code, reason) {
    this.emit('debug', 'Closing ' + client.ethersClientId + '...');
    for (var filterId in client.ethersFilters) {
        client.ethersFilters[filterId].stopWatching();
    }
    client.ethersFilters = [];
}

// These are calls we can safely just pass along (optionally requiring translation)
var ethMethods = {
    eth_getBalance: true,
    eth_getStorageAt: true,
    eth_getCode: true,
    eth_getBlock: true,
    eth_getBlockTransactionCount: true,
    eth_getUncle: true,
    eth_getBlockUncleCount: true,
    eth_getTransaction: true,
    eth_getTransactionFromBlock: true,
    eth_getTransactionReceipt: true,
    eth_getTransactionCount: true,
    eth_sendRawTransaction: true,
    eth_call: true,
    eth_estimateGas: true,

    eth_getBlockByHash: 'eth_getBlock',
    eth_getBlockByNumber: 'eth_getBlock',

    eth_getTransactionByBlockHashAndIndex: 'eth_getTransactionFromBlock',
    eth_getTransactionByBlockNumberAndIndex: 'eth_getTransactionFromBlock',

    eth_getUncleByBlockHashAndIndex: 'eth_getUncle',
    eth_getUncleByBlockNumberAndIndex: 'eth_getUncle',

    eth_getBlockTransactionCountByHash: 'eth_getBlockTransactionCount',
    eth_getBlockTransactionCountByNumber: 'eth_getBlockTransactionCount',

    eth_getUncleCountByBlockHash: 'eth_getBlockUncleCount',
    eth_getUncleCountByBlockNumber: 'eth_getBlockUncleCount',

    eth_getTransactionByHash: 'eth_getTransaction',
}

Server.prototype._handleEthMethod = function(client, method, params, callback) {
    var self = this;

    var action = ethMethods[method];
    if (!action) { return false; }

    // We need to translate the method back to web3
    if (action !== true) {
        method = action;

        // These operations were likely encoded into a hex string. We convert them
        // back into a Number, since this is how web3 decides which sub-call to make
        switch (method) {
            case 'eth_getBlockByNumber':
            case 'eth_getTransactionByBlockNumberAndIndex':
            case 'eth_getUncleByBlockNumberAndIndex':
            case 'eth_getBlockTransactionCountByNumber':
            case 'eth_getUncleCountByBlockNumber':
                try {
                    var value = params[0];
                    if (value === '' || value === '0x') { value = '0x0'; }
                    if (typeof(value) === 'string' && value.match(/0x[0-9a-fA-f]+/)) {
                        params[0] = parseInt(value.substring(2), 16);
                    }
                } catch (error) {
                     console.log('What?', error);
                }
                break;
        }
    }

    // Get the actual function to call
    var func = this._web3.eth[method.substring(4)];

    // Create a version of the parameters with the callback appended
    params = params.slice();
    params.push(function(error, result) {
        if (error) {
            callback(errors.ServerError);
        } else {
            callback(null, result);
        }
    });

    // Try calling the method
    try {
        func.apply(this._web3, params);

    // Parameters are not correct
    } catch (error) {
        setImmediate(function() { callback(error); });
    }

    return true;
}

Server.prototype._web3GetBalancePromise = function(address) {
    var self = this;
    return new Promise(function(resolve, reject) {
        self._web3.eth.getBalance(address, 'pending', function(error, balance) {
            if (error) {
                //self.emit('web3Error', wrapError(error));
                return reject(error);
            }
            resolve(balance);
        });
    });
}

Server.prototype._web3GetTransactionCountPromise = function(address) {
    var self = this;
    return new Promise(function(resolve, reject) {
        self._web3.eth.getTransactionCount(address, 'pending', function(error, transactionCount) {
            if (error) {
                //self.emit('web3Error', wrapError(error));
                return reject(error);
            }
            resolve(transactionCount);
        });
    });
}

Server.prototype._web3EstimateGasPromise = function(transaction) {
    var self = this;
    return new Promise(function(resolve, reject) {
        self._web3.eth.estimateGas(transaction, 'pending', function(error, gasPrice) {
            if (error) {
                //self.emit('web3Error', wrapError(error));
                return reject(error);
            }
            resolve(gasPrice);
        });
    });
}

Server.prototype._handleEthersMethod = function(client, method, params, callback) {
    var self = this;

    function invalidParameter(reason) {
        self.emit('debug', 'invalid param - ' + reason);
        setImmediate(function() { callback(errors.InvalidParameters); });
        return true;
    }

    switch (method) {
        case 'ethers_status':
            callback(null, {
                network: this.network,

                connection: this.connections,
                totalConnections: this.totalConnections,

                blockNumber: this._blockNumber,
                gasPrice: this._gasPrice.toString(10),

                connected: self._web3Connected,
                uptime: ((new Date()).getTime() - this._startTime),
            });
            break;

        case 'ethers_faucet':
            break;

        case 'ethers_deployContract':
            var source = params[0];
            var compilerVersion = params[1];
            var optimized = params[2];
            var deploymentTarget = params[3];
            var signedTransaction = params[4];

            // For now we'll support up to 32kb
            if (source.length > (1 << 15)) {
                return invalidParameter('contract source too large');
            }

            if (!util.isHexString(signedTransaction)) {
                return invalidParameter('transaction invalid hex');
            }

            var transaction = new ethereumTx(signedTransaction);

            // This is a not a deploy transaction
            if (transaction.to.length != 0) {
                return invalidParamaeter('contract deployment cannot send `to`');
            }

            // Make sure we have a proper signed transaction
            try {
                if (!transaction.verifySignature() || !transaction.from) {
                    throw new Error('unsigned transaction');
                }

            } catch (error) {
                return invalidParameter('unsigned transaction');
            }

            // We only support optimized code (for now)
            if (optimized !== true) {
                return invalidParameters('unsupported `optimized` value');
            }

            // We only support one compiler (for now)
            if (compilerVersion !== Contracts.compile.compilerVersion) {
                return invalidParameters('unsupported `compilerVersion`');
            }

            var from = getHexString(transaction.from);
            var value = getHexString(transaction.value);
            var nonce = getHexString(transaction.nonce);
            var data = getHexString(transaction.data);
            var gasPrice = getHexString(transaction.gasPrice);

            // In case we disconnect, remember who we are
            var networkHash = this._networkHash;

            // A mock transaction to compute the cost
            var sendTransaction = {
                from: from,
                value: value,
                data: data,
                nonce: nonce
            };

            // Wait until all results are in
            Promise.all([
                this._web3EstimateGasPromise(sendTransaction),
                this._web3GetBalancePromise(from),
                this._web3GetTransactionCountPromise(from)
            ]).then(function (results) {

                var estimatedGas = results[0];
                var balance = results[1];
                var transactionCount = results[2];

                // Check the nonce is what we expect
                if (nonce !== getHexString(transactionCount)) {
                    return invalidParameter('incorrect nonce');
                }

                // Check there is enough gasLimit in the transaction to deploy
                var expectedGas = new BN(estimatedGas);
                if ((new BN(transaction.gasLimit)).lt(expectedGas)) {
                    return invalidParameter('gas limit too low: ' + getHexString(expectedGas));
                }

                // Check there is enough balance on this account to deploy
                if (balance.lt((new BN(estimatedGas)).mul(new BN(gasPrice)))) {
                    return invalidParameter('insufficient funds');
                }

                Contracts.compile(source, deploymentTarget, function (error, contract) {
                    if (error) {
                        return invalidParameter('contract error');
                    }

                    // Check the compiled code matches the transaction's code
                    if (contract.bytecode !== data) {
                        return invalidParameter('bytecode mismatch');
                    }

                    // Save the contract source code
                    self._contracts.store(transaction, networkHash, contract, function(error, info) {

                        if (error) {
                            self.emit('debug', wrapError(error.message));
                            return callback(errors.ServerError);
                        }

                        self._web3.eth.sendRawTransaction(signedTransaction, function(error, hash) {

                            if (error) {
                                self.emit('debug', 'sendRawTransaction', wrapError(error));
                                return callback(errors.ServerError);
                            }

                            callback(null, {
                                //bytecode: data,
                                //compilerVersion: compilerVersion,
                                address: info.address,
                                //deploymentTarget: info.deploymentTarget,
                                gistId: info.gistId,
                                //optimized: optimized,
                                source: {
                                    hash: info.sourceHash,
                                    url: info.sourceUrl
                                },
                                interfaces: {
                                    hash: info.interfacesHash,
                                    url: info.interfacesUrl
                                },
                                hash: hash
                            });
                        });
                    });
                });
            }, function (error) {
                self.emit('debug', error.message, wrapError(error));
                callback(errors.ServerError);

            }).catch(function(error) {
                self.emit('debug', error.message, wrapError(error));
                callback(errors.ServerError);
            });

            break;

        case 'ethers_getContract':
            var address = params[0];
            if (!util.isAddress(address)) {
                return invalidParameter('invalid address');
            }

            // In case we disconnect, remember who we are
            var networkHash = this._networkHash;

            this._web3.eth.getCode(address, 'pending', function(error, bytecode) {
                if (error) {
                    //self.emit('web3Error', wrapError(error));
                    callback(errors.ServerError);
                    return;
                }

                if (!networkHash) {
                    return invalidParameter('unknown network');
                }

                self._contracts.fetch(address, networkHash, bytecode, function(error, info) {
                    if (error) {
                        return callback(errors.ServerError);
                    }

                    if (!info) { info = { }; }

                    callback(null, {
                        address: address,
                        bytecode: bytecode,
                        compilerVersion: info.compilerVersion,
                        deploymentTarget: info.deploymentTarget,
                        gistId: info.gistId,
                        optimized: (info.optimized === 'yes'),
                        source: {
                            hash: info.sourceHash,
                            url: info.sourceUrl
                        },
                        interfaces: {
                            hash: info.interfacesHash,
                            url: info.interfacesUrl
                        },
                        //hash: hash
                    });
                });
            });
            // Not implemented *yet*
            //setImmediate(function() { callback(errors.NotImplemented); });
            break;

        default:
            return false;
    }

    return true;
}

Server.prototype._handleFilterMethod = function(client, method, params, callback) {
    var filterInfo = null;
    switch (method) {
        case 'eth_newBlockFilter':
            filterInfo = 'latest';
            break
        //case 'eth_newPendingTransactionFilter':
        //    filterInfo = 'pending';
        //    break;
        case 'eth_newFilter':
            filterInfo = params[0];
            break;
        case 'eth_uninstallFilter':
            var filter = client.ethersFilters[params[0]];
            if (filter && filter.stopWatching) {
                filter.stopWatching();
                delete client.ethersFilters[params[0]];
                callback(null, true);
            } else {
                callback(null, false);
            }
            return true;
        default:
            return false;
    }

    var filterId = client.ethersNextFilterId();
    try {
        var self = this;
        var filter = this._web3.eth.filter(filterInfo, function(error, result) {
            if (error) {
                //self.emit('web3Error', wrapError(error));
                return;
            }
            client.send(JSON.stringify({filterId: filterId, payload: JSON.stringify(result)}));
        });

        client.ethersFilters[filterId] = filter;

        setImmediate(function() { callback(null, filterId); });

    } catch(error) {
        setImmediate(function() { callback(errors.InvalidParameters); });
    }

    return true;
}

Server.prototype._handleRequest = function(client, method, params, callback) {
    var self = this;

    if (this._handleEthMethod(client, method, params, callback)) {
        // Handled inside the if condition

    } else if (method === 'eth_blockNumber') {
        setImmediate(function() { callback(null, self._blockNumber); });

    } else if (method === 'eth_gasPrice') {
        setImmediate(function() { callback(null, self._gasPrice); });

    } else if (this._handleFilterMethod(client, method, params, callback)) {
        // Handled inside the if condition

    } else if (this._handleEthersMethod(client, method, params, callback)) {
        // Handled inside the if condition

    } else {
        setImmediate(function() { callback(errors.MethodNotFound); });
    }
}


module.exports = Server;
