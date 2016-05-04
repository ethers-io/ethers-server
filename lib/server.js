var EventEmitter = require('events').EventEmitter;
var net = require('net');
var urlParse = require('url').parse;
var util = require('util');

var Web3 = require('web3');
var ws = require("nodejs-websocket");


String.prototype.hasPrefix = function(prefix) {
    return (prefix.length <= this.length) && (this.substring(0, prefix.length) === prefix);
};

String.prototype.hasSuffix = function(suffix) {
    return (suffix.length <= this.length) && (this.substring(this.length - suffix.length) === suffix);
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


function makeError(message, properties) {
    var error = new Error(message);
    for (var property in properties) {
        error[property] = properties[property];
    }
    return error;
}

// JSON-RPC Errors
// See: http://www.jsonrpc.org/specification#error_object
var errors = {
    ParseError: makeError('parse error', {code: -32700}),
    InvalidRequest: makeError('invalid request', {code: -32600}),
    MethodNotFound: makeError('method not foiund', {code: -32601}),
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
    if (!(this instanceof arguments.callee)) {
        throw Error('Server must be instanitated with `new`');
    }

    this._rpc = options.rpc || 'http://localhost:8545';
    this._port = options.port || 8000;
    this._debug = options.debug || false;

    // Check the RPC url is at least a little ok
    getProvider(this._rpc);

    // The name of the network
    this._network = null;

    // This is set if and only if we are not connected to a web3 instance
    this._retryTimer = null;

    // Some things we track on block change (so we can access them synchronously)
    this._gasPrice = null;
    this._blockNumber = 0;

    // @TODO: Add a .stop()
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

    // Create the server
    this._server = createServer(function (client) {
        client.ethersClientId = 'cid-' + (nextClientId++);

        // Maps the client's filterId to our filterId
        client.ethersFilters = {};

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
            self.emit('debug', 'clientError - ' + error.message);
        });

        self.emit('debug', 'connection - ' + origin);

        // Send errors to the client
        function sendError(messageId, error, data, closeOnComplete) {
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
        if (self._retryTimer || !self._network) {
            sendError(0, errors.ServerError, null, true);
            return;
        }

        // Check the basics /v1/NETWORK
        var comps = (client.path || '').split('/');
        if (comps.length !== 3 || comps[0] !== '' || comps[1] !== 'v1') {
            sendError(0, errors.InvalidRequest, {invalidPath: client.path}, true);
            return;
        }

        // They want a nertwork we arent' serving
        if (comps[2] !== self._network) {
            sendError(0, errors.InvalidRequest, {network: comps[2], expectedNetwork: self._network}, true);
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
                sendError(messageId, errors.ParseError, null, true);
                return;
            }

            self._handleRequest(client, request.method, request.params, function(error, result) {
                if (error) {
                    sendError(messageId, error);

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
        });
    });

    // If debugging is enabled, show all debug info (@TODO add verbosity?)
    if (this._debug) {
        this.on('debug', function(message) {
            console.log('DEBUG: ' + message);
        });
    }
}
util.inherits(Server, EventEmitter);

Server.prototype._updateLatestBlock = function() {
    var self = this;

    // Get the blockNumber
    this._web3.eth.getBlockNumber(function(error, blockNumber) {
        if (error) {
            self._reconnect();
            self.emit('debug', '_updateLatestBlock:web3.eth.getBlockNumber - ' + error.message);
            return;
        }

        if (self._blockNumber === blockNumber) { return; }

        //self.emit('debug', 'blockNumber=' + blockNumber);
        self._blockNumber = blockNumber;
    })

    // Get the gasPrice
    this._web3.eth.getGasPrice(function(error, gasPrice) {
        if (error) {
            self._reconnect();
            self.emit('debug', '_updateLatestBlock:web3.eth.getGasPrice - ' + error.message);
            return;
        }

        if (self._gasPrice === gasPrice) { return; }

        //self.emit('debug', 'gasPrice=' + gasPrice);
        self._gasPrice = gasPrice;
    });

    // If we haven't figured out what network we're on, try to
    if (!self._network) {
        self._web3.eth.getBlock(1, function(error, block) {

            // Another call to getBlock completed already, we're done
            if (self._network !== null) { return; }

            if (error) {
                self.emit('debug', '_updateLatestBlock:web.eth.getBlock(1) error - ' + error.message);
                return;
            }

            self._network = getNetworkName(block.hash);

            self.emit('debug', 'network=' + self._network);
        });
    }
}

Server.prototype._reconnect = function() {

    // Already attempting to reconnect
    if (this._retryTimer) { return; }

    this.emit('debug', '_reconnect - connecting...');

    // The following "retry" should ONLY be scheduled against this._retryTimer.
    // i.e. Inside it, the _retryTimer has fired and is expired.
    var self = this;
    var retry = function () {
        self._web3.eth.getBlockNumber(function (error, blockNumber) {

            // Probably not connect, try connecting and checking back soon
            if (error) {
                self.emit('debug', '_reconnect:web3.eth.getBlockNumber - retrying in 1s...');
                self._web3 = new Web3(getProvider(self._rpc));
                self.retryTimer = setTimeout(retry, 1000);
                return;
            }

            self.emit('debug', '_reconnect - connected');

            // We are connected!
            clearTimeout(self._retryTimer);
            self._retryTimer = null;

            // Start watching for new blocks (@TODO: do I need to track this and .stopWatching?)
            self._web3.eth.filter('latest', function(error, blockHash) {
                if (error) {
                    self.emit('debug', '_reconnect:web3.eth.filter - ' + error.message);
                    return;
                }
                self._updateLatestBlock();
            });

            self._updateLatestBlock();
        });
    }

    this._retryTimer = setImmediate(retry);
}

Server.prototype.start = function(callback) {

    // Already started
    if (this._web3) {
        this.emit('debug', 'start - already started');
        return;
    }

    // Bootstrap our web3 connection
    this._web3 = new Web3(getProvider(this._rpc));
    this._reconnect();

    var self = this;

    // If we haven't had a block in 30s, maybe our web3 has failed us; reconnect
    var lastBlockNumber = null;
    var reconnectTimer = setInterval(function() {
        if (self._stopped) {
            clearInterval(reconnectTimer);
            return;
        }

        if (self._blockNumber === lastBlockNumber) {
            self.emit('debug', 'over 30s since last block - ' + lastBlockNumber);
            lastBlockNumber = self._blockNumber;
            self._reconnect();
        }
    }, 30000);
    reconnectTimer.unref();

    // Count how many connections we have
    var countConnectionsTimer = setInterval(function() {
        if (self._stopped) {
            clearInterval(countConnectionsTimer);
            return;
        }

        self._server.socket.getConnections(function(error, count) {
            if (error) {
                self.emit('debug', 'getConnections errror - ' + error.message);
                return;
            }
            self._connections = count;
        })
    }, 5000);
    countConnectionsTimer.unref();

    // Start listening
    this._server.listen(this._port, function() {
        callback();
    });
}


// These are calls we can safely just pass along (@TODO verify paramters)
var ethCalls = {
    'eth_getBalance': [],
    'eth_getStorageAt': [],
    'eth_getCode': [],
    'eth_getBlock': [],
    'eth_getBlockTransactionCount': [],
    'eth_getUncle': [],
    'eth_getBlockUncleCount': [],
    'eth_getTransaction': [],
    'eth_getTransactionFromBlock': [],
    'eth_getTransactionReceipt': [],
    'eth_getTransactionCount': [],
    'eth_sendRawTransaction': [],
    'eth_call': [],
    'eth_estimateGas': [],
};
function checkEthCall(method, params) {
    var params = ethCalls[method];
    if (!params) { return false; }
    return true;
}

// We are using web3, so we can simply convert these calls back to their general method
var translateEthCalls = {
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

function numberifyParam1(params) {
    try {
        var value = params[0];
        if (value === '' || value === '0x') { value = '0x0'; }
        if (typeof(value) === 'string' && value.match(/0x[0-9a-fA-f]+/)) {
            params[0] = parseInt(value.substring(2), 16);
        }
    } catch (error) {
        console.log('What?', error);
    }
}

var ethCallsParamProcessors = {
    eth_getBlockByNumber: numberifyParam1,
    eth_getTransactionByBlockNumberAndIndex: numberifyParam1,
    eth_getUncleByBlockNumberAndIndex: numberifyParam1,
    eth_getBlockTransactionCountByNumber: numberifyParam1,
    eth_getUncleCountByBlockNumber: numberifyParam1,
}

var ethersCalls = {
    ethers_startFilter: [],
    ethers_stopFilter: [],
    ethers_getFilter: [],
}
function checkEthersCall(method, params) {
    var params = ethersCalls[method];
    if (!params) { return false; }
    return true;
}

Server.prototype._handleClose = function(client, code, reason) {
    for (var filterId in client.ethersFilters) {
        client.ethersFilters[filterId].stopWatching();
    }
    client.ethersFilters = [];
}

Server.prototype._handleFilterRequest = function(client, method, params, callback) {
}

Server.prototype._handleRequest = function(client, method, params, callback) {
    if (translateEthCalls[method]) {
        // Adjust any of the parameters if needed
        var paramProcessor = ethCallsParamProcessors[method];
        if (paramProcessor) { paramProcessor(params); }

        // Convert the call to the correct web3 call
        method = translateEthCalls[method];
    }

    var self = this;

    if (checkEthCall(method, params)) {
        var func = this._web3.eth[method.substring(4)];
        params = params.slice();
        params.push(function(error, result) {
            if (error) {
                callback(errors.ServerError);
            } else {
                callback(null, result);
            }
        });

        try {
            func.apply(this._web3, params);
        } catch (error) {
            // Parameters are not correct
            setImmediate(function() { callback(error); });
        }

    } else if (method === 'eth_blockNumber') {
        setImmediate(function() { callback(null, self._blockNumber); });

    } else if (method === 'eth_gasPrice') {
        setImmediate(function() { callback(null, self._gasPrice); });

    } else if (checkEthersCall(method, params)) {
        // Not implemented *yet*
        callback(errors.NotImplemented);

    } else if (method === 'ethers_deployContract') {
        // Not implemented *yet*
        callback(errors.NotImplemented);

    } else {
        callback(errors.MethodNotFound);
    }
}


module.exports = Server;
