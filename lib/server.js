"use strict";

var EventEmitter = require('events').EventEmitter;
var http = require('http');
var net = require('net');
var urlParse = require('url').parse;
var inherits = require('util').inherits;

var Web3 = require('web3');
var ws = require("nodejs-websocket");
var ethereumTx = require('ethereumjs-tx');

var ethereumUtil = require('ethereumjs-util');
var BN = ethereumUtil.BN;

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
    ParseError: makeError('parse error', {code: -32700, jsonError: true}),
    InvalidRequest: makeError('invalid request', {code: -32600, jsonError: true}),
    MethodNotFound: makeError('method not found', {code: -32601, jsonError: true}),
    InvalidParameters: makeError('invalid parameters', {code: -32602, jsonError: true}),
    InternalError: makeError('internal error', {code: -32603, jsonError: true}),
    ServerError: makeError('server error', {code: -32000, jsonError: true}),
    NotImplemented: makeError('not implemented', {code: -32001, jsonError: true}),
}

function ensureHexString(value, length) {
    if (!util.isHexString(value, length)) {
        throw errors.InvalidParameters;
    }
    return value;
}


var ensureTransaction = (function() {
    var properties = {};
    ['data', 'from', 'gasLimit', 'gasPrice', 'nonce', 'to', 'value'].forEach(function(key) {
        properties[key] = true;
    });

    return (function(transaction) {
        console.log(transaction);
        ['to', 'from'].forEach(function(key) {
console.log(key);
            if (!transaction[key]) { return; }
            ensureHexString(transaction[key], 20);
        });
        ['data', 'gasLimit', 'gasPrice', 'nonce', 'value'].forEach(function(key) {
console.log(key);
            if (!transaction[key]) { return; }
            ensureHexString(transaction[key]);
        });
        for (var key in transaction) {
console.log(key);
            if (!properties[key]) { throw errors.InvalidParameters; }
        }
        return transaction;
    });
})();

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

    var self = this;

    util.defineProperty(this, 'rpc', options.rpc || 'http://localhost:8545');
    util.defineProperty(this, 'debug', options.debug || false);

    // @TODO: Move faucet to its own class
    var faucetPrivateKey = options.faucetPrivateKey || null;
    if (faucetPrivateKey) {
        if (!util.isHexString(faucetPrivateKey, 32)) { throw new Error('invalid faucetPrivateKey'); }
        util.defineProperty(this, 'faucetAddress', '0x' + ethereumUtil.privateToAddress(faucetPrivateKey).toString('hex'));
        faucetPrivateKey = new Buffer(faucetPrivateKey.substring(2), 'hex');
    } else {
        util.defineProperty(this, 'faucetAddress', null);
    }

    // The storage syste for contracts
    this._contracts = new Contracts(options.contractConfig);

    // Web3, the timer to attempt reconnecting and the latest block filter
    var web3Connected = false;
    var web3Synced = false;
    util.defineProperty(this, 'web3', new Web3(getProvider(this.rpc)));

    // Create a promise for a web3 call
    function getWeb3Promise(method) {
        var params = Array.prototype.slice.call(arguments, 1);
        return new Promise(function(resolve, reject) {
            params.push(function(error, result) {
                if (error) {
                    self.emit('web3Error', wrapError(error));
                    return reject(error);
                }
                resolve(result);
            });
            self.web3.eth[method].apply(self.web3, params);
        });
    }

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
        get: function() { return (options.port || 5000); }
    });

    var network = null, networkHash = null;
    Object.defineProperty(this, 'network', {
        get: function() { return network; }
    });

    Object.defineProperty(this, 'totalConnections', {
        get: function() { return (nextClientId - 1); }
    });

    // maps: address => {client._eid: true, ...}
    var addresses = {};

    // maps: client._eid => client
    var clients = {};

    function setupClientFilters(client) {
        util.defineProperty(client, '_addresses', []);
        util.defineProperty(client, '_lastValue', {});
        util.defineProperty(client, '_checkAddress', function(address) {

            Promise.all([
                getWeb3Promise('getBalance', address, 'pending'),
                getWeb3Promise('getTransactionCount', address, 'pending'),
            ]).then(function(results) {
               results = {
                   balance: util.hexlify(results[0]),
                   transactionCount: results[1],
               };

               var updated = {};
               Object.keys(results).forEach(function(key) {
                   if (results[key] === client._lastValue[key]) { return; }
                   updated[key] = results[key];
                   client._lastValue[key] = results[key];
               })

               // Only send state if anything has changed
               if (Object.keys(updated).length > 0) {
                   updated.address = address;
                   client._sendResult(0, {accounts: [updated]});
               }

            }, function(error) {
                console.log('error', error);
            });
        });
    }
    function addAddressFilter(client, address) {
        address = address.toLowerCase();
        client._addresses.push(address);
        var clientIds = addresses[address];
        if (!clientIds) {
            clientIds = {};
            addresses[address] = clientIds;
        }
        clientIds[client._eid] = true;

        client._checkAddress(address);
    }

    function removeClientFilters(client) {
        client._addresses.forEach(function (address) {
            var clientIds = addresses[address];
            if (clientIds) {
                if (Object.keys(clientIds).length <= 1) {
                    delete addresses[address];
                } else {
                    delete clientIds[client._eid];
                }
            }
        });
        client._addresses.splice(0, client._addresses.length);
    }

    // Create the server
    var server = createServer(function (client) {

        // Track the client
        util.defineProperty(client, '_eid', nextClientId++);
        clients[client._eid] = client;

        setupClientFilters(client);

        // Maps the client's local filterId to the actual filter
        /*
        client.ethersFilters = {};
        client.ethersNextFilterId = (function() {
            var filterPrefix = '0x' + self.web3.sha3(client._eid).substring(0, 8);
            var nextFilterId = 1;
            return function() {
                var value = self.web3.toHex((nextFilterId++)).substring(2);
                if (value.length % 2) { value = '0' + value; }
                return filterPrefix + value;
            };
        })();
        */

        // Where is this request coming from?
        var origin = null;
        if (client.headers && client.headers.origin) {
            var hostname = urlParse(client.headers.origin).hostname;
            if (hostname) {
                origin = hostname;
            }
        }

        // @TODO: Add options to specify allowed origins and validate here

        // Make sure we set up an error handler before doing anything
        // (uncaught erros will kill the server)
        client.on('error', function(error) {
            self.emit('debug', 'clientError', wrapError(error));
        });

        self.emit('debug', 'connection - ' + origin);

        // Function to Send errors to the client
        util.defineProperty(client, '_sendError', function(messageId, error, data, closeOnComplete) {
            if (!clients[client._eid]) {
                console.log('cannot send error; dead: ' + client._eid);
                return;
            }

            var payload = {
                id: messageId,
                jsonrpc: '2.0',
                message: error.message,
                code: error.code,
                data: data,
            };

            var callback = undefined;
            if (closeOnComplete) { callback = (function() { client.close(); }); }
            client.send(JSON.stringify(payload), callback);
        });

        util.defineProperty(client, '_sendResult', function(messageId, result) {
            if (!clients[client._eid]) {
                console.log('cannot send result; dead: ' + client._eid);
                return;
            }

            client.send(JSON.stringify({
                id: messageId,
                jsonrpc: '2.0',
                result: result,
            }));
        });

        // We are not on good terms with our web3 right now
        if (!network || !web3Synced) {
            client._sendError(0, errors.ServerError, null, true);
            return;
        }

        // Check the basics (i.e. /v2/NETWORK)
        var comps = (client.path || '').split('/');
        if (comps.length !== 3 || comps[0] !== '' || comps[1] !== 'v2') {
            client._sendError(0, errors.InvalidRequest, {invalidPath: client.path}, true);
            return;
        }

        // Check this is the expected network
        if (comps[2] !== network) {
            client._sendError(0, errors.InvalidRequest, {network: comps[2], expectedNetwork: network}, true);
            return;
        }

        // Send the initial state
        /*
        client._lastValue.gasPrice = self.gasPrice;
        client._lastValue.blockNumber = self.blockNumber;
        client.send(JSON.stringify({
            id: 0,
            jsonrpc: '2.0',
            result: {
                gasPrice: client._lastValue.gasPrice,
                blockNumber: client._lastValue.blockNumber,
            }
        }));
        */


        // New message
        client.on("text", function handleText(text) {
            var messageId = 0;

            // Parse the request and make sure it is valid
            try {
                var payload = JSON.parse(text);
                messageId = payload.id;

                if (!payload || payload.jsonrpc !== '2.0' || typeof(messageId) !== 'number') {
                    throw new Error('invalid JSON-RPC');
                }
                if (typeof(payload.method) !== 'string' || !Array.isArray(payload.params)) {
                    throw new Error('invalid JSON-RPC');
                }

            } catch (error) {
                self.emit('debug', text, wrapError(error));
                client._sendError(messageId, errors.ParseError, null, true);
                return;
            }

            try {
                if (!payload.params) { payload.params = {}; }
                var params = payload.params[0] || {};

                switch (payload.method) {
                    case 'watchAddress':
                        addAddressFilter(client, ensureHexString(params.address, 20));
                        client._sendResult(messageId, true);
                        break;

                    case 'getTransaction':
                        var txid = ensureHexString(params.txid, 32);
                        getWeb3Promise('getTransaction', txid).then(function(tx) {
                            var transaction = {
                                from: tx.from,
                                gas: util.hexlify(tx.gas),
                                gasPrice: util.hexlify(tx.gasPrice),
                                hash: tx.hash,
                                input: util.hexlify(tx.input),
                                nonce: util.hexlify(tx.nonce),
                                vaule: util.hexlify(tx.value)
                            };
                            ['blockHash', 'blockNumber', 'to'].forEach(function(key) {
                                if (!tx[key]) { return; }
                                transaction[key] = util.hexlify(tx[key]);
                            });
                            client._sendResult(messageId, transaction);
                        }, function(error) {
                            client._sendError(messageId, errors.ServerError);
                        });
                        break;

                    case 'sendTransaction':
                        var signedTransaction = ensureHexString(params.signedTransaction);
                        getWeb3Promise('sendTransaction', signedTransaction).then(function(txid) {
                            client._sendResult(messageId, txid);
                        }, function(error) {
                            client._sendError(messageId, errors.ServerError);
                        });
                        break;

                    case 'estimateGas':
                        // @TODO: Check transaction is good; ensureTransaction()
                        var transaction = ensureTransaction(params.transaction);
                        getWeb3Promise('estimateGas', transaction).then(function(estimatedGas) {
                            client._sendResult(messageId, util.hexlify(estimatedGas));
                        }, function(error) {
                            client._sendError(messageId, errors.ServerError);
                        });
                        break;

                    case 'call':
                        // @TODO: Check transaction is good; ensureTransaction()
                        var transaction = ensureTransaction(params.transaction);
                        getWeb3Promise('call', transaction).then(function(result) {
                            client._sendResult(messageId, result);
                        }, function(error) {
                            client._sendError(messageId, errors.ServerError);
                        });
                        break;

                    case 'fundAccount':
                        if (self.network !== 'morden' || !faucetPrivateKey) { throw errors.MethodNotFound; }
                        getWeb3Promise('getTransactionCount', self.faucetAddress, 'pending').then(function(transactionCount) {
                            var transaction = new ethereumTx({
                                to: ensureHexString(params.address, 20),
                                gasPrice: util.hexlify(self.gasPrice),
                                gasLimit: util.hexlify(3000000),
                                nonce: util.hexlify(transactionCount),
                                value: util.hexlify(3141592653589793238)
                            });

                            transaction.sign(faucetPrivateKey);
                            var signedTransaction = util.hexlify(transaction.serialize().toString('hex'));

                            getWeb3Promise('sendRawTransaction', signedTransaction).then(function(txid) {
                                client._sendResult(messageId, txid);
                            }, function(error) {
                                console.log(error);
                                client._sendError(messageId, errors.ServerError);
                            });

                        }, function(error) {
                            client._sendError(messageId, errors.ServerError);
                        });
                        break;

                    case 'status':
                        var result = {
                            blockNumber: util.hexlify(self.blockNumber),
                            connections: util.hexlify(self.connections),
                            gasPrice: util.hexlify(self.gasPrice),
                            uptime: util.hexlify(self.uptime),
                        };
                        if (self.faucetAddress) { result.faucetAddress = self.faucetAddress; }
                        client._sendResult(messageId, result);
                        break;

                    default:
                        throw errors.MethodNotFound;
                }

            } catch (error) {
                console.log(error);
                client._sendError(messageId, (error.jsonError ? error: errors.ServerError));
            }
        });

        client.on("close", function (code, reason) {
            this.emit('debug', 'Closing ' + client._eid + '...');

            removeClientFilters(client);

            /*
            for (var filterId in client.ethersFilters) {
                client.ethersFilters[filterId].stopWatching();
            }
            client.ethersFilters = [];
            */

            delete clients[client._eid];
        });
    });

    function disconnectClients() {
        addresses = {};

        for (var clientId in clients) {
            clients[clientId]._sendError(0, errors.ServerError, null, true);
        }
        clients = {};
    }

    this.on('web3Connect', function(url, network) {
        console.log('web3.connect(' + url + ', ' + network + ')');

        // Start watching for new blocks
        resetFilters(false);
    });

    this.on('web3Error', function(error) {
        // No longer have a valid network
        network = null;
        networkHash = null;

        // Stop watching for new blocks
        resetFilters(true);
        self.web3.reset();

        // First failure, notify anyone who cares
        if (web3Connected) {
            web3Connected = false;
            disconnectClients();
            self.emit('web3Disconnect');
        }

        // Try reconnecting (may already be trying, it will figure that out)
        reconnectWeb3();
    });

    // If debugging is enabled, show all debug info (@TODO add verbosity?)
    if (this.debug) {
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

    var resetFilters = (function() {
        var gasPrice = null;
        Object.defineProperty(self, 'gasPrice', {
            enumerable: true,
            get: function() { return gasPrice; }
        });

        var blockNumber = 0;
        Object.defineProperty(self, 'blockNumber', {
            enumerable: true,
            get: function() { return blockNumber; }
        });

        var latestFilter = null, pendingFilter = null;

        var clientUpdates = {};
        function addUpdateAll(key, value) {
            for (var clientId in clients) {

                // Dedup data (eg. gasPrice almost never changes)
                var client = clients[clientId];
                if (client._lastValue[key] === value) { continue; }
                client._lastValue[key] = value;

                // Create the entry if it doesn't exist and set it
                var update = clientUpdates[clientId];
                if (!update) {
                    update = {};
                    clientUpdates[clientId] = update;
                }
                update[key] = value;
            }
        }

        function addUpdate(address, transaction) {
            var clientIds = addresses[address.toLowerCase()];
            if (!clientIds) { return; }

            var txid = transaction.hash;

            for (var clientId in clientIds) {
                var updates = clientUpdates[clientId];
                if (!updates) {
                    updates = {accounts: [{address: address, txid: [txid]}]};
                    clientUpdates[clientId] = updates;
                } else if (!updates.accounts) {
                    updates.accounts = [{address: address, txid: [txid]}];
                } else {
                    updates.accounts.push({address: address, txid: [txid]});
                }

                var client = clients[clientId];
                if (client) { client._checkAddress(address); }
/*
                console.log(transaction);
                getWeb3Promise('getTransactionReceipt', txid).then(function(receipt) {
                    console.log(receipt);
                }, function(error) {
                    console.log('eee', error);
                });
*/
            }
        }

        function sendUpdates() {
            for (var clientId in clientUpdates) {
                var client = clients[clientId];
                // @TODO: collapse address fields;
                // eg. {address: a, txid[b]}, {address: a, txid[c]} => {address: a, txid[b, c]}
                if (client) { client._sendResult(0, clientUpdates[clientId]); }
            }
            clientUpdates = {};
        }

        function processTransaction(transaction) {
            ['creates', 'from', 'to'].forEach(function(key) {
                var address = transaction[key];
                if (!address) { return; }

                addUpdate(address, transaction);
            });
        }

        return (function(disable) {
            // Remove any existing latest filter
            if (latestFilter) {
                latestFilter.stopWatching();
                latestFilter = null;
            }

            if (pendingFilter) {
                pendingFilter.stopWatching();
                pendingFilter = null;
            }

            if (disable) { return; }

            // Process all transactions in a block
            function updateBlock(blockHash) {

                // We aren't synced, so we would be saturated processing blocks
                if (!web3Synced) { return; }

                Promise.all([
                    getWeb3Promise('getBlockNumber'),
                    getWeb3Promise('getGasPrice'),
                    getWeb3Promise('getBlock', blockHash, true)
                ]).then(function(results) {
                    blockNumber = results[0];
                    gasPrice = '0x' + results[1].toString(16);
                    var block = results[2];

                    addUpdateAll('blockNumber', blockNumber);
                    addUpdateAll('gasPrice', gasPrice);


                    block.transactions.forEach(function(transaction) {
                        processTransaction(transaction);
                    });

                    sendUpdates();

                }, function(error) {
                    console.log(error);
                });
            }

            // Start monitoring new blocks for their transactions
            latestFilter = self.web3.eth.filter('latest', function(error, blockHash) {
                if (error) {
                     self.emit('web3Error', wrapError(error));
                     return;
                }

                // Are we falling behind?
                getWeb3Promise('getSyncing').then(function(result) {
                    web3Synced = (result === false || (result.highestBlock - result.currentBlock) <= 10);
                });

                updateBlock(blockHash);
            });

            // Bootstrap the blockNumber, gasPrice, etc.
            Promise.all([
                getWeb3Promise('getSyncing'),
                getWeb3Promise('getBlock', 'latest')
            ]).then(function(result) {
                web3Synced = (result[0] === false || (result[0].highestBlock - result[0].currentBlock) <= 10);
                updateBlock(result[1].hash);
            });

            // Start monitoring pending transactions
            pendingFilter = self.web3.eth.filter('pending', function(error, txid) {
                if (error) {
                     self.emit('web3Error', wrapError(error));
                     return;
                }

                self.web3.eth.getTransaction(txid, function(error, transaction) {
                    processTransaction(transaction);
                    sendUpdates();
                });
            });
        });
    })();


    var reconnectWeb3 = (function() {
        var retryTimer = null;

        return function() {

            // Already inflight attempt to reconnect
            if (retryTimer) { return; }

            // The following "retry" should ONLY be scheduled against this._retryTimer.
            // i.e. Inside it, the _retryTimer is defined, has fired and is expired.
            var retry = function () {
                self.web3.eth.getBlock(1, function (error, block) {

                    // Try reconnecting to web3
                    if (error) {
                        self.emit('debug', 'Error connecting to Web3 (retrying in 1s)');
                        retryTimer = setTimeout(retry, 1000);
                        retryTimer.unref();
                        return;
                    }

                    // We are connected!
                    networkHash = block.hash;
                    network = getNetworkName(block.hash);

                    // Maybe we reconnected due to a timeout, so never technically disconnected
                    if (!web3Connected) {
                        web3Connected = true;
                        self.emit('web3Connect', self.rpc, self.network);
                    }

                    // No longer retrying
                    retryTimer = null;

                    // Start watching for new blocks again
                    resetFilters(false);
                });
            }

            // Try to connect immediately (but use timeout, so clearTimeout works)
            retryTimer = setTimeout(retry, 0);
            retryTimer.unref();
        };
    })();


    // Service control
    (function() {
        var connections = 0;
        Object.defineProperty(self, 'connections', {
            enumeration: true,
            get: function() { return connections; }
        });

        var startTime = null;
        Object.defineProperty(self, 'uptime', {
            enumerable: true,
            get: function() {
                if (startTime === null) { return 0; }
                return ((new Date()).getTime() - startTime);
            }
        });

        var started = false, stopped = false;
        util.defineProperty(self, 'start', function(callback) {

            // Already started
            if (started) {
                self.emit('debug', 'start - already started');
               return;
            }
            started = true;

            // Our Web3 connection
            reconnectWeb3();

            // Count how many connections we have
            // We poll for this every 5 seconds once started (i.e. is only approximate)
            var countConnectionsTimer = setInterval(function() {
                if (stopped) {
                    if (countConnectionsTimer) {
                        clearInterval(countConnectionsTimer);
                        countConnectionsTimer = null;
                    }
                    return;
                }

                server.socket.getConnections(function(error, count) {
                    if (error) {
                        self.emit('debug', 'getConnections errror', wrapError(error));
                        return;
                    }
                    connections = count;
                })
            }, 5000);
            countConnectionsTimer.unref();

            // Start listening
            server.listen(self.port, function() {
                startTime = (new Date()).getTime();
                self.emit('listen');
                callback();
            });
        });

        // @TODO: This doesn't actually work yet...
        util.defineProperty(self, 'stop', function() {
            stopped = true;
        });

    })();

    (function() {
        if (!self.faucetAddress) { return; }
        setInterval(function() {
            self.web3.eth.getBalance(self.faucetAddress, function(error, balance) {
                balance = self.web3.fromWei(balance).toNumber();
                self.emit('debug', 'Faucet Balance: ' + balance);
                if (balance < 10000) {
                    var url = 'http://icarus.parity.io/rain/' + self.faucetAddress;
                    var request = http.request(url, function(response) {
                        var data = new Buffer(0);;
                        response.on('data', function(chunk) {
                            data = Buffer.concat([data, chunk]);
                        }).on('end', function() {
                            self.emit('debug', 'Faucet - ' + data.toString());
                        });
                    }).on('error', function(error) {
                        console.log('error', error);
                    });
                    request.end();
                }
            });
        }, 5 * 60 * 1000);
    })();

}
inherits(Server, EventEmitter);

/*
Server.prototype._updateLatestBlock = function() {
    var self = this;

    // Get the blockNumber
}
*/


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
