"use strict";

// System libraries
var EventEmitter = require('events').EventEmitter;
var http = require('http');
var net = require('net');
var urlParse = require('url').parse;
var inherits = require('util').inherits;

// Third-party libraries
var ethereumTx = require('ethereumjs-tx');
var ethereumUtil = require('ethereumjs-util');
var Web3 = require('web3');
var ws = require("nodejs-websocket");

// Provider Engine
var FilterSubprovider = require('web3-provider-engine/subproviders/filters.js')
var FixtureSubprovider = require('web3-provider-engine/subproviders/fixture.js')
var ProviderEngine = require('web3-provider-engine');
var RpcSubprovider = require('web3-provider-engine/subproviders/rpc.js');

var BN = ethereumUtil.BN;

var Contracts = require('./contracts.js');
var Faucet = require('./faucet.js');
var utils = require('./utils.js');
var version = require('../package.json').version;

EventEmitter.defaultMaxListeners = 1000;

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
        error.originalStack = error.stack;
        error.stack = e.stack;
    }
    return error;
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



// Convert a URL into a provider; Currently http:// and ipc:// are supported.
function getProvider(rpc) {
    if (rpc.substring(0, 7) === 'http://' || rpc.substring(0, 8) === 'https://') {
        return new Web3.providers.HttpProvider(rpc);
    } else if (rpc.substring(0, 4) === 'ipc:') {
        return new Web3.providers.IpcProvider(rpc.substring(4), net);
    }

    throw new Error('unsupported RPC url: ' + rpc);
}

function Client(connection, server, cleanupFunc) {
    if (!(this instanceof Client)) { throw Error('missing new'); }
    var self = this;

    utils.defineProperty(this, 'connection', connection);
    utils.defineProperty(this, 'getWeb3Promise', utils.getWeb3Promise(server.web3));

    var updateClosed = utils.defineValue(this, 'closed', false);

    var updateServer = utils.defineValue(this, 'server', server);


    // @TODO: Store this in the server and keep an optimized list rather
    // than linear probing over all connections each time?
    var addresses = {};
    utils.defineProperty(this, 'watchAddress', function(address) {
        address = address.toLowerCase();
        addresses[address] = 'notSent';
        self.updateAddress(address);
    });

    utils.defineProperty(this, 'updateAddress', function(address, transaction) {
        address = address.toLowerCase();
        if (!addresses[address]) { return; }

        self.getWeb3Promise('getBalance', address, 'pending').then(function(balance) {
            balance = utils.hexlify(balance);
            if (balance === addresses[address]) { return; }
            addresses[address] = balance;
            var accountPayload = {address: address, balance: balance};
            if (transaction) { accountPayload.txid = transaction.hash; }
            self.sendResult(0, {accounts: [accountPayload]});
        }, function(error) {
            console.log(error);
        });
    });

    var lastValues = {};
    utils.defineProperty(this, 'updateValue', function(key, value) {
        if (lastValues[key] === value) { return; }
        lastValues[key] = value;

        var payload = {};
        payload[key] = value;

        self.sendResult(0, payload);
    });

    var filters = {};
    utils.defineProperty(this, 'addFilter', function(filterId, topics) {

        // Stop any existing filter
        this.removeFilter(filterId);

        // Install the new filter
        filters[filterId] = self.server.web3.eth.filter({
            topics: topics,
        }, function(error, result) {
            if (error) {
                console.log(error);
                return;
            }
            self.sendResult(0, {
                filterId: filterId,
                blockNumber: result.blockNumber,
                data: result.data
            });
        });
    });

    utils.defineProperty(this, 'removeFilter', function(filterId) {
        if (!filters[filterId]) { return; }

        filters[filterId].stopWatching(function() { });
        delete filters[filterId];
    });


    connection.on('close', function (code, reason) {
        if (self.closed) { return; }

        updateClosed(true);

        // Prevent retain-cyles
        updateServer(null);

        // Remove all filters
        Object.keys(filters).forEach(function(filterId) {
            self.removeFilter(filterId);
        });

        // Cleanup (@TODO: inherit eventEmitted and emit('terminate')?
        if (cleanupFunc) { cleanupFunc(); }
    });

    utils.defineProperty(this, 'close', function() {
        setImmediate(function() { connection.close(); });
    });

    // Make sure we set up an error handler before doing anything
    // (uncaught errors will kill the server)
    connection.on('error', function(error) {
        console.log(error);
        setImmediate(function() { connection.close(); });
    });

}

utils.defineProperty(Client.prototype, 'sendError', function(messageId, error, data, closeOnComplete) {
    var self = this;
    setImmediate(function() {
        if (self.closed) {
            console.log('cannot send error; dead: ' + self);
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
        if (closeOnComplete) { callback = (function() { self.close(); }); }
        self.connection.send(JSON.stringify(payload), callback);
    });
});

utils.defineProperty(Client.prototype, 'sendResult', function(messageId, result) {
    var self = this;
    setImmediate(function() {
        if (self.closed) {
            console.log('cannot send result; dead: ' + self);
            return;
        }
        ///console.log('>>>', result);

        self.connection.send(JSON.stringify({
            id: messageId,
            jsonrpc: '2.0',
            result: result,
        }));
    });
});


utils.defineProperty(Client.prototype, 'handleMessage', function(method, params) {
    var self = this;

    return new Promise(function(resolve, reject) {
        ///console.log('<<<', method, params);
        try {
            switch (method) {
                case 'watchAddress':
                    self.watchAddress(utils.ensureAddress(params.address));
                    resolve(true);
                    break;

                case 'registerFilter':
                    params.topics.forEach(function(topic) {
                        utils.ensureHexString(topic);
                    });
                    self.addFilter(utils.ensureNumber(params.filterId), params.topics);
                    resolve(true);
                    break;

                case 'unregisterFilter':
                    self.removeFilter(utils.ensureNumber(params.filterId));
                    resolve(true);
                    break;

                case 'sendTransaction':
                    var signedTransaction = utils.ensureHexString(params.signedTransaction);
                    self.getWeb3Promise('sendRawTransaction', signedTransaction).then(function(hash) {
                        resolve(hash);
                    }, function(error) {
                        console.log(error);
                        reject(errors.ServerError);
                    });
                    break;

                    /*
                    case 'deployContract':
                        deploySignedContract(params, function(error, result) {
                            if (error) {
                                client._sendError(messageId, error, error.reason);
                                return;
                            }
                            client._sendResult(messageId, result);
                            //client._checkAddress();
                        });
                        break;
                    */

                // Blockchain read-only

                case 'call':
                    var transaction = utils.ensureTransaction(params.transaction);
                    self.getWeb3Promise('call', transaction).then(function(result) {
                        resolve(result);
                    }, function(error) {
                        reject(errors.ServerError);
                    });
                    break;

                case 'estimateGas':
                    var transaction = utils.ensureTransaction(params.transaction);
                    self.getWeb3Promise('estimateGas', transaction).then(function(estimatedGas) {
                        resolve(utils.hexlify(estimatedGas));
                    }, function(error) {
                        reject(errors.ServerError);
                    });
                    break;

                case 'getBalance':
                    var address = utils.ensureAddress(params.address);
                    var blockNumber = utils.ensureBlockNumber(params.blockNumber);
                    self.getWeb3Promise('getBalance', address, blockNumber).then(function(result) {
                        resolve('0x' + result.toString(16));
                    }, function(error) {
                        reject(errors.ServerError);
                    });
                    break;

                case 'getBlock':
                    var block = params.block;
                    if (!(typeof(block) === 'number' && parseInt(block) === block && block >= 0) &&
                           !utils.isHexString(block, 32) && block !== 'latest') {
                        throw new Error('invalid block');
                    }
                    self.getWeb3Promise('getBlock', block).then(function(result) {
                        resolve(result);
                    }, function(error) {
                        reject(errors.ServerError);
                    });
                    break;

                case 'getGasPrice':
                    resolve(self.server.gasPrice);
                    break;

                case 'getTransaction':
                    var txid = utils.ensureHexString(params.txid, 32);
                    self.getWeb3Promise('getTransaction', txid).then(function(tx) {
                        var transaction = {
                            from: tx.from,
                            gasLimit: utils.hexlify(tx.gas),
                            gasPrice: utils.hexlify(tx.gasPrice),
                            hash: tx.hash,
                            data: utils.hexlify(tx.input),
                            nonce: tx.nonce,
                            vaule: utils.hexlify(tx.value)
                        };
                        ['blockHash', 'to'].forEach(function(key) {
                            if (!tx[key]) { return; }
                            transaction[key] = utils.hexlify(tx[key]);
                        });
                        if (tx.blockNumnber) { transaction.blockNumber = tx.blockNumber; }

                        resolve(transaction);
                    }, function(error) {
                        reject(errors.ServerError);
                    });
                    break;

                case 'getTransactionCount':
                    var address = utils.ensureAddress(params.address);
                    var blockNumber = utils.ensureBlockNumber(params.blockNumber);
                    self.getWeb3Promise('getTransactionCount', address, blockNumber).then(function(result) {
                        resolve('0x' + (new BN(result)).toString(16));
                    }, function(error) {
                        reject(errors.ServerError);
                    });
                    break;


                // @TODO: getTransactionReceipt

                // Maintenance

                case 'fundAccount':
                    if (self.server.network !== 'morden' || !faucet) { throw errors.MethodNotFound; }
                    faucet.send(utils.ensureAddress(params.address), '0x2b992ddfa23249d6').then(function(txid) {
                        resolve(txid);
                    }, function(error) {
                        reject(errors.ServerError);
                    });
                    break;

                case 'status':
                    var result = {
                        blockNumber: utils.hexlify(self.server.blockNumber),
                        connections: utils.hexlify(self.server.connections),
                        gasPrice: utils.hexlify(self.server.gasPrice),
                        uptime: utils.hexlify(self.server.uptime),
                    };
                    if (self.faucet) { result.faucetAddress = self.faucet.address; }
                    resolve(result);
                    break;

                default:
                    reject(errors.MethodNotFound);
            }
        } catch (error) {
            console.log('ERROR', error);
            reject(error.jsonError ? error: errors.ServerError);
        }
    });
});


function Server(options) {
    if (!(this instanceof Server)) { throw Error('missing new'); }

    var self = this;

    utils.defineProperty(this, 'rpc', options.rpc || 'http://localhost:8545');
    utils.defineProperty(this, 'debug', (options.debug === true));

    // The storage syste for contracts
    this._contracts = new Contracts(options.contractConfig);

    var server = null;

    // Connection to the Ethereum node
    utils.defineProperty(this, 'web3', (function() {
        var engine = new ProviderEngine()
        var web3 = new Web3(engine)

        var getWeb3Promise = utils.getWeb3Promise(web3);

        engine.addProvider(new FixtureSubprovider({
            web3_clientVersion: 'ethers.io/' + version + '/javascript',
            net_listening: true,
            eth_hashrate: '0x00',
            eth_mining: false,
            eth_syncing: true,
        }));

        engine.addProvider(new FilterSubprovider())

        engine.addProvider(new RpcSubprovider({ rpcUrl: self.rpc }))

        var updateBlockNumber = utils.defineValue(self, 'blockNumber', 0);
        var updateGasPrice = utils.defineValue(self, 'gasPrice', null);
        var updateNetwork = utils.defineValue(self, 'network', null);
        //var updateWeb3Connected = utils.defineValue(self, 'web3Connected', false);

        var reconnectTimer = null;
        function connect() {
            Promise.all([
                getWeb3Promise('getBlock', 1),
                getWeb3Promise('getGasPrice'),
                getWeb3Promise('getBlockNumber'),
            ]).then(function(results) {
                if (reconnectTimer) {
                    clearInterval(reconnectTimer);
                    reconnectTimer = null;
                }

                if (self.network) { return; }

                updateBlockNumber(results[2]);
                updateGasPrice('0x' + results[1].toString(16));
                updateNetwork(getNetworkName(results[0].hash));
                self.emit('web3Connect', self.network);

            }, function(error) {
                console.log(error);
            });
        }
        connect();

        engine.on('block', function(block) {
            if (!self.network) { return; }

            updateBlockNumber(parseInt(block.number.toString('hex'), 16));
            getWeb3Promise('getGasPrice').then(function(gasPrice) {
                updateGasPrice('0x' + gasPrice.toString(16));
            }, function(error) {
                console.log(error);
            })

            self.emit('block', block);
        });

        engine.on('error', function(error) {
            console.log('web3Error:', error);
            if (!self.network) { return; }

            updateNetwork(null);
            reconnectTimer = setInterval(function() { connect(); }, 1000);
            reconnectTimer.unref();
            self.emit('web3Disconnect');
        });

        // Count how many connections we have
        var updateConnections = utils.defineValue(self, 'connections', 0);
        setInterval(function() {
            server.socket.getConnections(function(error, count) {
                if (error) {
                    self.emit('debug', 'getConnections errror', wrapError(error));
                    return;
                }
                updateConnections(count);
            })
        }, 5000).unref();

        var startTime = null;
        Object.defineProperty(self, 'uptime', {
            enumerable: true,
            get: function() {
                if (startTime === null) { return 0; }
                return ((new Date()).getTime() - startTime);
            }
        });

        var pendingFilter = null;
        utils.defineProperty(self, 'start', function(callback) {

            // Start watching the blockchain
            engine.start();
            pendingFilter = web3.eth.filter('pending', function(error, hash) {
                web3.eth.getTransaction(hash, function(error, transaction) {
                    if (error) {
                        console.log(error);
                        return;
                    }
                    if (!transaction) { return; }
                    self.emit('transaction', transaction);
                });
            });

            // Already started
            if (startTime !== null) {
                self.emit('debug', 'start - already started');
                return;
            }
            startTime = (new Date()).getTime();

            // Start listening
            server.listen(self.port, function() {
                self.emit('listen');
                callback();
            });
        });

/*
        this.on('stop', function() {
            if (pendingFilter) {
                pendingFilter.stopWatching();
                pendingFilter = null;
            }

            engine.stop();
        });
*/
        return web3;
    })());;

    // A faucet (for testnet) if on the morden network
    utils.defineProperty(this, 'faucet', (function() {
        if (options.faucetPrivateKey) {
            return new Faucet(options.faucetPrivateKey, this.web3)
        }
        return null;
    })());


    // Create a promise for a web3 call
    //var getWeb3Promise = utils.getWeb3Promise(this.web3);

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

    utils.defineProperty(this, 'port', options.port || 5000);

    Object.defineProperty(this, 'totalConnections', {
        get: function() { return (nextClientId - 1); }
    });


    var nextClientId = 1;
    var clients = {};

    var self = this;

    // Create the server
    var server = createServer(function(connection) {
        var clientId = nextClientId++;

        var client = new Client(connection, self, function() {
            delete clients[clientId];
        });
        clients[clientId] = client;

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
        if (connection.headers && connection.headers.origin) {
            var hostname = urlParse(connection.headers.origin).hostname;
            if (hostname) { origin = hostname; }
        }

        // @TODO: Add options to specify allowed origins and validate here

        self.emit('debug', 'connection - ' + origin);

        // We are not on good terms with our web3 right now
        if (!self.network) {
            client.sendError(0, errors.ServerError, null, true);
            return;
        }

        // Check the basics (i.e. /v2/NETWORK)
        var comps = (connection.path || '').split('/');
        if (comps.length !== 3 || comps[0] !== '' || comps[1] !== 'v2') {
            client.sendError(0, errors.InvalidRequest, {invalidPath: connection.path}, true);
            return;
        }

        // Check this is the expected network
        if (comps[2] !== self.network) {
            client.sendError(0, errors.InvalidRequest, {
                network: comps[2],
                expectedNetwork: self.network
            }, true);
            return;
        }

        // Handle text
        connection.on('text', function(text) {
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
                client.sendError(messageId, errors.ParseError, null, true);
                return;
            }

            var params = payload.params[0];
            if (!params) { params = {}; }
            client.handleMessage(payload.method, params).then(function(result) {
                client.sendResult(messageId, result);
            }, function(error) {
                client.sendError(messageId, error);
            });
        });
    });

    /*
    function disconnectClients() {
        clients.forEach(function(client) {
            client.sendError(0, errors.ServerError, null, true);
            client.close();
        });
    }
    */

    this.on('web3Connect', function(network) {
        console.log('web3.connect(' + self.network + ')');
    });

    this.on('web3Disconnect', function() {
        console.log('web3.dicconnect()');
    });

    this.on('web3Error', function(error) {
        console.log(error.message, error._web3);
    });

    // If debugging is enabled, show all debug info (@TODO add verbosity?)
    if (this.debug) {
        this.on('debug', function(message, error) {
            console.log('DEBUG: ' + message);
            if (error) {
                console.log(error);
                console.trace(error);
            }
        });
    }



    var lastBlockNumber = null;
    self.on('block', function(block) {
        var blockNumber = parseInt(block.number.toString('hex'), 16);
        if (lastBlockNumber === null) { lastBlockNumber = blockNumber; }
        while (lastBlockNumber <= blockNumber) {
            for (var clientId in clients) {
                var client = clients[clientId];
                client.updateValue('blockNumber', utils.hexlify(lastBlockNumber));
            }
            lastBlockNumber++;
        }

        var gasPrice = utils.hexlify(self.gasPrice);
        for (var clientId in clients) {
            clients[clientId].updateValue('gasPrice', gasPrice);
        }
    });

    self.on('transaction', function(transaction) {
        ['creates', 'from', 'to'].forEach(function(key) {
            var address = transaction[key];
            if (!address) { return; }

            for (var clientId in clients) {
                clients[clientId].updateAddress(address, transaction);
            }
        });
    });

}

inherits(Server, EventEmitter);

module.exports = Server;
