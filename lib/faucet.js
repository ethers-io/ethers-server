'use strict';

var EthereumTx = require('ethereumjs-tx');
var ethereumUtil = require('ethereumjs-util');

var utils = require('./utils.js');

function Faucet(privateKey, web3) {
    if (!(this instanceof Faucet)) { throw new Error('missing new'); }

    if (!utils.isHexString(privateKey, 32)) {
        throw new Error('invalid faucetPrivateKey');
    }

    var address = '0x' + ethereumUtil.privateToAddress(privateKey).toString('hex');
    utils.defineProperty(this, 'address', address);

    privateKey = utils.hexOrBuffer(privateKey);

    var getWeb3Promise = utils.getWeb3Promise(web3);

    var self = this;

    utils.defineProperty(this, 'send', function(address, amountWei) {
        return new Promise(function(resolve, reject) {
            Promise.all([
                getWeb3Promise('getTransactionCount', self.address, 'pending'),
                getWeb3Promise('getGasPrice')
            ]).then(function (results) {
                var transaction = new EthereumTx({
                    to: utils.ensureAddress(address),
                    gasPrice: utils.hexlify(results[1]),
                    gasLimit: utils.hexlify(3000000),
                    nonce: utils.hexlify(results[0]),
                    value: utils.hexlify(amountWei)
                });
                transaction.sign(privateKey);
                var signedTransaction = utils.hexlify('0x' + transaction.serialize().toString('hex'));

                getWeb3Promise('sendRawTransaction', signedTransaction).then(function(txid) {
                    resolve(txid);
                }, function(error) {
                   reject(error);
                });
            }, function(error) {
                reject(error);
            });
         });
    });

    function checkBalance() {
        getWeb3Promise('getBalance', address, 'latest').then(function(balance) {
            balance = web3.fromWei(balance).toNumber();
            console.log('Faucet Balance: ' + balance);

            if (balance < 10000) {
                var url = 'http://icarus.parity.io/rain/' + address;
                utils.fetchUrl(url).then(function(body) {
                    console.log('Faucet - ' + body);
                });
            }
        }, function(error) {
            console.log('Faucet Error', error);
        });
    }

    setTimeout(function() {
        checkBalance();
    }, 5000);

    var poll = setInterval(function() {
        checkBalance();
    }, 5 * 60 * 1000);
}

// @TODO: EventEmitter

module.exports = Faucet;
