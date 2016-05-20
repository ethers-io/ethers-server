ethers-server
=============

Exposes an Ethereum node (via RPC or IPC) via [WebSockets](https://en.wikipedia.org/wiki/WebSocket) for efficient communications using the [ethers-web3 package](https://github.com/ethers-io/ethers-web3).

Features
- Light-weight WebSockets (so no polling is requried)
- Secure (wss://) or insecure (ws://) connections supported


Installing
----------

```
npm install ethers-server
```


Command Line Interface
----------------------

```
/Users/ethers> node server.js --help

Command Line Interface - ethers.io/0.0.1

Usage:
    node server.js [--help] [--version] [--debug] [--pid-file PATH]
                [--port PORT] [--rpc URL] [--contract-config PATH]
                [--certificate CERT --private-key KEY
                   [ --intermediate-certificate CERT ] ... ]

        --help               show this help screen
        --version            show the software version
        --debug              enable debug options
        --pid-file PATH      path to store PID file

Service Options
        --rpc URL            url to ethereum rpc service
        --contract-config PATH
                             config JSON for contract storage

HTTP Options
        --port PORT          port to bind the server to (default: 5000)

HTTPS Options
        --certificate CERT   SSL certificate (PEM format)
        --private-key KEY    SSL private key (PEM format)
        --intermediate-certificate CERT
                             SSL intermediate certificate(s) (PEM format)
```

**Notes:**
* You can specify as many `--intermediate-certificate` options as you require.
* The `--rpc URL` options can accept either an IPC URL (e.g. `ipc:/User/ethers/Library/Ethereum/geth.ipc`) or HTTP URL (e.g. `http://localhost:8545`).


License
-------

The *ethers* library is released under the MIT License.

The *web3* library is available under the LGPL-3.0 license. This should not affect you unless you modify the source of the embedded web3, in which case those (and only those) changes are swept into the LGPL-3.0 license.

