'use strict';

var fs = require('fs');

var Server = require('./lib/server.js');
var util = require('./lib/util.js');
var version = require('./package.json').version;


var opts = util.getopts({
    "certificate": '',
    "contract-config": '',
    "faucet-config": '',
    "intermediate-certificate": [],
    "rpc": "http://localhost:8545",
    "pid-file": '',
    "port": 5000,
    "private-key": '',
}, {
    debug: false,
    help: false,
    version: false
});

function ensureInteger(key, min, max) {
    var value = opts.options[key];
    if (parseInt(value) != value) {
        throw new Error(key + ' must be an integer');
    }

    value = parseInt(value);

    if (typeof(min) === 'number' && min > value) {
        throw new Error(key + ' must be ' + min + ' or greater');
    } else if (typeof(max) === 'number' && max < value) {
        throw new Error(key + ' must be ' + max + ' or less');
    }

    return value;
}

function loadFile(filename) {
    try {
        return fs.readFileSync(filename);
    } catch (error) {
        throw new Error('could not open file: ' + filename);
    }
}

function checkOptions() {
    if (opts.error) {
        throw new Error(opts.error);
    }

    if (opts.args.length) {
        throw new Error('invalid argument: ' + opts.args[0]);
    }

    var values = {
        port: ensureInteger('port'),

        // @TODO: Do some tests on these?
        rpc: (opts.options['rpc'] || null),
        pidFile: (opts.options['pid-file'] || null),
    }

    // Intermediate certificates require a SSL
    var intermediateCertificateCount = opts.options['intermediate-certificate'].length
    if (values.privateKey && intermediateCertificatesCount) {
        throw new Error('intermediate certificates require --private-key and --certificate');
    }

    // Using SSL
    if (opts.options['certificate'] && opts.options['private-key']) {

        // Load the private key and certificate
        values.privateKey = loadFile(opts.options['private-key']);
        values.certificate = loadFile(opts.options['certificate']);


        // Load the intermediate certificates
        values.intermediateCertificate = [];
        for (var i = 0; i < intermediateCertificateCount; i++) {
            values.intermediateCertificate.push(loadFile(opts.options['intermediate-certificate'][i]));
        }

    } else if (opts.options['certificate'] || opts.options['private-key']) {
        throw new Error('SSL requires both --certificate and --private-key');
    }

    // Load the contract storage configuration
    if (opts.options['contract-config']) {
        var contractConfig = loadFile(opts.options['contract-config']);
        try {
            values.contractConfig = JSON.parse(contractConfig);
        } catch (error) {
            throw new Error('invalid --contract-config JSON: ' + error);
        }
    }

    if (opts.options['faucet-config']) {
        try {
            values.faucetPrivateKey = loadFile(opts.options['faucet-config']).toString();
            if (!util.isHexString(values.faucetPrivateKey, 32)) {
                throw new Error('invalid faucet private key');
            }
        } catch (error) {
            values.faucetPrivateKey = '0x' + require('crypto').randomBytes(32).toString('hex');
            fs.writeFileSync(opts.options['faucet-config'], values.faucetPrivateKey);
        }
    }

    return values;
}

var values, errorMessage;
try {
    values = checkOptions();
} catch (error) {
    errorMessage = error.message;
}

// Show the help (-h or the input parameters had problems)
if (errorMessage || opts.flags.help) {
    console.log('');
    console.log("Command Line Interface - ethers.io/" + version);
    console.log('');
    console.log("Usage:");
    console.log("    node server.js [--help] [--version] [--debug] [--pid-file PATH]");
    console.log("                [--port PORT] [--rpc URL] [--contract-config PATH]");
    console.log("                [--faucet-config PATH]");
    console.log("                [--certificate CERT --private-key KEY");
    console.log('                   [ --intermediate-certificate CERT ] ... ]');
    console.log('');
    console.log('        --help               show this help screen');
    console.log('        --version            show the software version');
    console.log('        --debug              enable debug options');
    console.log('        --pid-file PATH      path to store PID file');
    console.log('');
    console.log('Service Options');
    console.log('        --rpc URL            url to rpc service (http://localhost:8545');
    console.log('        --contract-config PATH');
    console.log('                             config JSON for contract storage');
    console.log('');
    console.log('HTTP Options');
    console.log('        --port PORT          port to bind the server to (default: 5000)');
    console.log('');
    console.log('HTTPS Options');
    console.log('        --certificate CERT   SSL certificate (PEM format)');
    console.log('        --private-key KEY    SSL private key (PEM format)');
    console.log('        --intermediate-certificate CERT');
    console.log('                             SSL intermediate certificate(s) (PEM format)');
    console.log('');
    console.log('NOTES:');
    console.log('   - RPC URLs may be of the forms http://localhost:8545 (default) or');
    console.log('     ipc:/User/ricmoo/Library/Ethereum.geth.ipc');
    console.log('');
    if (errorMessage) {
        console.log('Error:', errorMessage);
        console.log('');
    }

// Show the version
} else if (opts.flags.version) {
    console.log("ethers.io/" + version);

// Start up the server :o)
} else {
    var server = new Server({
        // Service options
        rpc: values.rpc,
        port: values.port,
        contractConfig: values.contractConfig,
        debug: opts.flags.debug,

        faucetPrivateKey: values.faucetPrivateKey,

        // SSL Options
        certificate: values.certificate,
        privateKey: values.privateKey,
        intermediateCertificate: values.intermediateCertificate,
    });

    server.on('error', function(error) {
        /*
        if (error.message === "CONNECTION ERROR: Couldn't connect to node on IPC.") {
            console.log("ERROR: Could not connect to IPC " + values.ipcPath);
            process.exit();

        } else {
        */
        console.log('ERROR: ' + error.message);
        //}
    });

    server.start(function() {
        console.log('ethers.io is running on port', server.port);
    });

    if (values.pidFile) {
        fs.writeFile(values.pidFile, String(process.pid), function (error) {
            if (error) {
                process.exit("Could not write PID: " + error.message);
            }
        });
    }
}


//server = new Server();
//server.start();
