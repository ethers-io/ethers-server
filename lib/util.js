var crypto = require('crypto');

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

function sha256(data) {
    if (!Buffer.isBuffer(data)) {
        throw new Error('data must be a Buffer');
    }

    var hasher = crypto.createHash('sha256');
    hasher.update(data);
    return hasher.digest();
}

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

module.exports = {
    getFileHash: getFileHash,
    getopts: getopts,
    sha256: sha256,
};
