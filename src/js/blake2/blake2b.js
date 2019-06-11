const { blake2b } = require('../native');
const guard = require('../util/guard');


const HASH_LENGTH = Object.freeze({
    '64': 64,
    '32': 32,
    '16': 16,
    '8': 8
});

const lengths = Object.freeze({
    KEY_LENGTH: 64
});

const messages = Object.freeze({
    INVALID_DATA: `Data must be a buffer.`,
    INVALID_KEY: `Key must be a buffer of length ${lengths.KEY_LENGTH}`
});

function hashFactory(func) {
    return function hash(data, hashLength) {
        guard.isBuffer(data, messages.INVALID_DATA);

        return func(data, hashLength);
    };
};

function keyedHashFactory(func) {
    return function keyedHash(data, key, hashLength) {
        guard.isBuffer(data, messages.INVALID_DATA);

        return func(data, key, hashLength, data.length);
    };
};

module.exports = (function moduleFactory(impl) {
    return Object.freeze({
        HASH_LENGTH,

        hash: hashFactory(impl.hash),
        keyedHash: keyedHashFactory(impl.keyedHash),
    });
})(blake2b);
