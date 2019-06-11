const { blake2b } = require('../native');
const guard = require('../util/guard');

const lengths = Object.freeze({
    MIN_HASH_LENGTH: 1,
    MAX_HASH_LENGTH: 64,
    KEY_LENGTH: 64
});

const messages = Object.freeze({
    INVALID_DATA: `Data must be a buffer.`,
    INVALID_HASH_LENGTH: `Hash length must be an integer between ${lengths.MIN_HASH_LENGTH} and ${lengths.MAX_HASH_LENGTH} (inclusive).`,
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

        guard.isIntegerBetweenInclusive(hashLength, lengths.MIN_HASH_LENGTH, lengths.MAX_HASH_LENGTH, messages.INVALID_HASH_LENGTH);

        return func(data, key, hashLength, data.length);
    };
};

module.exports = (function moduleFactory(impl) {
    return Object.freeze({
        hash: hashFactory(impl.hash),
        keyedHash: keyedHashFactory(impl.keyedHash),
    });
})(blake2b);
