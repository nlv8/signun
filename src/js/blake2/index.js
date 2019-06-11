const { blake2 } = require('../native');
const guard = require('../util/guard');


const lengths = Object.freeze({
    
});

const messages = Object.freeze({
    INVALID_DATA: `Data must be a buffer.`,
    INVALID_KEY: `Key must be a buffer.`
});

function hashFactory(func) {
    return function hash(data) {
        guard.isBuffer(data, messages.INVALID_DATA);

        return func(data);
    };
};

function keyedHashFactory(func) {
    return function keyedHash(data, key) {
        guard.isBuffer(data, messages.INVALID_DATA);

        guard.isBuffer(key, messages.INVALID_KEY);

        return func(data, key);
    };
};

module.exports = (function moduleFactory(impl) {
    return Object.freeze({
        hash: hashFactory(impl.hash),
        keyedHash: keyedHashFactory(impl.keyedHash),
    });
})(blake2);
