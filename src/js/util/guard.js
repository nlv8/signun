const {} = require('./messages');


const guard = {
    isBuffer(obj, errorMessage) {
        if (!Buffer.isBuffer(obj)) {
            throw new TypeError(errorMessage);
        }
    },
    isBufferOfLength(obj, expectedLength, errorMessage) {
        guard.isBuffer(obj, errorMessage);

        if (obj.length !== expectedLength) {
            throw new RangeError(errorMessage);
        }
    },
    isBufferOfLengthAny(obj, acceptedLengths, errorMessage) {
        guard.isBuffer(obj, errorMessage);

        const hasAcceptedLength = acceptedLengths.some(accepted => obj.length === accepted);

        if (!hasAcceptedLength) {
            throw new RangeError(errorMessage);
        }
    },
    isFunction(obj, errorMessage) {
        if (!typeof obj === 'function') {
            throw new TypeError(errorMessage);
        }
    }
};

module.exports = Object.freeze(guard);
