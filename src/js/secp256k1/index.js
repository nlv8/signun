const { secp256k1 } = require('../native');
const guard = require('../util/guard');


const lengths = Object.freeze({
    DATA: 32,
    MESSAGE: 32,
    PRIVATE_KEY: 32,
    PUBLIC_KEY1: 33,
    PUBLIC_KEY2: 65,
    SIGNATURE: 64
});

const messages = Object.freeze({
    INVALID_DATA: `Data must be a buffer of length ${lengths.DATA}.`,
    INVALID_MESSAGE: `The message must be a Buffer of length ${lengths.MESSAGE}.`,
    INVALID_NONCE_FUNCTION: `nonceFunction must be a callable function.`,
    INVALID_PRIVATE_KEY: `The private key must be a Buffer of length ${lengths.PRIVATE_KEY}.`,
    INVALID_PUBLIC_KEY: `The public key must be a Buffer of length ${lengths.PUBLIC_KEY1} or ${lengths.PUBLIC_KEY2}.`,
    INVALID_SIGNATURE: `The signature must be a Buffer of length ${lengths.SIGNATURE}.`
});

const UNSET_NONCE_FUNCTION = null;
const UNSET_SIGN_DATA = null;

module.exports = (function moduleFactory(impl) {
    return Object.freeze({
        privateKeyVerifySync(privateKey) {
            guard.isBufferOfLength(privateKey, lengths.PRIVATE_KEY, messages.INVALID_PRIVATE_KEY);

            return impl.privateKeyVerifySync(privateKey);
        },

        privateKeyVerify(privateKey) {
            guard.isBufferOfLength(privateKey, lengths.PRIVATE_KEY, messages.INVALID_PRIVATE_KEY);

            return impl.privateKeyVerify(privateKey);
        },

        publicKeyCreateSync(privateKey, isCompressed = true) {
            guard.isBufferOfLength(privateKey, lengths.PRIVATE_KEY, messages.INVALID_PRIVATE_KEY);

            return impl.publicKeyCreateSync(privateKey, !!isCompressed);
        },

        publicKeyCreate(privateKey, isCompressed = true) {
            guard.isBufferOfLength(privateKey, lengths.PRIVATE_KEY, messages.INVALID_PRIVATE_KEY);

            return impl.publicKeyCreate(privateKey, !!isCompressed);
        },

        signSync(message, privateKey, { data, noncefn }) {
            guard.isBufferOfLength(message, lengths.MESSAGE, messages.INVALID_MESSAGE);

            guard.isBufferOfLength(privateKey, lengths.PRIVATE_KEY, messages.INVALID_PRIVATE_KEY);

            if (data) {
                guard.isBufferOfLength(data, lengths.DATA, messages.INVALID_DATA);
            }

            if (noncefn) {
                guard.isFunction(noncefn, messages.INVALID_NONCE_FUNCTION);
            }

            return impl.signSync(message, privateKey, noncefn || UNSET_NONCE_FUNCTION, data || UNSET_SIGN_DATA);
        },

        sign(message, privateKey, { data, noncefn }) {
            guard.isBufferOfLength(message, lengths.MESSAGE, messages.INVALID_MESSAGE);

            guard.isBufferOfLength(privateKey, lengths.PRIVATE_KEY, messages.INVALID_PRIVATE_KEY);

            if (data) {
                guard.isBufferOfLength(data, lengths.DATA, messages.INVALID_DATA);
            }

            if (noncefn) {
                guard.isFunction(noncefn, messages.INVALID_NONCE_FUNCTION);
            }

            return impl.sign(message, privateKey, noncefn || UNSET_NONCE_FUNCTION, data || UNSET_SIGN_DATA);
        },

        verifySync(message, signature, publicKey) {
            guard.isBufferOfLength(message, lengths.MESSAGE, messages.INVALID_MESSAGE);

            guard.isBufferOfLength(signature, lengths.SIGNATURE, messages.INVALID_SIGNATURE);

            guard.isBufferOfLengthAny(publicKey, [lengths.PUBLIC_KEY1, lengths.PUBLIC_KEY2], messages.INVALID_PUBLIC_KEY);

            return impl.verifySync(message, signature, publicKey);
        },

        verify(message, signature, publicKey) {
            guard.isBufferOfLength(message, lengths.MESSAGE, messages.INVALID_MESSAGE);

            guard.isBufferOfLength(signature, lengths.SIGNATURE, messages.INVALID_SIGNATURE);

            guard.isBufferOfLengthAny(publicKey, [lengths.PUBLIC_KEY1, lengths.PUBLIC_KEY2], messages.INVALID_PUBLIC_KEY);

            return impl.verify(message, signature, publicKey);
        }
    });
})(secp256k1);
