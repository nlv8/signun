const { secp256k1 } = require('../native');

module.exports = (function moduleFactory(impl) {
    return Object.freeze({
        privateKeyVerify(privateKey) {

        },
        publicKeyCreate(privateKey) {

        },
        sign(message, privateKey) {

        },
        verify(message, signature, publicKey) {

        }
    });
})(secp256k1);
