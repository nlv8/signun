const blake2 = require('./blake2');
const secp256k1 = require('./secp256k1');


module.exports = Object.freeze({
    ...blake2,
    secp256k1
});
