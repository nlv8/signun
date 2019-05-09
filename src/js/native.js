const BINDINGS_NOT_COMPILED = 'Native bindings are not compiled. This library however, can only be used with native bindings.';

try {
    const native = require('../../build/Release/signun.node');

    module.exports = Object.freeze(native);
} catch (err) {
    console.error(BINDINGS_NOT_COMPILED);

    throw err;
}
