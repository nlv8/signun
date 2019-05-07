const { BINDINGS_NOT_COMPILED } = require('./util/messages')


try {
    const native = require('../../build/Release/signun.node');

    module.exports = Object.freeze(native);
} catch (err) {
    console.error(BINDINGS_NOT_COMPILED);

    throw err;
}
