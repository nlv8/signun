# signun

[![NPM version](https://img.shields.io/npm/v/signun.svg)](https://www.npmjs.com/package/signun)
[![Build Status](https://dev.azure.com/battila7/signun/_apis/build/status/battila7.signun?branchName=master)](https://dev.azure.com/battila7/signun/_build/latest?definitionId=1&branchName=master)
[![License](https://img.shields.io/github/license/battila7/signun.svg)](LICENSE)

signun provides sync and async [N-API](https://nodejs.org/api/n-api.html#n_api_n_api) bindings to the following crypto libraries:

  * [secp256k1](https://github.com/bitcoin-core/secp256k1)
    * `privateKeyVerify`,
    * `publicKeyCreate`,
    * `sign`
      * Note: custom nonce function not yet supported for async, however it works with sync.
    * `verify`.

## Install

Install with npm or yarn:

~~~~
npm i signun --save
~~~~

~~~~
yarn add signun
~~~~

Please keep in mind, that you must have [GMP](https://gmplib.org/) installed (signun will not fallback to JS-only implementations).

## Examples

### secp256k1 ECDSA

#### Sync

~~~~JavaScript
const { randomBytes } = require('crypto');
const { secp256k1 } = require('signun');


let privateKey;

do {
    privateKey = randomBytes(32)
} while (!secp256k1.privateKeyVerifySync(privateKey));

const publicKey = secp256k1.publicKeyCreateSync(privateKey);

const message = randomBytes(32);

const signOptions = {
    // 32 bytes of custom data.
    data: null,
    // Custom nonce function.
    noncefn: null
}

const signResult =  secp256k1.signSync(message, privateKey, signOptions);

const verifyResult =  secp256k1.verifySync(message, signResult.signature, publicKey);

console.log(verifyResult);
~~~~

#### Async

~~~~JavaScript
const { randomBytes } = require('crypto');
const { secp256k1 } = require('signun');


(async function main() {
    let privateKey;

    do {
        privateKey = randomBytes(32)
    } while (!(await secp256k1.privateKeyVerify(privateKey)));
    
    const publicKey = await secp256k1.publicKeyCreate(privateKey);
    
    const message = randomBytes(32);
    
    // Custom nonce function is not supported yet for async.
    const signOptions = {
        // 32 bytes of custom data.
        data: null
    }
    
    const signResult =  await secp256k1.sign(message, privateKey, signOptions);
    
    const verifyResult =  await secp256k1.verify(message, signResult.signature, publicKey);
    
    console.log(verifyResult);    
})();
~~~~

## Acknowledgements

This project is kindly supported by:

  * [NLV8](https://nlv8.com/)

I'd like to give special thanks to [Viktor Simkó](https://github.com/ViktorSimko) and [Tibor Balla](https://github.com/ballatibi) for helping me out when I was lost :unicorn:

## License

signun is licensed under [Apache-2.0](https://github.com/battila7/signun/blob/master/LICENSE).

Licenses of dependencies:

  * [secp256k1](https://github.com/bitcoin-core/secp256k1): [MIT](https://github.com/bitcoin-core/secp256k1/blob/master/COPYING)
