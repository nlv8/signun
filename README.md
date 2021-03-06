# signun

[![NPM version](https://img.shields.io/npm/v/@nlv8/signun.svg)](https://www.npmjs.com/package/@nlv8/signun)
[![Build Master](https://github.com/nlv8/signun/workflows/Build%20Master/badge.svg)](https://github.com/nlv8/signun/actions?query=workflow%3A%22Build+Master%22)
[![License](https://img.shields.io/github/license/nlv8/signun.svg)](LICENSE)

signun provides [N-API](https://nodejs.org/api/n-api.html#n_api_n_api) bindings to the following crypto libraries:

  * [secp256k1](https://github.com/bitcoin-core/secp256k1),
  * [BLAKE2](https://github.com/BLAKE2/BLAKE2).

## Installation

~~~~
npm i @nlv8/signun
~~~~

## Features

  * Digital Signature
    * Sync and async secp256k1 ECDSA.
      * Tunable performance characteristics in [bindings.gyp](bindings.gyp). Please see the documentation of [secp256k1](https://github.com/bitcoin-core/secp256k1) for the available settings.
      * Uses [GMP](https://gmplib.org/) if available.
  * Cryptographic Hash
    * Async BLAKE2b.
  
Runs on

  * Windows x86 (will not use GMP),
  * Linux x86/ARM (will use GMP if available),
  * Mac x86/ARM (will use GMP if available).

## Examples

### secp256k1 ECDSA

#### Sync

~~~~JavaScript
const { randomBytes } = require('crypto');
const { secp256k1 } = require('@nlv8/signun');


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
const { secp256k1 } = require('@nlv8/signun');


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

### BLAKE2

#### hash

~~~~JavaScript
const { randomBytes } = require('crypto');
const { blake2b } = require('@nlv8/signun');

(async function main() {
  const data = randomBytes(64);
  const hashLength = 64;

  const result = await blake2b.hash(data, hashLength);
})();
~~~~

#### keyedHash

~~~~JavaScript
const { randomBytes } = require('crypto');
const { blake2b } = require('@nlv8/signun');

(async function main() {
  const data = randomBytes(64);
  const key = randomBytes(64);
  const hashLength = 64;

  const result = await blake2b.keyedHash(data, key, hashLength);
})();
~~~~


## API

signun exports the following two objects.

### `secp256k1`

Asynchronous and synchronous bindings for secdp256k1-based ECDSA. By default, all functions are async, returning a Promise. However, by appending `Sync` at the end of the function name, one can invoke them synchronously.

#### `privateKeyVerify(privateKey)`

Verifies whether a Buffer is a valid private key.

  * `privateKey: Buffer`: A Buffer containing the candidate private key.

Returns `true` if the specified Buffer is a valid private key and `false` otherwise.

#### `publicKeyCreate(privateKey, isCompressed = true)`

Constructs a new public key corresponding to the specified private key.

  * `privateKey: Buffer`: A Buffer containing a valid private key.
  * `isCompressed: boolean = true`: Whether a compressed representation should be produced.

Returns a Buffer with the public key upon success.

Will throw/reject if the public key cannot be created from the specified data.

#### `sign(message, privateKey, options)`

Signs the message with the specified private key.

  * `message: Buffer`: The message to sign.
  * `privateKey: Buffer`: The private key with which the signature will be created.
  * `options: object`: Optional options object. Can only be used for synchronous invocations.
    * `data: Buffer`: Arbitrary data to be passed to the nonce function.
    * `noncefn: function`: A custom nonce function, with the following signature: `noncefn(message: Buffer, key: Buffer, algo: Buffer, data: Buffer, attempt: number): Buffer`.

Returns an object with the following properties upon success:

  * `signature: Buffer`: The actual signature.
  * `recovery: number`: The recovery id.

Will throw/reject if the signature cannot be created.

#### `verify(message, signature, publicKey)`

Verifies a signature against the specified message and public key.

   * `message: Buffer`: The message we think was signed.
   * `signature: Buffer`: The signature to be verified.
   * `publicKey`: The public key pair of the signing private key.

Returns `true` if the signature is valid and `false` otherwise.

### `blake2b`

Asynchronous BLAKE2b hashing.

#### `hash(data, hashLength)`

Hashes the specified data.

  * `data: Buffer`: The data to be hashed. Can be empty but must be a valid Buffer.
  * `hashLength: number`: The length of the hash. Must be between 1 and 64 (inclusive).

Returns the hash in a Buffer.

#### `keyedHash(data, key, hashLength)`

Produces the keyed hash of the specified data.

  * `data: Buffer`: The data to be hashed. Can be empty but must be a valid Buffer.
  * `key: Buffer`: The key to be used.
  * `hashLength: number`: The length of the hash. Must be between 1 and 64 (inclusive).

Returns the hash in a Buffer.

## Acknowledgements

This is an open source project maintained by [NLV8](https://nlv8.com/).

Original authors include [Viktor Simkó](https://github.com/ViktorSimko), [Tibor Balla](https://github.com/ballatibi) and [Attila Bagossy](https://github.com/battila7)

## Licence

signun is licensed under [Apache-2.0](https://github.com/battila7/signun/blob/master/LICENSE).

Licences of dependencies:

  * [secp256k1](https://github.com/bitcoin-core/secp256k1): [MIT](https://github.com/bitcoin-core/secp256k1/blob/master/COPYING)
  * [BLAKE2](https://github.com/BLAKE2/BLAKE2): Triple-licensed, using [Apache 2.0](https://github.com/BLAKE2/BLAKE2/blob/master/README.md)
