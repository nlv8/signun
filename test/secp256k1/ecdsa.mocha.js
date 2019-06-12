const { randomBytes } = require('crypto');
const path = require('path');

const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');

const { secp256k1 } = require('../../src/js');


chai.use(chaiAsPromised);
const expect = chai.expect;

describe('secp256k1', function describeSecp256k1() {
    describe('elliptic curve digital signature', function describeEcdsa() {
        it('can produce and verify a signature with the appropriate keypair', async function () {
            // Given
            const { privateKey, publicKey } = await generateKeyPair();
            const message = randomBytes(32);
            
            // When
            const { signature } =  await secp256k1.sign(message, privateKey);
            const isValid =  await secp256k1.verify(message, signature, publicKey);

            // Then
            expect(isValid).to.be.true;
        });

        it('can produce and verify a signature with an invalid public key', async function () {
            // Given
            const signKeyPair = await generateKeyPair();
            const verifyKeyPair = await generateKeyPair();
            const message = randomBytes(32);
            
            // When
            const { signature } =  await secp256k1.sign(message, signKeyPair.privateKey);
            const isValid =  await secp256k1.verify(message, signature, verifyKeyPair.publicKey);

            // Then
            expect(isValid).to.be.false;
        });
    });
});

async function generateKeyPair() {
    let privateKey;

    do {
        privateKey = randomBytes(32);
    } while (!(await secp256k1.privateKeyVerify(privateKey)));

    return {
        privateKey,
        publicKey: await secp256k1.publicKeyCreate(privateKey)
    };
};
