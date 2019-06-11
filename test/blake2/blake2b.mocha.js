const path = require('path');

const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');

const { blake2b } = require('../../src/js');


chai.use(chaiAsPromised);
const expect = chai.expect;

const testDataPath = path.resolve(__dirname, '..', '..', 
    'dependencies', 'BLAKE2', 'testvectors', 'blake2-kat.json');

const testData = (function loadTestData(p) {
    const data = require(p)
        .filter(testCase => testCase.hash == 'blake2b');

    const withoutKey = data
        .filter(testCase => testCase.key == '');

    const withKey = data
        .filter(testCase => testCase.key != '');
    
    return {
        withoutKey,
        withKey
    };
})(testDataPath);

describe('blake2b', function describeBlake2b() {
    describe('without key', function describeWithoutKey() {
        testData.withoutKey.forEach(testWithoutKey);
    });

    describe('with key', function describeWithoutKey() {
        testData.withKey.forEach(testWithKey);
    });
});

function testWithoutKey(testCase) {
    it(`should correctly hash "${testCase.in}"`, async function () {
        // Given
        const data = Buffer.from(testCase.in, 'hex');

        // When
        const result = await blake2b.hash(data, 64);

        // Then
        const resultHex = result.toString('hex');
        expect(resultHex).to.be.equal(testCase.out);
    });
};

function testWithKey(testCase) {
    it(`should correctly hash "${testCase.in}" with key "${testCase.key}"`, async function () {
        // Given
        const data = Buffer.from(testCase.in, 'hex');
        const key = Buffer.from(testCase.key, 'hex');

        // When
        const result = await blake2b.keyedHash(data, key, 64);

        // Then
        const resultHex = result.toString('hex');
        expect(resultHex).to.be.equal(testCase.out);
    });
};
