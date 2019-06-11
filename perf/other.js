var blake2 = require('blake2');

const data = Buffer.from('437cbc541a692edaefcf5de012c8386f03b294ed6336c9e75d1d93a4e5041d307e1c987b9634b66c690424e8830744782febf368cc691054f41e4c19ff2625fc', 'hex');
let result;
for (let i = 0; i < 10000; ++i) {
    var h = blake2.createHash('blake2b');

    h.update(data);
    result = h.digest('hex');
}

console.log(result);
