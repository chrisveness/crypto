/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/*  Crypto Test Harness - AES                                         (c) Chris Veness 2014-2017  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* !! Note module.exports / require statement must be uncommented for these tests to work !!      */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

'use strict';

const chai = require('chai');  // BDD/TDD assertion library

const Aes = require('../aes.js');
Aes.Ctr = require('../aes-ctr.js');

chai.should();
const test = it; // just an alias


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* AES - test vectors: csrc.nist.gov/publications/fips/fips197/fips-197.pdf C.1                   */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

describe('aes', function() {
    const plaintext = vectorToBytes('00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff');

    const key128    = vectorToBytes('00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f');
    const cipher128 = vectorToBytes('69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a');

    const key192    = vectorToBytes('00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17');
    const cipher192 = vectorToBytes('dd a9 7c a4 86 4c df e0 6e af 70 a0 ec 0d 71 91');

    const key256    = vectorToBytes('00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f');
    const cipher256 = vectorToBytes('8e a2 b7 ca 51 67 45 bf ea fc 49 90 4b 49 60 89');

    test('Aes-128-bit test vector', function() { Aes.cipher(plaintext, Aes.keyExpansion(key128)).should.eql(cipher128); });
    test('Aes-192-bit test vector', function() { Aes.cipher(plaintext, Aes.keyExpansion(key192)).should.eql(cipher192); });
    test('Aes-256-bit test vector', function() { Aes.cipher(plaintext, Aes.keyExpansion(key256)).should.eql(cipher256); });

    function vectorToBytes(v) {
        const a = v.split(/ /);
        for (let i=0; i<a.length; i++) a[i] = parseInt('0x'+a[i]);
        return a;
    }

    function bytesToVector(b) {
        const v = b.slice(); // clone b
        for (let i=0; i<v.length; i++) {
            v[i] = v[i]<0x10 ? '0'+v[i].toString(16) : v[i].toString(16);
        }
        return v.join(' ');
    }
});


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* Aes CTR: test Unicode text & password (ciphertext will be different on each invocation)        */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

describe('aes.ctr', function() {
    const origtext = 'My big secret סוד קצת بت سرية  ความลับบิต 位的秘密';
    const ciphertext = Aes.Ctr.encrypt(origtext, 'pāšşŵōřđ', 256);
    const decrtext = Aes.Ctr.decrypt(ciphertext, 'pāšşŵōřđ', 256);

    test('decrypted ciphertext matches original text', function() { decrtext.should.equal(origtext); });
});


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
