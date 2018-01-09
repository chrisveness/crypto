/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* Crypto Test Harness - AES                                          (c) Chris Veness 2014-2018  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */


import Aes    from '../aes.js';
import AesCtr from '../aes-ctr.js';

// import chai from 'chai'; // BDD/TDD assertion library - uncomment for Node.js tests

const should = chai.should();


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* AES - test vectors: csrc.nist.gov/publications/fips/fips197/fips-197.pdf C.1                   */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

describe('aes fips test vectors', function() {
    const plaintext = vectorToBytes('00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff');

    const key128    = vectorToBytes('00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f');
    const cipher128 = vectorToBytes('69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a');

    const key192    = vectorToBytes('00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17');
    const cipher192 = vectorToBytes('dd a9 7c a4 86 4c df e0 6e af 70 a0 ec 0d 71 91');

    const key256    = vectorToBytes('00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f');
    const cipher256 = vectorToBytes('8e a2 b7 ca 51 67 45 bf ea fc 49 90 4b 49 60 89');

    it('encrypts Aes-128-bit test vector', function() { Aes.cipher(plaintext, Aes.keyExpansion(key128)).should.deep.equal(cipher128); });
    it('encrypts Aes-192-bit test vector', function() { Aes.cipher(plaintext, Aes.keyExpansion(key192)).should.deep.equal(cipher192); });
    it('encrypts Aes-256-bit test vector', function() { Aes.cipher(plaintext, Aes.keyExpansion(key256)).should.deep.equal(cipher256); });

    function vectorToBytes(v) { return v.split(/ /).map(i => parseInt('0x'+i)); }

    function bytesToVector(b) { return b.map(i => i<0x10 ? '0'+i.toString(16) : i.toString(16)).join(' '); }
});


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* Aes CTR: test Unicode text & password (ciphertext will be different on each invocation)        */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

describe('aes.ctr', function() {
    describe('unicode plaintext/password', function() {
    const origtext = 'My big secret סוד קצת بت سرية  ความลับบิต 位的秘密';

        const ciphertext128 = AesCtr.encrypt(origtext, 'pāšşŵōřđ', 128);
        const decrypttext128 = AesCtr.decrypt(ciphertext128, 'pāšşŵōřđ', 128);
        it('decrypts ciphertext to match original (unicode) text @ 128', function() { decrypttext128.should.equal(origtext); });

        const ciphertext192 = AesCtr.encrypt(origtext, 'pāšşŵōřđ', 192);
        const decrypttext192 = AesCtr.decrypt(ciphertext192, 'pāšşŵōřđ', 192);
        it('decrypts ciphertext to match original (unicode) text @ 192', function() { decrypttext192.should.equal(origtext); });

        const ciphertext256 = AesCtr.encrypt(origtext, 'pāšşŵōřđ', 256);
        const decrypttext256 = AesCtr.decrypt(ciphertext256, 'pāšşŵōřđ', 256);
        it('decrypts ciphertext to match original (unicode) text @ 256', function() { decrypttext256.should.equal(origtext); });
    });

    describe('various lengths of plaintext', function() {
        const password = Date().toString();

        const plaintext1 = '0';
        it('decrypts string of 1 @ 128', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext1, password, 128), password, 128) });
        it('decrypts string of 1 @ 192', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext1, password, 192), password, 192) });
        it('decrypts string of 1 @ 256', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext1, password, 256), password, 256) });

        const plaintext10 = '0123456789';
        it('decrypts string of 10 @ 128', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext10, password, 128), password, 128) });
        it('decrypts string of 10 @ 192', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext10, password, 192), password, 192) });
        it('decrypts string of 10 @ 256', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext10, password, 256), password, 256) });

        const plaintext100 = plaintext10.repeat(10);
        it('decrypts string of 100 @ 128', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext100, password, 128), password, 128) });
        it('decrypts string of 100 @ 192', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext100, password, 192), password, 192) });
        it('decrypts string of 100 @ 256', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext100, password, 256), password, 256) });

        const plaintext1k = plaintext100.repeat(10);
        it('decrypts string of 1k @ 128', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext1k, password, 128), password, 128) });
        it('decrypts string of 1k @ 192', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext1k, password, 192), password, 192) });
        it('decrypts string of 1k @ 256', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext1k, password, 256), password, 256) });

        const plaintext10k = plaintext1k.repeat(10);
        it('decrypts string of 10k @ 128', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext10k, password, 128), password, 128) });
        it('decrypts string of 10k @ 192', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext10k, password, 192), password, 192) });
        it('decrypts string of 10k @ 256', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext10k, password, 256), password, 256) });

        const plaintext100k = plaintext10k.repeat(10);
        it('decrypts string of 100k @ 128', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext100k, password, 128), password, 128) });
        it('decrypts string of 100k @ 192', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext100k, password, 192), password, 192) });
        it('decrypts string of 100k @ 256', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext100k, password, 256), password, 256) });

        const plaintext1M = plaintext100k.repeat(10);
        it('decrypts string of 1M @ 128', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext1M, password, 128), password, 128) });
        it('decrypts string of 1M @ 192', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext1M, password, 192), password, 192) });
        it('decrypts string of 1M @ 256', function() { AesCtr.decrypt(AesCtr.encrypt(plaintext1M, password, 256), password, 256) });
    });
});


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
