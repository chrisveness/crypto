/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* Crypto Test Harness - AES                                          (c) Chris Veness 2014-2019  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

import Aes    from '../src/aes.js';
import AesCtr from '../src/aes-ctr.js';

if (typeof window == 'undefined') { // node
    import('chai').then(chai => { global.should = chai.should(); });
} else {                            // browser
    // eslint-disable-next-line no-undef
    window.should = chai.should();
}

// just for this test suite!
String.prototype.toBytes = function() { return this.replace(/ /g, '').match(/(..?)/g).map(b => parseInt('0x'+b)); };
String.prototype.toWords = function() { return this.split(/ /).map(w => w.match(/(..?)/g).map(b => parseInt('0x'+b))); };
Array.prototype.toByteStr = function() { return this.map(b => b.toString(16).padStart(2, '0')).join(' '); };
Array.prototype.toWordStr = function() { return this.map(w => w.map(b => b.toString(16).padStart(2, '0')).join('')).join(' '); };


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* AES - test vectors: csrc.nist.gov/publications/fips/fips197/fips-197.pdf appendices A, C       */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

describe('nist fips 197 §a key expansion', function() {
    this.slow(2); // 2 ms

    const key128      = '2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c';
    const schedule128 = '2b7e1516 28aed2a6 abf71588 09cf4f3c'; // 1st 4 words

    const key192      = '8e 73 b0 f7 da 0e 64 52 c8 10 f3 2b 80 90 79 e5 62 f8 ea d2 52 2c 6b 7b';
    const schedule192 = '8e73b0f7 da0e6452 c810f32b 809079e5 62f8ead2 522c6b7b'; // 1st 6 words

    const key256      = '60 3d eb 10 15 ca 71 be 2b 73 ae f0 85 7d 77 81 1f 35 2c 07 3b 61 08 d7 2d 98 10 a3 09 14 df f4';
    const schedule256 = '603deb10 15ca71be 2b73aef0 857d7781 1f352c07 3b6108d7 2d9810a3 0914dff4'; // 1st 8 words

    it('Aes-128-bit key expansion test vector', function() {
        Aes.keyExpansion(key128.toBytes()).slice(0, 4).should.deep.equal(schedule128.toWords());
    });
    it('Aes-192-bit key expansion test vector', function() {
        Aes.keyExpansion(key192.toBytes()).slice(0, 6).should.deep.equal(schedule192.toWords());
    });
    it('Aes-256-bit key expansion test vector', function() {
        Aes.keyExpansion(key256.toBytes()).slice(0, 8).should.deep.equal(schedule256.toWords());
    });

});

describe('nist fips 197 §c aes vectors', function() {
    this.slow(2); // 2 ms

    const plaintext = '00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff';

    const key128    = '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f';
    const cipher128 = '69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a';

    const key192    = '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17';
    const cipher192 = 'dd a9 7c a4 86 4c df e0 6e af 70 a0 ec 0d 71 91';

    const key256    = '00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f';
    const cipher256 = '8e a2 b7 ca 51 67 45 bf ea fc 49 90 4b 49 60 89';

    it('Aes-128-bit cipher test vector', function() {
        Aes.cipher(plaintext.toBytes(), Aes.keyExpansion(key128.toBytes())).should.deep.equal(cipher128.toBytes());
    });
    it('Aes-192-bit cipher test vector', function() {
        Aes.cipher(plaintext.toBytes(), Aes.keyExpansion(key192.toBytes())).should.deep.equal(cipher192.toBytes());
    });
    it('Aes-256-bit cipher test vector', function() {
        Aes.cipher(plaintext.toBytes(), Aes.keyExpansion(key256.toBytes())).should.deep.equal(cipher256.toBytes());
    });

});


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* NIST AES-CTR - test vectors: csrc.nist.gov/publications/detail/sp/800-38a/final                */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

describe('nist sp 800-38a aes-ctr example vectors', function() {
    this.slow(4); // 4 ms

    const counter =
        'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff';
    const plaintext =
        '6bc1bee22e409f96e93d7e117393172a'+
        'ae2d8a571e03ac9c9eb76fac45af8e51'+
        '30c81c46a35ce411e5fbc1191a0a52ef'+
        'f69f2445df4f9b17ad2b417be66c3710';

    it('verifies CTR-AES128.Encrypt §F.5.1, CTR-AES128.Decrypt §F.5.2', function() {
        const key128 =
            '2b7e151628aed2a6abf7158809cf4f3c';
        const ciphertext128 =
            '874d6191b620e3261bef6864990db6ce'+
            '9806f66b7970fdff8617187bb9fffdff'+
            '5ae4df3edbd5d35e5b4f09020db03eab'+
            '1e031dda2fbe03d1792170a0f3009cee';
        AesCtr.nistEncryption(plaintext.toBytes(), key128.toBytes(), counter.toBytes()).should.deep.equal(ciphertext128.toBytes());
        AesCtr.nistDecryption(ciphertext128.toBytes(), key128.toBytes(), counter.toBytes()).should.deep.equal(plaintext.toBytes());
    });

    it('verifies CTR-AES192.Encrypt §F.5.3, CTR-AES192.Decrypt §F.5.4', function() {
        const key192 =
            '8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b';
        const ciphertext192 =
            '1abc932417521ca24f2b0459fe7e6e0b'+
            '090339ec0aa6faefd5ccc2c6f4ce8e94'+
            '1e36b26bd1ebc670d1bd1d665620abf7'+
            '4f78a7f6d29809585a97daec58c6b050';
        AesCtr.nistEncryption(plaintext.toBytes(), key192.toBytes(), counter.toBytes()).should.deep.equal(ciphertext192.toBytes());
        AesCtr.nistDecryption(ciphertext192.toBytes(), key192.toBytes(), counter.toBytes()).should.deep.equal(plaintext.toBytes());
    });

    it('verifies CTR-AES256.Encrypt §F.5.5, CTR-AES256.Decrypt §F.5.6', function() {
        const key256 =
            '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4';
        const ciphertext256 =
            '601ec313775789a5b7a7f504bbf3d228'+
            'f443e3ca4d62b59aca84e990cacaf5c5'+
            '2b0930daa23de94ce87017ba2d84988d'+
            'dfc9c58db67aada613c2dd08457941a6';
        AesCtr.nistEncryption(plaintext.toBytes(), key256.toBytes(), counter.toBytes()).should.deep.equal(ciphertext256.toBytes());
        AesCtr.nistDecryption(ciphertext256.toBytes(), key256.toBytes(), counter.toBytes()).should.deep.equal(plaintext.toBytes());
    });
});


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* Aes CTR: test Unicode text & password (ciphertext will be different on each invocation)        */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

describe('aes.ctr', function() {
    this.timeout(10e3); // 10 sec

    describe('unicode plaintext/password', function() {
        this.slow(4); // 4 ms
        const origtext = 'My big secret סוד קצת بت سرية  ความลับบิต 位的秘密';
        const password = 'pāšşŵōřđ';

        it('en/decrypts ciphertext to match original (unicode) text @ 128', function() {
            const ciphertext128 = AesCtr.encrypt(origtext, password, 128);
            const decrypttext128 = AesCtr.decrypt(ciphertext128, password, 128);
            decrypttext128.should.equal(origtext);
        });

        it('en/decrypts ciphertext to match original (unicode) text @ 192', function() {
            const ciphertext192 = AesCtr.encrypt(origtext, password, 192);
            const decrypttext192 = AesCtr.decrypt(ciphertext192, password, 192);
            decrypttext192.should.equal(origtext);
        });

        it('en/decrypts ciphertext to match original (unicode) text @ 256', function() {
            const ciphertext256 = AesCtr.encrypt(origtext, password, 256);
            const decrypttext256 = AesCtr.decrypt(ciphertext256, password, 256);
            decrypttext256.should.equal(origtext);
        });

    });

    describe('various lengths of plaintext', function() {
        this.slow(8); // 8 ms
        const password = Date().toString();

        const plaintext1 = '0';
        it('en/decrypts string of 1 @ 128', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext1, password, 128), password, 128).should.equal(plaintext1);
        });
        it('en/decrypts string of 1 @ 192', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext1, password, 192), password, 192).should.equal(plaintext1);
        });
        it('en/decrypts string of 1 @ 256', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext1, password, 256), password, 256).should.equal(plaintext1);
        });

        const plaintext10 = '0123456789';
        it('en/decrypts string of 10 @ 128', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext10, password, 128), password, 128).should.equal(plaintext10);
        });
        it('en/decrypts string of 10 @ 192', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext10, password, 192), password, 192).should.equal(plaintext10);
        });
        it('en/decrypts string of 10 @ 256', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext10, password, 256), password, 256).should.equal(plaintext10);
        });

        const plaintext100 = plaintext10.repeat(10);
        it('en/decrypts string of 100 @ 128', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext100, password, 128), password, 128).should.equal(plaintext100);
        });
        it('en/decrypts string of 100 @ 192', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext100, password, 192), password, 192).should.equal(plaintext100);
        });
        it('en/decrypts string of 100 @ 256', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext100, password, 256), password, 256).should.equal(plaintext100);
        });

        const plaintext1k = plaintext100.repeat(10);
        it('en/decrypts string of 1k @ 128', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext1k, password, 128), password, 128).should.equal(plaintext1k);
        });
        it('en/decrypts string of 1k @ 192', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext1k, password, 192), password, 192).should.equal(plaintext1k);
        });
        it('en/decrypts string of 1k @ 256', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext1k, password, 256), password, 256).should.equal(plaintext1k);
        });

        const plaintext10k = plaintext1k.repeat(10);
        it('en/decrypts string of 10k @ 128', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext10k, password, 128), password, 128).should.equal(plaintext10k);
        });
        it('en/decrypts string of 10k @ 192', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext10k, password, 192), password, 192).should.equal(plaintext10k);
        });
        it('en/decrypts string of 10k @ 256', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext10k, password, 256), password, 256).should.equal(plaintext10k);
        });

        const plaintext100k = plaintext10k.repeat(10);
        it('en/decrypts string of 100k @ 128', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext100k, password, 128), password, 128).should.equal(plaintext100k);
        });
        it('en/decrypts string of 100k @ 192', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext100k, password, 192), password, 192).should.equal(plaintext100k);
        });
        it('en/decrypts string of 100k @ 256', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext100k, password, 256), password, 256).should.equal(plaintext100k);
        });

        const plaintext1M = plaintext100k.repeat(10);
        it('en/decrypts string of 1M @ 128', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext1M, password, 128), password, 128).should.equal(plaintext1M);
        });
        it('en/decrypts string of 1M @ 192', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext1M, password, 192), password, 192).should.equal(plaintext1M);
        });
        it('en/decrypts string of 1M @ 256', function() {
            AesCtr.decrypt(AesCtr.encrypt(plaintext1M, password, 256), password, 256).should.equal(plaintext1M);
        });
    });
});


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
