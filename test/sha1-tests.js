/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* Crypto Test Harness - SHA-1                                        (c) Chris Veness 2014-2019  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

import Sha1 from '../src/sha1.js';

if (typeof window == 'undefined') { // node
    import('chai').then(chai => { global.should = chai.should(); });
} else {                            // browser
    // eslint-disable-next-line no-undef
    window.should = chai.should();
}


describe('SHA-1', function() {

    // csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf Appendex A: SHA-1 Examples
    describe('NIST CSRC FIPS 180-2 SHA-1 examples', function() {
        it('checks FIPS 180-2 A.1', function() { Sha1.hash('abc', { outFormat: 'hex-w' }).should.equal('a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d'); });
        const msg448 = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq';
        it('checks FIPS 180-2 A.2', function() { Sha1.hash(msg448, { outFormat: 'hex-w' }).should.equal('84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1'); });
        const msg1M = 'a'.repeat(1000000);
        it('checks FIPS 180-2 A.3', function() { Sha1.hash(msg1M, { outFormat: 'hex-w' }).should.equal('34aa973c d4c4daa4 f61eeb2b dbad2731 6534016f'); });
    });

    // csrc.nist.gov/groups/STM/cavp/secure-hashing.html#test-vectors
    describe('NIST CSRC SHA-1 test vectors', function() {
        if (typeof module != 'undefined' && this.module != module) { // only run these tests within node (s/o 4224606)
            responseTestVectors('SHA1ShortMsg', Sha1.hash);
            responseTestVectors('SHA1LongMsg', Sha1.hash);
        }
    });

    function responseTestVectors(file, fn) {
        const fs = require('fs');
        const rsp = fs.readFileSync(`./test/${file}.rsp`, 'utf8');
        const msg = rsp.split('\r\n').filter(line => line.slice(0, 6) == 'Msg = ').map(line => line.slice(6));
        const md = rsp.split('\r\n').filter(line => line.slice(0, 5) == 'MD = ').map(line => line.slice(5));
        for (let t=0; t<msg.length; t++) {
            if (msg[t] == '00') msg[t] = ''; // what are NIST up to? '00'.length == 0? duh!
            it(`hashes ${file} Len ${msg[t].length}`, function() { fn(msg[t], { msgFormat: 'hex-bytes' }).should.equal(md[t]); });
        }
    }
});


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
