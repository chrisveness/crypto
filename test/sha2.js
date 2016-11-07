/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
//  Crypto Test Harness - SHA                                         (c) Chris Veness 2014-2016  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

'use strict';

var chai = require('chai'); // BDD/TDD assertion library
var fs   = require('fs');   // nodejs.org/api/fs.html

var Sha256 = require('../sha256.js');
var Sha512 = require('../sha512.js');

chai.should();
var test = it; // just an alias


describe('SHA-2', function() {

    // csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf Appendex B: SHA-256 Examples
    describe('NIST CSRC FIPS 180-2 SHA-256 examples', function() {
        this.timeout(5000);
        test('FIPS 180-2 B.1', function() { Sha256.hash('abc', { outFormat: 'hex-w' }).should.equal('ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad'); });
        var msg448 = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq';
        test('FIPS 180-2 B.2', function() { Sha256.hash(msg448, { outFormat: 'hex-w' }).should.equal('248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1'); });
        const msg1M = 'a'.repeat(1e6);
        test('FIPS 180-2 B.3', function() { Sha256.hash(msg1M, { outFormat: 'hex-w' }).should.equal('cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0'); });
    });

    // csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf Appendex C: SHA-512 Examples
    describe('NIST CSRC FIPS 180-2 SHA-512 examples', function() {
        var msg1 = 'abc';
        test('FIPS 180-2 C.1', function() { Sha512.hash('abc', { outFormat: 'hex-w' }).should.equal('ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a 2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f'); });
        var msg448 = 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu';
        test('FIPS 180-2 C.2', function() { Sha512.hash(msg448, { outFormat: 'hex-w' }).should.equal('8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018 501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909'); });
        const msg1M = 'a'.repeat(1e6);
        test('FIPS 180-2 C.3', function() { Sha512.hash(msg1M, { outFormat: 'hex-w' }).should.equal('e718483d0ce76964 4e2e42c7bc15b463 8e1f98b13b204428 5632a803afa973eb de0ff244877ea60a 4cb0432ce577c31b eb009c5c2c49aa2e 4eadb217ad8cc09b'); });
    });

    // csrc.nist.gov/groups/STM/cavp/secure-hashing.html#test-vectors
    describe('NIST CSRC SHA-2 test vectors', function() {
        rsp('SHA256ShortMsg', Sha256.hash);
        rsp('SHA256LongMsg', Sha256.hash);
        rsp('SHA512ShortMsg', Sha512.hash);
        rsp('SHA512LongMsg', Sha512.hash);
    });

    function rsp(file, fn) {
        const rsp = fs.readFileSync(`./test/${file}.rsp`, 'utf8');
        const msg = rsp.split('\r\n').filter(line => line.slice(0,6) == 'Msg = ').map(line => line.slice(6));
        const md = rsp.split('\r\n').filter(line => line.slice(0,5) == 'MD = ').map(line => line.slice(5));
        for (let t=0; t<msg.length; t++) {
            if (msg[t] == '00') msg[t] = ''; // what are NIST up to? '00'.length == 0? duh!
            test(`${file} Len ${msg[t].length}`, function() { fn(msg[t], { msgFormat: 'hex-bytes' }).should.equal(md[t]); });
        }
    }
});


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
