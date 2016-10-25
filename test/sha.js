/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
//  Crypto Test Harness - SHA                                         (c) Chris Veness 2014-2016  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

'use strict';

var chai = require('chai'); // BDD/TDD assertion library
var fs   = require('fs');   // nodejs.org/api/fs.html

var Sha1   = require('../sha1.js');
var Sha256 = require('../sha256.js');
var Sha512 = require('../sha512.js');

chai.should();
var test = it; // just an alias


// csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf Appendex A: SHA-1 Examples

describe('NIST CSRC FIPS 180-2 SHA-1 examples', function() {
    var msg1 = 'abc';
    test('FIPS 180-2 A.1', function() { Sha1.hash(msg1, { outFormat: 'hex-w' }).should.equal('a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d'); });
    var msg2 = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq';
    test('FIPS 180-2 A.2', function() { Sha1.hash(msg2, { outFormat: 'hex-w' }).should.equal('84983e44 1c3bd26e baae4aa1 f95129e5 e54670f1'); });
    const msg3 = 'a'.repeat(1000000);
    test('FIPS 180-2 A.3', function() { Sha1.hash(msg3, { outFormat: 'hex-w' }).should.equal('34aa973c d4c4daa4 f61eeb2b dbad2731 6534016f'); });
});


// csrc.nist.gov/groups/STM/cavp/secure-hashing.html#test-vectors

describe('NIST CSRC SHA-1 test vectors', function() {
    const sha1ShortMsg = fs.readFileSync('./test/SHA1ShortMsg.rsp', 'utf8');
    const msgS = sha1ShortMsg.split('\r\n').filter(line => line.slice(0,6) == 'Msg = ').map(line => line.slice(6));
    const mdS = sha1ShortMsg.split('\r\n').filter(line => line.slice(0,5) == 'MD = ').map(line => line.slice(5));
    for (let t=0; t<msgS.length; t++) {
        if (msgS[t] == '00') msgS[t] = ''; // what are NIST up to? '00'.length == 0? duh!
        test('sha1ShortMsg Len '+msgS[t].length, function() { Sha1.hash(msgS[t], { msgFormat: 'hex-bytes' }).should.equal(mdS[t]); });
    }
    const sha1LongMsg = fs.readFileSync('./test/SHA1LongMsg.rsp', 'utf8');
    const msgL = sha1LongMsg.split('\r\n').filter(line => line.slice(0,6) == 'Msg = ').map(line => line.slice(6));
    const mdL = sha1LongMsg.split('\r\n').filter(line => line.slice(0,5) == 'MD = ').map(line => line.slice(5));
    for (let t=0; t<msgL.length; t++) {
        test('sha1LongMsg Len '+msgL[t].length, function() { Sha1.hash(msgL[t], { msgFormat: 'hex-bytes' }).should.equal(mdL[t]); });
    }
});


// csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf Appendex B: SHA-256 Examples

describe('NIST CSRC FIPS 180-2 SHA-256 examples', function() {
    var msg1 = 'abc';
    test('FIPS 180-2 B.1', function() { Sha256.hash(msg1, { outFormat: 'hex-w' }).should.equal('ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad'); });
    var msg2 = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq';
    test('FIPS 180-2 B.2', function() { Sha256.hash(msg2, { outFormat: 'hex-w' }).should.equal('248d6a61 d20638b8 e5c02693 0c3e6039 a33ce459 64ff2167 f6ecedd4 19db06c1'); });
    const msg3 = 'a'.repeat(1000000);
    test('FIPS 180-2 B.3', function() { Sha256.hash(msg3, { outFormat: 'hex-w' }).should.equal('cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0'); });
});


// csrc.nist.gov/groups/STM/cavp/secure-hashing.html#test-vectors

describe('NIST CSRC SHA-256 test vectors', function() {
    const sha256ShortMsg = fs.readFileSync('./test/SHA256ShortMsg.rsp', 'utf8');
    const msgS = sha256ShortMsg.split('\r\n').filter(line => line.slice(0,6) == 'Msg = ').map(line => line.slice(6));
    const mdS = sha256ShortMsg.split('\r\n').filter(line => line.slice(0,5) == 'MD = ').map(line => line.slice(5));
    for (let t=0; t<2; t++) {
        if (msgS[t] == '00') msgS[t] = ''; // what are NIST up to? '00'.length == 0? duh!
        test('sha256ShortMsg Len '+msgS[t].length, function() { Sha256.hash(msgS[t], { msgFormat: 'hex-bytes' }).should.equal(mdS[t]); });
    }
    const sha256LongMsg = fs.readFileSync('./test/SHA256LongMsg.rsp', 'utf8');
    const msgL = sha256LongMsg.split('\r\n').filter(line => line.slice(0,6) == 'Msg = ').map(line => line.slice(6));
    const mdL = sha256LongMsg.split('\r\n').filter(line => line.slice(0,5) == 'MD = ').map(line => line.slice(5));
    for (let t=0; t<msgL.length; t++) {
        test('sha256LongMsg Len '+msgL[t].length, function() { Sha256.hash(msgL[t], { msgFormat: 'hex-bytes' }).should.equal(mdL[t]); });
    }
});


// csrc.nist.gov/publications/fips/fips180-2/fips180-2.pdf Appendex B: SHA-512 Examples

describe('NIST CSRC FIPS 180-2 SHA-512 examples', function() {
    this.timeout(5000);
    var msg1 = 'abc';
    test('FIPS 180-2 B.1', function() { Sha512.hash(msg1, { outFormat: 'hex-w' }).should.equal('ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a 2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f'); });
    var msg2 = 'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu';
    test('FIPS 180-2 B.2', function() { Sha512.hash(msg2, { outFormat: 'hex-w' }).should.equal('8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018 501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909'); });
    const msg3 = 'a'.repeat(1000000);
    test('FIPS 180-2 B.3', function() { Sha512.hash(msg3, { outFormat: 'hex-w' }).should.equal('e718483d0ce76964 4e2e42c7bc15b463 8e1f98b13b204428 5632a803afa973eb de0ff244877ea60a 4cb0432ce577c31b eb009c5c2c49aa2e 4eadb217ad8cc09b'); });
});


// csrc.nist.gov/groups/STM/cavp/secure-hashing.html#test-vectors

describe('NIST CSRC SHA-512 test vectors', function() {
    const sha512ShortMsg = fs.readFileSync('./test/SHA512ShortMsg.rsp', 'utf8');
    const msgS = sha512ShortMsg.split('\r\n').filter(line => line.slice(0,6) == 'Msg = ').map(line => line.slice(6));
    const mdS = sha512ShortMsg.split('\r\n').filter(line => line.slice(0,5) == 'MD = ').map(line => line.slice(5));
    for (let t=0; t<2; t++) {
        if (msgS[t] == '00') msgS[t] = ''; // what are NIST up to? '00'.length == 0? duh!
        test('sha512ShortMsg Len '+msgS[t].length, function() { Sha512.hash(msgS[t], { msgFormat: 'hex-bytes' }).should.equal(mdS[t]); });
    }
    const sha512LongMsg = fs.readFileSync('./test/SHA512LongMsg.rsp', 'utf8');
    const msgL = sha512LongMsg.split('\r\n').filter(line => line.slice(0,6) == 'Msg = ').map(line => line.slice(6));
    const mdL = sha512LongMsg.split('\r\n').filter(line => line.slice(0,5) == 'MD = ').map(line => line.slice(5));
    for (let t=0; t<msgL.length; t++) {
        test('sha512LongMsg Len '+msgL[t].length, function() { Sha512.hash(msgL[t], { msgFormat: 'hex-bytes' }).should.equal(mdL[t]); });
    }
});


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
