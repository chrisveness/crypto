/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
//  Crypto Test Harness - SHA                                         (c) Chris Veness 2014-2016  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

'use strict';

var chai = require('chai'); // BDD/TDD assertion library
var fs   = require('fs');   // nodejs.org/api/fs.html

var Sha1   = require('../sha1.js');
var Sha256 = require('../sha256.js');

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


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
