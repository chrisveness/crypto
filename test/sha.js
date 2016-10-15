/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
//  Crypto Test Harness - SHA                                         (c) Chris Veness 2014-2016  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

'use strict';

var chai = require('chai');  // BDD/TDD assertion library

var Sha1   = require('../sha1.js');
var Sha256 = require('../sha256.js');

chai.should();
var test = it; // just an alias


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* SHA-1: csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA1.pdf                             */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

describe('sha1', function() {
    var msg1 = 'abc';
    test('sha1 1 block msg', function() { Sha1.hash(msg1).should.equal('a9993e364706816aba3e25717850c26c9cd0d89d'); });
    var msg2 = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq';
    test('sha1 2 block msg', function() { Sha1.hash(msg2).should.equal('84983e441c3bd26ebaae4aa1f95129e5e54670f1'); });
});


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* SHA-256: csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA256.pdf                         */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

describe('sha256', function() {
    var msg1 = 'abc';
    test('sha256 1 block msg', function() { Sha256.hash(msg1).should.equal('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'); });
    var msg2 = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq';
    test('sha256 2 block msg', function() { Sha256.hash(msg2).should.equal('248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'); });
});


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
