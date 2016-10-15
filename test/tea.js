/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
//  Crypto Test Harness - TEA                                         (c) Chris Veness 2014-2016  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

'use strict';

var chai = require('chai');  // BDD/TDD assertion library

var Tea = require('../tea-block.js');

chai.should();
var test = it; // just an alias


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* Block TEA: test decrypted encrypted text matches original text (with Unicode text & password)  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

describe('tea-block', function() {
    var origtext = 'My big secret סוד קצת بت سرية  ความลับบิต 位的秘密';
    var ciphertext = Tea.encrypt(origtext, 'pāšşŵōřđ');
    var decrtext = Tea.decrypt(ciphertext, 'pāšşŵōřđ');

    test('decrypted ciphertext matches original text', function() { decrtext.should.equal(origtext); });
});


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
