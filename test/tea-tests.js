/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* Crypto Test Harness - TEA                                          (c) Chris Veness 2014-2017  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

'use strict';

const chai = require('chai');  // BDD/TDD assertion library

const Tea = require('../tea-block.js');

chai.should();
const test = it; // just an alias


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* Block TEA: test decrypted encrypted text matches original text (with Unicode text & password)  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

describe('tea-block', function() {
    const origtext = 'My big secret סוד קצת بت سرية  ความลับบิต 位的秘密';
    const ciphertext = Tea.encrypt(origtext, 'pāšşŵōřđ');
    const decrtext = Tea.decrypt(ciphertext, 'pāšşŵōřđ');

    test('decrypted ciphertext matches original text', function() { decrtext.should.equal(origtext); });
});


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
