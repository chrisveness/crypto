/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
//  Crypto Test Harness                                                    (c) Chris Veness 2014  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
'use strict'

var test = require('tape');

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* Block TEA: test decrypted encrypted text matches original text (with Unicode text & password)  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

test('tea-block', function(assert) {
    var Tea = require('./tea-block.js');

    var origtext = 'My big secret סוד קצת بت سرية  ความลับบิต 位的秘密';
    var ciphertext = Tea.encrypt(origtext, 'pāšşŵōřđ');
    var decrtext = Tea.decrypt(ciphertext, 'pāšşŵōřđ');

    assert.equal(decrtext, origtext, 'decrypted ciphertext matches original text');
    assert.end();
});

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
