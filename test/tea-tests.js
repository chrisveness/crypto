/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* Crypto Test Harness - TEA                                          (c) Chris Veness 2014-2018  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */


import Tea from '../tea-block.js';

// import chai from 'chai'; // BDD/TDD assertion library - uncomment for Node.js tests

const should = chai.should();


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* Block TEA: test decrypted encrypted text matches original text (with Unicode text & password)  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

describe('tea-block', function() {
    const origtext = 'My big secret סוד קצת بت سرية  ความลับบิต 位的秘密';
    const ciphertext = Tea.encrypt(origtext, 'pāšşŵōřđ');
    const decryptext = Tea.decrypt(ciphertext, 'pāšşŵōřđ');

    it('decrypts ciphertext to match original (unicode) text', function() { decryptext.should.equal(origtext); });
});


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
