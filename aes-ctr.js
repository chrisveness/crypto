/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* AES counter-mode (CTR) implementation in JavaScript                (c) Chris Veness 2005-2017  */
/*                                                                                   MIT Licence  */
/* www.movable-type.co.uk/scripts/aes.html                                                        */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

/* global WorkerGlobalScope */
'use strict';
// const Aes = require('./aes.js'); // ≡ import Aes from 'aes.js'; uncomment to use in Node.js


/**
 * AesCtr: Counter-mode (CTR) wrapper for AES.
 *
 * This encrypts a Unicode string to produces a base64 ciphertext using 128/192/256-bit AES,
 * and the converse to decrypt an encrypted ciphertext.
 *
 * See csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
 */
class AesCtr extends Aes {

    /**
     * Encrypt a text using AES encryption in Counter mode of operation.
     *
     * Unicode multi-byte character safe
     *
     * @param   {string} plaintext - Source text to be encrypted.
     * @param   {string} password - The password to use to generate a key for encryption.
     * @param   {number} nBits - Number of bits to be used in the key; 128 / 192 / 256.
     * @returns {string} Encrypted text.
     *
     * @example
     *   const encr = AesCtr.encrypt('big secret', 'pāşšŵōřđ', 256); // 'lwGl66VVwVObKIr6of8HVqJr'
     */
    static encrypt(plaintext, password, nBits) {
        const blockSize = 16;  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
        if (!(nBits==128 || nBits==192 || nBits==256)) throw new Error('Key size is not 128 / 192 / 256');
        plaintext = AesCtr.utf8Encode(String(plaintext));
        password = AesCtr.utf8Encode(String(password));

        // use AES itself to encrypt password to get cipher key (using plain password as source for key
        // expansion) to give us well encrypted key (in real use hashed password could be used for key)
        const nBytes = nBits/8;  // no bytes in key (16/24/32)
        const pwBytes = new Array(nBytes);
        for (let i=0; i<nBytes; i++) {  // use 1st 16/24/32 chars of password for key
            pwBytes[i] = i<password.length ?  password.charCodeAt(i) : 0;
        }
        let key = Aes.cipher(pwBytes, Aes.keyExpansion(pwBytes)); // gives us 16-byte key
        key = key.concat(key.slice(0, nBytes-16));  // expand key to 16/24/32 bytes long

        // initialise 1st 8 bytes of counter block with nonce (NIST SP800-38A §B.2): [0-1] = millisec,
        // [2-3] = random, [4-7] = seconds, together giving full sub-millisec uniqueness up to Feb 2106
        const counterBlock = new Array(blockSize);

        const nonce = (new Date()).getTime();  // timestamp: milliseconds since 1-Jan-1970
        const nonceMs = nonce%1000;
        const nonceSec = Math.floor(nonce/1000);
        const nonceRnd = Math.floor(Math.random()*0xffff);
        // for debugging: nonce = nonceMs = nonceSec = nonceRnd = 0;

        for (let i=0; i<2; i++) counterBlock[i]   = (nonceMs  >>> i*8) & 0xff;
        for (let i=0; i<2; i++) counterBlock[i+2] = (nonceRnd >>> i*8) & 0xff;
        for (let i=0; i<4; i++) counterBlock[i+4] = (nonceSec >>> i*8) & 0xff;

        // and convert it to a string to go on the front of the ciphertext
        let ctrTxt = '';
        for (let i=0; i<8; i++) ctrTxt += String.fromCharCode(counterBlock[i]);

        // generate key schedule - an expansion of the key into distinct Key Rounds for each round
        const keySchedule = Aes.keyExpansion(key);

        const blockCount = Math.ceil(plaintext.length/blockSize);
        let ciphertext = '';

        for (let b=0; b<blockCount; b++) {
            // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
            // done in two stages for 32-bit ops: using two words allows us to go past 2^32 blocks (68GB)
            for (let c=0; c<4; c++) counterBlock[15-c] = (b >>> c*8) & 0xff;
            for (let c=0; c<4; c++) counterBlock[15-c-4] = (b/0x100000000 >>> c*8);

            const cipherCntr = Aes.cipher(counterBlock, keySchedule);  // -- encrypt counter block --

            // block size is reduced on final block
            const blockLength = b<blockCount-1 ? blockSize : (plaintext.length-1)%blockSize+1;
            const cipherChar = new Array(blockLength);

            for (let i=0; i<blockLength; i++) {
                // -- xor plaintext with ciphered counter char-by-char --
                cipherChar[i] = cipherCntr[i] ^ plaintext.charCodeAt(b*blockSize+i);
                cipherChar[i] = String.fromCharCode(cipherChar[i]);
            }
            ciphertext += cipherChar.join('');

            // if within web worker, announce progress every 1000 blocks (roughly every 50ms)
            if (typeof WorkerGlobalScope != 'undefined' && self instanceof WorkerGlobalScope) {
                if (b%1000 == 0) self.postMessage({ progress: b/blockCount });
            }
        }

        ciphertext =  AesCtr.base64Encode(ctrTxt+ciphertext);

        return ciphertext;
    }


    /**
     * Decrypt a text encrypted by AES in counter mode of operation
     *
     * @param   {string} ciphertext - Cipher text to be decrypted.
     * @param   {string} password - Password to use to generate a key for decryption.
     * @param   {number} nBits - Number of bits to be used in the key; 128 / 192 / 256.
     * @returns {string} Decrypted text
     *
     * @example
     *   const decr = AesCtr.decrypt('lwGl66VVwVObKIr6of8HVqJr', 'pāşšŵōřđ', 256); // 'big secret'
     */
    static decrypt(ciphertext, password, nBits) {
        const blockSize = 16;  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
        if (!(nBits==128 || nBits==192 || nBits==256)) throw new Error('Key size is not 128 / 192 / 256');
        ciphertext = AesCtr.base64Decode(String(ciphertext));
        password = AesCtr.utf8Encode(String(password));

        // use AES to encrypt password (mirroring encrypt routine)
        const nBytes = nBits/8;  // no bytes in key
        const pwBytes = new Array(nBytes);
        for (let i=0; i<nBytes; i++) {  // use 1st nBytes chars of password for key
            pwBytes[i] = i<password.length ?  password.charCodeAt(i) : 0;
        }
        let key = Aes.cipher(pwBytes, Aes.keyExpansion(pwBytes));
        key = key.concat(key.slice(0, nBytes-16));  // expand key to 16/24/32 bytes long

        // recover nonce from 1st 8 bytes of ciphertext
        const counterBlock = new Array(8);
        const ctrTxt = ciphertext.slice(0, 8);
        for (let i=0; i<8; i++) counterBlock[i] = ctrTxt.charCodeAt(i);

        // generate key schedule
        const keySchedule = Aes.keyExpansion(key);

        // separate ciphertext into blocks (skipping past initial 8 bytes)
        const nBlocks = Math.ceil((ciphertext.length-8) / blockSize);
        const ct = new Array(nBlocks);
        for (let b=0; b<nBlocks; b++) ct[b] = ciphertext.slice(8+b*blockSize, 8+b*blockSize+blockSize);
        ciphertext = ct;  // ciphertext is now array of block-length strings

        // plaintext will get generated block-by-block into array of block-length strings
        let plaintext = '';

        for (let b=0; b<nBlocks; b++) {
            // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
            for (let c=0; c<4; c++) counterBlock[15-c] = ((b) >>> c*8) & 0xff;
            for (let c=0; c<4; c++) counterBlock[15-c-4] = (((b+1)/0x100000000-1) >>> c*8) & 0xff;

            const cipherCntr = Aes.cipher(counterBlock, keySchedule);  // encrypt counter block

            const plaintxtByte = new Array(ciphertext[b].length);
            for (let i=0; i<ciphertext[b].length; i++) {
                // -- xor plaintext with ciphered counter byte-by-byte --
                plaintxtByte[i] = cipherCntr[i] ^ ciphertext[b].charCodeAt(i);
                plaintxtByte[i] = String.fromCharCode(plaintxtByte[i]);
            }
            plaintext += plaintxtByte.join('');

            // if within web worker, announce progress every 1000 blocks (roughly every 50ms)
            if (typeof WorkerGlobalScope != 'undefined' && self instanceof WorkerGlobalScope) {
                if (b%1000 == 0) self.postMessage({ progress: b/nBlocks });
            }
        }

        plaintext = AesCtr.utf8Decode(plaintext);  // decode from UTF8 back to Unicode multi-byte chars

        return plaintext;
    }


    /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */


    /**
     * Encodes multi-byte string to utf8.
     *
     * Note utf8Encode is an identity function with 7-bit ascii strings, but not with 8-bit strings;
     * utf8Encode('x') = 'x', but utf8Encode('ça') = 'Ã§a', and utf8Encode('Ã§a') = 'ÃÂ§a'.
     */
    static utf8Encode(str) {
        try {
            return new TextEncoder().encode(str, 'utf-8').reduce((prev,curr) => prev + String.fromCharCode(curr), '');
        } catch (e) { // no TextEncoder available?
            return unescape(encodeURIComponent(str)); // monsur.hossa.in/2012/07/20/utf-8-in-javascript.html
        }
    }

    /**
     * Decodes utf8 string to multi-byte.
     */
    static utf8Decode(str) {
        try {
            return new TextEncoder().decode(str, 'utf-8').reduce((prev,curr) => prev + String.fromCharCode(curr), '');
        } catch (e) { // no TextEncoder available?
            return decodeURIComponent(escape(str)); // monsur.hossa.in/2012/07/20/utf-8-in-javascript.html
        }
    }

    /*
     * Encodes string as base-64.
     *
     * - developer.mozilla.org/en-US/docs/Web/API/window.btoa, nodejs.org/api/buffer.html
     * - note: btoa & Buffer/binary work on single-byte Unicode (C0/C1), so ok for utf8 strings, not for general Unicode...
     * - note: if btoa()/atob() are not available (eg IE9-), try github.com/davidchambers/Base64.js
     */
    static base64Encode(str) {
        if (typeof btoa != 'undefined') return btoa(str); // browser
        if (typeof Buffer != 'undefined') return new Buffer(str, 'binary').toString('base64'); // Node.js
        throw new Error('No Base64 Encode');
    }

    /*
     * Decodes base-64 encoded string.
     */
    static base64Decode(str) {
        if (typeof atob != 'undefined') return atob(str); // browser
        if (typeof Buffer != 'undefined') return new Buffer(str, 'base64').toString('binary'); // Node.js
        throw new Error('No Base64 Decode');
    }

}


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

// module.exports = AesCtr; // uncomment to use in Node.js
