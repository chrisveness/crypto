/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/*  Block TEA (xxtea) Tiny Encryption Algorithm         (c) Chris Veness 2002-2014 / MIT Licence  */
/*   - www.movable-type.co.uk/scripts/tea-block.html                                              */
/*                                                                                                */
/*  Algorithm: David Wheeler & Roger Needham, Cambridge University Computer Lab                   */
/*             http://www.cl.cam.ac.uk/ftp/papers/djw-rmn/djw-rmn-tea.html (1994)                 */
/*             http://www.cl.cam.ac.uk/ftp/users/djw3/xtea.ps (1997)                              */
/*             http://www.cl.cam.ac.uk/ftp/users/djw3/xxtea.ps (1998)                             */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

/* jshint node:true *//* global define, escape, unescape, btoa, atob */
'use strict';


/**
 * Tiny Encryption Algorithm
 *
 * @namespace
 */
var Tea = {};


/**
 * Encrypts text using Corrected Block TEA (xxtea) algorithm.
 *
 * @param   {string} plaintext - String to be encrypted (multi-byte safe).
 * @param   {string} password - Password to be used for encryption (1st 16 chars).
 * @returns {string} Encrypted text (encoded as base64).
 */
Tea.encrypt = function(plaintext, password) {
    plaintext = String(plaintext);
    password = String(password);

    if (plaintext.length == 0) return('');  // nothing to encrypt

    //  v is n-word data vector; converted to array of longs from UTF-8 string
    var v = Tea.strToLongs(plaintext.utf8Encode());
    //  k is 4-word key; simply convert first 16 chars of password as key
    var k = Tea.strToLongs(password.utf8Encode().slice(0,16));
    var n = v.length;

    v = Tea.encode(v, k);

    // convert array of longs to string
    var ciphertext = Tea.longsToStr(v);

    // convert binary string to base64 ascii for safe transport
    return ciphertext.base64Encode();
};


/**
 * Decrypts text using Corrected Block TEA (xxtea) algorithm.
 *
 * @param   {string} ciphertext - String to be decrypted.
 * @param   {string} password - Password to be used for decryption (1st 16 chars).
 * @returns {string} Decrypted text.
 */
Tea.decrypt = function(ciphertext, password) {
    ciphertext = String(ciphertext);
    password = String(password);

    if (ciphertext.length == 0) return('');

    //  v is n-word data vector; converted to array of longs from base64 string
    var v = Tea.strToLongs(ciphertext.base64Decode());
    //  k is 4-word key; simply convert first 16 chars of password as key
    var k = Tea.strToLongs(password.utf8Encode().slice(0,16));
    var n = v.length;

    v = Tea.decode(v, k);

    var plaintext = Tea.longsToStr(v);

    // strip trailing null chars resulting from filling 4-char blocks:
    plaintext = plaintext.replace(/\0+$/,'');

    return plaintext.utf8Decode();
};


/**
 * XXTEA: encodes array of unsigned 32-bit integers using 128-bit key.
 *
 * @param   {number[]} v - Data vector.
 * @param   {number[]} k - Key.
 * @returns {number[]} Encoded vector.
 */
Tea.encode = function(v, k) {
    if (v.length < 2) v[1] = 0;  // algorithm doesn't work for n<2 so fudge by adding a null
    var n = v.length;

    var z = v[n-1], y = v[0], delta = 0x9E3779B9;
    var mx, e, q = Math.floor(6 + 52/n), sum = 0;

    while (q-- > 0) {  // 6 + 52/n operations gives between 6 & 32 mixes on each word
        sum += delta;
        e = sum>>>2 & 3;
        for (var p = 0; p < n; p++) {
            y = v[(p+1)%n];
            mx = (z>>>5 ^ y<<2) + (y>>>3 ^ z<<4) ^ (sum^y) + (k[p&3 ^ e] ^ z);
            z = v[p] += mx;
        }
    }

    return v;
};


/**
 * XXTEA: decodes array of unsigned 32-bit integers using 128-bit key.
 *
 * @param   {number[]} v - Data vector.
 * @param   {number[]} k - Key.
 * @returns {number[]} Decoded vector.
 */
Tea.decode = function(v, k) {
    var n = v.length;

    var z = v[n-1], y = v[0], delta = 0x9E3779B9;
    var mx, e, q = Math.floor(6 + 52/n), sum = q*delta;

    while (sum != 0) {
        e = sum>>>2 & 3;
        for (var p = n-1; p >= 0; p--) {
            z = v[p>0 ? p-1 : n-1];
            mx = (z>>>5 ^ y<<2) + (y>>>3 ^ z<<4) ^ (sum^y) + (k[p&3 ^ e] ^ z);
            y = v[p] -= mx;
        }
        sum -= delta;
    }

    return v;
};


/**
 * Converts string to array of longs (each containing 4 chars).
 * @private
 */
Tea.strToLongs = function(s) {
    // note chars must be within ISO-8859-1 (Unicode code-point <= U+00FF) to fit 4/long
    var l = new Array(Math.ceil(s.length/4));
    for (var i=0; i<l.length; i++) {
        // note little-endian encoding - endianness is irrelevant as long as it matches longsToStr()
        l[i] = s.charCodeAt(i*4)        + (s.charCodeAt(i*4+1)<<8) +
              (s.charCodeAt(i*4+2)<<16) + (s.charCodeAt(i*4+3)<<24);
    }
    return l; // note running off the end of the string generates nulls since bitwise operators
};            // treat NaN as 0


/**
 * Converts array of longs to string.
 * @private
 */
Tea.longsToStr = function(l) {
    var a = new Array(l.length);
    for (var i=0; i<l.length; i++) {
        a[i] = String.fromCharCode(l[i] & 0xFF, l[i]>>>8 & 0xFF, l[i]>>>16 & 0xFF, l[i]>>>24 & 0xFF);
    }
    return a.join('');  // use Array.join() for better performance than repeated string appends
};


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */


/** Extend String object with method to encode multi-byte string to utf8
 *  - monsur.hossa.in/2012/07/20/utf-8-in-javascript.html */
if (typeof String.prototype.utf8Encode == 'undefined') {
    String.prototype.utf8Encode = function() {
        return unescape( encodeURIComponent( this ) );
    };
}

/** Extend String object with method to decode utf8 string to multi-byte */
if (typeof String.prototype.utf8Decode == 'undefined') {
    String.prototype.utf8Decode = function() {
        try {
            return decodeURIComponent( escape( this ) );
        } catch (e) {
            return this; // invalid UTF-8? return as-is
        }
    };
}


/** Extend String object with method to encode base64
 *  - developer.mozilla.org/en-US/docs/Web/API/window.btoa, nodejs.org/api/buffer.html
 *  note: if btoa()/atob() are not available (eg IE9-), try github.com/davidchambers/Base64.js */
if (typeof String.prototype.base64Encode == 'undefined') {
    String.prototype.base64Encode = function() {
        if (typeof btoa != 'undefined') return btoa(this); // browser
        if (typeof Buffer != 'undefined') return new Buffer(this, 'utf8').toString('base64'); // Node.js
        throw new Error('No Base64 Encode');
    };
}

/** Extend String object with method to decode base64 */
if (typeof String.prototype.base64Decode == 'undefined') {
    String.prototype.base64Decode = function() {
        if (typeof atob != 'undefined') return atob(this); // browser
        if (typeof Buffer != 'undefined') return new Buffer(this, 'base64').toString('utf8'); // Node.js
        throw new Error('No Base64 Decode');
    };
}


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
if (typeof module != 'undefined' && module.exports) module.exports = Tea; // CommonJS export
if (typeof define == 'function' && define.amd) define([''], function() { return Tea; }); // AMD
