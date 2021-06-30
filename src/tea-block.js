/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* Block TEA (xxtea) Tiny Encryption Algorithm                        (c) Chris Veness 2002-2019  */
/*                                                                                   MIT Licence  */
/* www.movable-type.co.uk/scripts/tea-block.html                                                  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */


/**
 * Tiny Encryption Algorithm. David Wheeler & Roger Needham, Cambridge University Computer Lab.
 *
 * www.movable-type.co.uk/scripts/tea.pdf   - TEA, a Tiny Encryption Algorithm (1994)
 * www.movable-type.co.uk/scripts/xtea.pdf  - Tea extensions (1997)
 * www.movable-type.co.uk/scripts/xxtea.pdf - Correction to xtea (1998)
 */
class Tea {

    /**
     * Encrypts text using Corrected Block TEA (xxtea) algorithm.
     *
     * @param   {string} plaintext - String to be encrypted (multi-byte safe).
     * @param   {string} password - Password to be used for encryption (1st 16 chars).
     * @returns {string} Encrypted text (encoded as base64).
     */
    static encrypt(plaintext, password) {
        plaintext = String(plaintext);
        password = String(password);

        if (plaintext.length == 0) return ''; // nothing to encrypt

        //  v is n-word data vector; converted to array of longs from UTF-8 string
        const v = Tea.strToLongs(Tea.utf8Encode(plaintext));
        //  k is 4-word key; simply convert first 16 chars of password as key
        const k = Tea.strToLongs(Tea.utf8Encode(password).slice(0, 16));

        const cipher = Tea.encode(v, k);

        // convert array of longs to string
        const ciphertext = Tea.longsToStr(cipher);

        // convert binary string to base64 ascii for safe transport
        const cipherbase64 = Tea.base64Encode(ciphertext);

        return cipherbase64;
    }


    /**
     * Decrypts text using Corrected Block TEA (xxtea) algorithm.
     *
     * @param   {string} ciphertext - String to be decrypted.
     * @param   {string} password - Password to be used for decryption (1st 16 chars).
     * @returns {string} Decrypted text.
     * @throws  {Error}  Invalid ciphertext
     */
    static decrypt(ciphertext, password) {
        ciphertext = String(ciphertext);
        password = String(password);

        if (ciphertext.length == 0) return '';  // nothing to decrypt

        //  v is n-word data vector; converted to array of longs from base64 string
        const v = Tea.strToLongs(Tea.base64Decode(ciphertext));
        //  k is 4-word key; simply convert first 16 chars of password as key
        const k = Tea.strToLongs(Tea.utf8Encode(password).slice(0, 16));

        const plain = Tea.decode(v, k);

        const plaintext = Tea.longsToStr(plain);

        // strip trailing null chars resulting from filling 4-char blocks:
        const plainUnicode = Tea.utf8Decode(plaintext.replace(/\0+$/, ''));

        return plainUnicode;
    }


    /**
     * XXTEA: encodes array of unsigned 32-bit integers using 128-bit key.
     *
     * @param   {number[]} v - Data vector.
     * @param   {number[]} k - Key.
     * @returns {number[]} Encoded vector.
     */
    static encode(v, k) {
        if (v.length < 2) v[1] = 0;  // algorithm doesn't work for n<2 so fudge by adding a null
        const n = v.length;
        const delta = 0x9e3779b9;
        let q = Math.floor(6 + 52/n);

        let z = v[n-1], y = v[0];
        let mx, e, sum = 0;

        while (q-- > 0) {  // 6 + 52/n operations gives between 6 & 32 mixes on each word
            sum += delta;
            e = sum>>>2 & 3;
            for (let p = 0; p < n; p++) {
                y = v[(p+1)%n];
                mx = (z>>>5 ^ y<<2) + (y>>>3 ^ z<<4) ^ (sum^y) + (k[p&3 ^ e] ^ z);
                z = v[p] += mx;
            }
        }

        return v;
    }


    /**
     * XXTEA: decodes array of unsigned 32-bit integers using 128-bit key.
     *
     * @param   {number[]} v - Data vector.
     * @param   {number[]} k - Key.
     * @returns {number[]} Decoded vector.
     */
    static decode(v, k) {
        const n = v.length;
        const delta = 0x9e3779b9;
        const q = Math.floor(6 + 52/n);

        let z = v[n-1], y = v[0];
        let mx, e, sum = q*delta;

        while (sum != 0) {
            e = sum>>>2 & 3;
            for (let p = n-1; p >= 0; p--) {
                z = v[p>0 ? p-1 : n-1];
                mx = (z>>>5 ^ y<<2) + (y>>>3 ^ z<<4) ^ (sum^y) + (k[p&3 ^ e] ^ z);
                y = v[p] -= mx;
            }
            sum -= delta;
        }

        return v;
    }


    /**
     * Converts string to array of longs (each containing 4 chars).
     * @private
     */
    static strToLongs(s) {
        // note chars must be within ISO-8859-1 (Unicode code-point <= U+00FF) to fit 4/long
        const l = new Array(Math.ceil(s.length/4));
        for (let i=0; i<l.length; i++) {
            // note little-endian encoding - endianness is irrelevant as long as it matches longsToStr()
            l[i] = s.charCodeAt(i*4)        + (s.charCodeAt(i*4+1)<<8) +
                (s.charCodeAt(i*4+2)<<16) + (s.charCodeAt(i*4+3)<<24);
        } // note running off the end of the string generates nulls since bitwise operators treat NaN as 0
        return l;
    }


    /**
     * Converts array of longs to string.
     * @private
     */
    static longsToStr(l) {
        let str = '';
        for (let i=0; i<l.length; i++) {
            str += String.fromCharCode(l[i] & 0xff, l[i]>>>8 & 0xff, l[i]>>>16 & 0xff, l[i]>>>24 & 0xff);
        }
        return str;
    }


    /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */


    /**
     * Encodes multi-byte string to utf8 - monsur.hossa.in/2012/07/20/utf-8-in-javascript.html
     */
    static utf8Encode(str) {
        return unescape(encodeURIComponent(str));
    }

    /**
     * Decodes utf8 string to multi-byte
     */
    static utf8Decode(utf8Str) {
        try {
            return decodeURIComponent(escape(utf8Str));
        } catch (e) {
            return utf8Str; // invalid UTF-8? return as-is
        }
    }


    /**
     * Encodes base64 - developer.mozilla.org/en-US/docs/Web/API/window.btoa, nodejs.org/api/buffer.html
     */
    static base64Encode(str) {
        if (typeof btoa != 'undefined') return btoa(str); // browser
        if (typeof Buffer != 'undefined') return new Buffer(str, 'binary').toString('base64'); // Node.js
        throw new Error('No Base64 Encode');
    }

    /**
     * Decodes base64
     */
    static base64Decode(b64Str) {
        if (typeof atob == 'undefined' && typeof Buffer == 'undefined') throw new Error('No base64 decode');
        try {
            if (typeof atob != 'undefined') return atob(b64Str); // browser
            if (typeof Buffer != 'undefined') return new Buffer(b64Str, 'base64').toString('binary'); // Node.js
        } catch (e) {
            throw new Error('Invalid ciphertext');
        }
    }

}


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

export default Tea;
