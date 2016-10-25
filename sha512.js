/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* SHA-512 (FIPS 180-4) implementation in JavaScript                       (c) Chris Veness 2016  */
/*                                                                                   MIT Licence  */
/* www.movable-type.co.uk/scripts/sha512.html                                                     */
/*                                                                                                */
/* - see http://csrc.nist.gov/groups/ST/toolkit/secure_hashing.html                               */
/*       http://csrc.nist.gov/groups/ST/toolkit/examples.html                                     */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

'use strict';


/**
 * SHA-512 hash function reference implementation.
 *
 * This is a direct implementation of FIPS 180-4, without any optimisations. It is intended to aid
 * understanding of the algorithm rather than for production use, though it could be used where
 * performance is not critical.
 *
 * SHA-512 is more difficult to implement in JavaScript than SHA-256, as it is based on 64-bit
 * (unsigned) integers, which are not natively supported in JavaScript (in which all numbers are
 * IEEE 754 64-bit floating-point numbers). A 'Long' library here provides UInt64-style support.
 *
 * @namespace
 */
var Sha512 = {};


/**
 * Generates SHA-512 hash of string.
 *
 * @param   {string} msg - (Unicode) string to be hashed.
 * @param   {Object} [options]
 * @param   {string} [options.msgFormat=string] - Message format: 'string' for JavaScript string
 *   (gets converted to UTF-8 for hashing); 'hex-bytes' for string of hex bytes ('616263' ≡ 'abc') .
 * @param   {string} [options.outFormat=hex] - Output format: 'hex' for string of contiguous
 *   hex bytes; 'hex-w' for grouping hex bytes into groups of (8 byte / 16 character) words.
 * @returns {string} Hash of msg as hex character string.
 */
Sha512.hash = function(msg, options) {
    var defaults = { msgFormat: 'string', outFormat: 'hex' };
    var opt = Object.assign(defaults, options);

    switch (opt.msgFormat) {
        default: // default is to convert string to UTF-8, as SHA only deals with byte-streams
        case 'string':   msg = Sha512.utf8Encode(msg);       break;
        case 'hex-bytes':msg = Sha512.hexBytesToString(msg); break; // mostly for running tests
    }

    // constants [§4.2.3]
    var K = [
        '428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc',
        '3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118',
        'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2',
        '72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694',
        'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65',
        '2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5',
        '983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4',
        'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70',
        '27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df',
        '650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b',
        'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30',
        'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8',
        '19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8',
        '391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3',
        '748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec',
        '90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b',
        'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178',
        '06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b',
        '28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c',
        '4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817',
    ].map(function(k) { return Sha512.Long.fromString(k); }); // note no '=>' in IE

    // initial hash value [§5.3.5]
    var H = [
        '6a09e667f3bcc908', 'bb67ae8584caa73b', '3c6ef372fe94f82b', 'a54ff53a5f1d36f1',
        '510e527fade682d1', '9b05688c2b3e6c1f', '1f83d9abfb41bd6b', '5be0cd19137e2179',
    ].map(function(h) { return Sha512.Long.fromString(h); }); // note no '=>' in IE

    // PREPROCESSING [§6.4.1]

    msg += String.fromCharCode(0x80);  // add trailing '1' bit (+ 0's padding) to string [§5.1.2]

    // convert string msg into 1024-bit blocks (array of 16 uint64) [§5.2.2]
    var l = msg.length/8 + 2; // length (in 64-bit longs) of msg + ‘1’ + appended length
    var N = Math.ceil(l/16);  // number of 16-long (1024-bit) blocks required to hold 'l' ints
    var M = new Array(N);     // message M is N×16 array of 64-bit integers

    for (var i=0; i<N; i++) {
        M[i] = new Array(16);
        for (var j=0; j<16; j++) { // encode 8 chars per uint64 (128 per block), big-endian encoding
            var lo = (msg.charCodeAt(i*128+j*8+0)<<24) | (msg.charCodeAt(i*128+j*8+1)<<16) |
                     (msg.charCodeAt(i*128+j*8+2)<< 8) | (msg.charCodeAt(i*128+j*8+3)<< 0);
            var hi = (msg.charCodeAt(i*128+j*8+4)<<24) | (msg.charCodeAt(i*128+j*8+5)<<16) |
                     (msg.charCodeAt(i*128+j*8+6)<< 8) | (msg.charCodeAt(i*128+j*8+7)<< 0);
            M[i][j] = new Sha512.Long(lo, hi);
        } // note running off the end of msg is ok 'cos bitwise ops on NaN return 0
    }
    // add length (in bits) into final pair of 64-bit integers (big-endian) [§5.1.2]
    M[N-1][14] = new Sha512.Long(0, 0); // tooo hard... limit msg to 2 million terabytes
    // note: most significant word would be (len-1)*8 >>> 32, but since JS converts
    // bitwise-op args to 32 bits, we need to simulate this by arithmetic operators
    var lenHi = ((msg.length-1)*8) / Math.pow(2, 32);
    var lenLo = ((msg.length-1)*8) >>> 0; // note '>>> 0' coerces number to unsigned 32-bit integer
    M[N-1][15] = new Sha512.Long(Math.floor(lenHi), lenLo);


    // HASH COMPUTATION [§6.4.2]

    for (var i=0; i<N; i++) {
        var W = new Array(80);

        // 1 - prepare message schedule 'W'
        for (var t=0;  t<16; t++) W[t] = M[i][t];
        for (var t=16; t<80; t++) {
            W[t] = (Sha512.σ1(W[t-2]).add(W[t-7]).add(Sha512.σ0(W[t-15])).add(W[t-16]));
        }

        // 2 - initialise working variables a, b, c, d, e, f, g, h with previous hash value
        var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];

        // 3 - main loop (note 'addition modulo 2^64')
        for (var t=0; t<80; t++) {
            var T1 = h.add(Sha512.Σ1(e)).add(Sha512.Ch(e, f, g)).add(K[t]).add(W[t]);
            var T2 = Sha512.Σ0(a).add(Sha512.Maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.add(T1);
            d = c;
            c = b;
            b = a;
            a = T1.add(T2);
        }

        // 4 - compute the new intermediate hash value
        H[0] = H[0].add(a);
        H[1] = H[1].add(b);
        H[2] = H[2].add(c);
        H[3] = H[3].add(d);
        H[4] = H[4].add(e);
        H[5] = H[5].add(f);
        H[6] = H[6].add(g);
        H[7] = H[7].add(h);
    }

    // convert H0..H7 to hex strings (with leading zeros)
    for (var h=0; h<H.length; h++) H[h] = H[h].toString();

    // concatenate H0..H7, with separator if required
    var separator = opt.outFormat=='hex-w' ? ' ' : '';

    return H.join(separator);
};


/**
 * Rotates right (circular right shift) value x by n positions [§3.2.4].
 * @private
 */
Sha512.ROTR = function(x, n) { // emulates (x >>> n) | (x << (64-n)
    if (n == 0) return x;
    if (n == 32) return new Sha512.Long(x.lo, x.hi);

    var hi = x.hi, lo = x.lo;

    if (n > 32) { // swap hi/lo
        var tmp = lo;
        lo = hi;
        hi = tmp;
        n -= 32;
    }

    var hi1 = (hi >>> n) | (lo << (32-n));
    var lo1 = (lo >>> n) | (hi << (32-n));

    return new Sha512.Long(hi1, lo1);
};


/**
 * Logical functions [§4.1.3].
 * @private
 */
Sha512.Σ0  = function(x) { return Sha512.ROTR(x, 28).xor(Sha512.ROTR(x, 34)).xor(Sha512.ROTR(x, 39)); };
Sha512.Σ1  = function(x) { return Sha512.ROTR(x, 14).xor(Sha512.ROTR(x, 18)).xor(Sha512.ROTR(x, 41)); };
Sha512.σ0  = function(x) { return Sha512.ROTR(x,  1).xor(Sha512.ROTR(x,  8)).xor(x.shr(7)); };
Sha512.σ1  = function(x) { return Sha512.ROTR(x, 19).xor(Sha512.ROTR(x, 61)).xor(x.shr(6)); };
Sha512.Ch  = function(x, y, z) { return (x.and(y)).xor(x.not().and(z)); };         // 'choice'
Sha512.Maj = function(x, y, z) { return (x.and(y)).xor(x.and(z)).xor(y.and(z)); }; // 'majority'


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

/*
 * 'Long' library for handling unsigned 64-bit integers. All string manipulation is radix 16.
 *
 * Note n >>> 0 coerces n to unsigned 32-bit value.
 */

Sha512.Long = function(hi, lo) {
    this.hi = hi >>> 0;
    this.lo = lo >>> 0;
};

Sha512.Long.fromString = function(str) {
    var hi = parseInt(str.slice(0, -8), 16);
    var lo = parseInt(str.slice(-8), 16);

    return new Sha512.Long(hi, lo);
};

Sha512.Long.prototype.toString = function() {
    var hi = ('00000000'+this.hi.toString(16)).slice(-8);
    var lo = ('00000000'+this.lo.toString(16)).slice(-8);

    return hi + lo;
};

Sha512.Long.prototype.add = function(that) { // addition modulo 2^64
    var lo = this.lo + that.lo;
    var hi = this.hi + that.hi + (lo>0x100000000 ? 1 : 0); // carry top bit if lo > 2^32

    return new Sha512.Long(hi >>> 0, lo >>> 0);
};

Sha512.Long.prototype.and = function(that) { // &
    return new Sha512.Long(this.hi & that.hi, this.lo & that.lo);
};

Sha512.Long.prototype.xor = function(that) { // ^
    return new Sha512.Long(this.hi ^ that.hi, this.lo ^ that.lo);
};

Sha512.Long.prototype.not = function() {  // ~
    return new Sha512.Long(~this.hi, ~this.lo);
};

Sha512.Long.prototype.shr = function(n) { // >>>
    if (n ==  0) return this;
    if (n == 32) return new Sha512.Long(0, this.hi);
    if (n >  32) return new Sha512.Long(0, this.hi >>> n-32);
    /* else */   return new Sha512.Long(this.hi >>> n, this.lo >>> n | this.hi << (32-n));
};

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */


/**
 * Encodes multi-byte string to utf8 - monsur.hossa.in/2012/07/20/utf-8-in-javascript.html
 */
Sha512.utf8Encode = function(str) {
    return unescape(encodeURIComponent(str));
};


/**
 * Converts a string of a sequence of hex numbers to a string of characters (eg '616263' => 'abc').
 */
Sha512.hexBytesToString = function(hexStr) {
    hexStr = hexStr.replace(' ', ''); // allow space-separated groups
    var str = '';
    for (var i=0; i<hexStr.length; i+=2) {
        str += String.fromCharCode(parseInt(hexStr.slice(i, i+2), 16));
    }
    return str;
};


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
if (typeof module != 'undefined' && module.exports) module.exports = Sha512; // CommonJs export
