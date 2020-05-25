/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* SHA-3 (FIPS 202) ‘Keccak’ reference implementation in JavaScript   (c) Chris Veness 2016-2020  */
/*                                                                                   MIT Licence  */
/* www.movable-type.co.uk/scripts/sha3.html                                                       */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */


/**
 * SHA-3 (FIPS 202) ‘Keccak’ hash functions.
 *
 * This is an annotated reference implementation intended to aid understanding of the algorithm.
 * While it is fully tested, it is not at all optimised and is not recommended for production use.
 *
 * See keccak.noekeon.org/Keccak-reference-3.0.pdf
 *     nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
 */
class Sha3 {

    /*
     * Keccak-f[b] permutations:
     *  - ℓ:  0  1   2   3   4   5    6
     *  - w:  1  2   4   8  16  32   64 (2ˡ)
     *  - b: 25 50 100 200 400 800 1600 (25 × 2ˡ)
     * SHA-3 specifies Keccak-f[1600] only, hence ℓ=6, w=64, b=1600.
     */


    /**
     * Generates 224-bit SHA-3 / Keccak hash of message.
     *
     * @param   {string} message - String to be hashed (Unicode-safe).
     * @param   {Object} options - padding: sha-3 / keccak; msgFormat: string / hex; outFormat: hex / hex-b / hex-w.
     * @returns {string} Hash as hex-encoded string.
     *
     * @example
     *   import Sha3 from './sha3.js';
     *   const hash = Sha3.hash224('abc'); // 'e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf'
     */
    static hash224(message, options) {
        return Sha3.keccak1600(1152, 448, message, options);
    }

    /**
     * Generates 256-bit SHA-3 / Keccak hash of message.
     *
     * @param   {string} message - String to be hashed (Unicode-safe).
     * @param   {Object} options - padding: sha-3 / keccak; msgFormat: string / hex; outFormat: hex / hex-b / hex-w.
     * @returns {string} Hash as hex-encoded string.
     */
    static hash256(message, options) {
        return Sha3.keccak1600(1088, 512, message, options);
    }

    /**
     * Generates 384-bit SHA-3 / Keccak hash of message.
     *
     * @param   {string} message - String to be hashed (Unicode-safe).
     * @param   {Object} options - padding: sha-3 / keccak; msgFormat: string / hex; outFormat: hex / hex-b / hex-w.
     * @returns {string} Hash as hex-encoded string.
     */
    static hash384(message, options) {
        return Sha3.keccak1600(832, 768, message, options);
    }

    /**
     * Generates 512-bit SHA-3 / Keccak hash of message.
     *
     * @param   {string} message - String to be hashed (Unicode-safe).
     * @param   {Object} options - padding: sha-3 / keccak; msgFormat: string / hex; outFormat: hex / hex-b / hex-w.
     * @returns {string} Hash as hex-encoded string.
     */
    static hash512(message, options) {
        return Sha3.keccak1600(576, 1024, message, options);
    }


    /**
     * Generates SHA-3 / Keccak hash of message M.
     *
     * @param   {number} r - Bitrate 'r' (b−c)
     * @param   {number} c - Capacity 'c' (b−r), md length × 2
     * @param   {string} M - Message
     * @param   {Object} options - padding: sha-3 / keccak; msgFormat: string / hex; outFormat: hex / hex-b / hex-w.
     * @returns {string} Hash as hex-encoded string.
     *
     * @private
     */
    static keccak1600(r, c, M, options) {
        const defaults = { padding: 'sha-3', msgFormat: 'string', outFormat: 'hex' };
        const opt = Object.assign(defaults, options);

        const l = c / 2; // message digest output length in bits

        let msg = null;
        switch (opt.msgFormat) {
            default: // convert string to UTF-8 to ensure all characters fit within single byte
            case 'string':    msg = utf8Encode(M);       break;
            case 'hex-bytes': msg = hexBytesToString(M); break; // mostly for NIST test vectors
        }

        /**
         * Keccak state is a 5 × 5 x w array of bits (w=64 for keccak-f[1600] / SHA-3).
         *
         * Here, it is implemented as a 5 × 5 array of BigInt. The first subscript (x) defines the
         * sheet, the second (y) defines the plane, together they define a lane. Slices, columns,
         * and individual bits are obtained by bit operations on the BigInt representing the lane
         * (note BigInt is the JavaScript equivalent of Int64 / long).
         */
        const state = [ [], [], [], [], [] ];
        for (let x=0; x<5; x++) {
            for (let y=0; y<5; y++) {
                state[x][y] = 0n;
            }
        }

        // append padding (for SHA-3 the domain is 01 hence M||0110*1) [FIPS §B.2]
        const q = (r/8) - msg.length % (r/8);
        if (q == 1) {
            msg += String.fromCharCode(opt.padding=='keccak' ? 0x81 : 0x86);
        } else {
            msg += String.fromCharCode(opt.padding=='keccak' ? 0x01 : 0x06);
            msg += String.fromCharCode(0x00).repeat(q-2);
            msg += String.fromCharCode(0x80);
        }

        // absorbing phase: work through input message in blocks of r bits (r/64 longs, r/8 bytes)

        const w = 64; // for keccak-f[1600]
        const blocksize = r / w * 8; // block size in bytes (≡ utf-8 characters)

        for (let i=0; i<msg.length; i+=blocksize) {
            for (let j=0; j<r/w; j++) {
                const i64 = (BigInt(msg.charCodeAt(i+j*8+0))<< 0n) + (BigInt(msg.charCodeAt(i+j*8+1))<< 8n)
                          + (BigInt(msg.charCodeAt(i+j*8+2))<<16n) + (BigInt(msg.charCodeAt(i+j*8+3))<<24n)
                          + (BigInt(msg.charCodeAt(i+j*8+4))<<32n) + (BigInt(msg.charCodeAt(i+j*8+5))<<40n)
                          + (BigInt(msg.charCodeAt(i+j*8+6))<<48n) + (BigInt(msg.charCodeAt(i+j*8+7))<<56n);
                const x = j % 5;
                const y = Math.floor(j / 5);
                state[x][y] = state[x][y] ^ i64;
            }
            Sha3.keccak_f_1600(state);
        }

        // squeezing phase: first l bits of state are message digest

        // transpose state, concatenate (little-endian) hex values, & truncate to l bits
        let md = transpose(state)
            .map(plane => plane.map(lane => lane.toString(16).padStart(16, '0').match(/.{2}/g).reverse().join('')).join(''))
            .join('')
            .slice(0, l/4);

        // if required, group message digest into bytes or words
        if (opt.outFormat == 'hex-b') md = md.match(/.{2}/g).join(' ');
        if (opt.outFormat == 'hex-w') md = md.match(/.{8,16}/g).join(' ');

        return md;

        /* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

        function transpose(array) { // to iterate across y (columns) before x (rows)
            return array.map((row, r) => array.map(col => col[r]));
        }

        function utf8Encode(str) {
            try {
                return new TextEncoder().encode(str, 'utf-8').reduce((prev, curr) => prev + String.fromCharCode(curr), '');
            } catch (e) { // no TextEncoder available?
                return unescape(encodeURIComponent(str)); // monsur.hossa.in/2012/07/20/utf-8-in-javascript.html
            }
        }

        function hexBytesToString(hexStr) { // convert string of hex numbers to a string of chars (eg '616263' -> 'abc').
            const str = hexStr.replace(' ', ''); // allow space-separated groups
            return str=='' ? '' : str.match(/.{2}/g).map(byte => String.fromCharCode(parseInt(byte, 16))).join('');
        }
    }


    /**
     * Applies permutation Keccak-f[1600] to state a.
     *
     * @param {BigInt[][]} a - State to be permuted (5 × 5 array of BigInt).
     *
     * @private
     */
    static keccak_f_1600(a) {

        const nRounds = 24; // number of rounds nᵣ = 12 + 2ℓ, hence 24 for Keccak-f[1600] [Keccak §1.2]

        /**
         * Round constants: output of a maximum-length linear feedback shift register (LFSR) for the
         * ι step [Keccak §1.2, §2.3.5], keccak.noekeon.org/specs_summary.html.
         *
         *   RC[iᵣ][0][0][2ʲ−1] = rc[j+7iᵣ] for 0 ≤ j ≤ l
         * where
         *   rc[t] = ( xᵗ mod x⁸ + x⁶ + x⁵ + x⁴ + 1 ) mod x in GF(2)[x].
         */
        const RC = [
            0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an,
            0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
            0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an,
            0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
            0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n,
            0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
            0x000000000000800an, 0x800000008000000an, 0x8000000080008081n,
            0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
        ];

        // Keccak-f permutations
        for (let r=0; r<nRounds; r++) {
            // apply step mappings θ, ρ, π, χ, ι to the state 'a'

            // θ [Keccak §2.3.2]
            const C = [], D = []; // intermediate sub-states
            for (let x=0; x<5; x++) {
                C[x] = a[x][0];
                for (let y=1; y<5; y++) {
                    C[x] = C[x] ^ a[x][y];
                }
            }
            for (let x=0; x<5; x++) {
                // D[x] = C[x−1] ⊕ ROT(C[x+1], 1)
                D[x] = C[(x+4)%5] ^ ROT(C[(x+1)%5], 1);
                // a[x,y] = a[x,y] ⊕ D[x]
                for (let y=0; y<5; y++) {
                    a[x][y] = a[x][y] ^ D[x];
                }
            }

            // ρ + π [Keccak §2.3.4]
            let [ x, y ] = [ 1, 0 ];
            let current = a[x][y];
            for (let t=0; t<24; t++) {
                const [ X, Y ] = [ y, (2*x + 3*y) % 5 ];
                const tmp = a[X][Y];
                a[X][Y] = ROT(current, ((t+1)*(t+2)/2) % 64);
                current = tmp;
                [ x, y ] = [ X, Y ];
            }
            // note by folding the π step into the ρ step, it is only necessary to cache the current
            // lane; with π looping around x & y, it would be necessary to take a copy of the full
            // state for the A[X,Y] = a[x,y] operation

            // χ [Keccak §2.3.1]
            for (let y=0; y<5; y++) {
                const C = [];  // take a copy of the plane
                for (let x=0; x<5; x++) C[x] = a[x][y];
                for (let x=0; x<5; x++) {
                    a[x][y] = (C[x] ^ ((~C[(x+1)%5]) & C[(x+2)%5]));
                }
            }

            // ι [Keccak §2.3.5]
            a[0][0] = (a[0][0] ^ RC[r]);
        }

        function ROT(a, d) { // 64-bit rotate left
            return BigInt.asUintN(64, a << BigInt(d) | a >> BigInt(64-d));
        }

        function debugNist(s) { // debug of state s in NIST format
            const d = transpose(s)
                .map(plane => plane.map(lane => lane.toString(16).padStart(16, '0').match(/.{2}/g).reverse().join('')).join(''))
                .join('')
                .match(/.{2}/g).join(' ')
                .match(/.{23,48}/g).join('\n');
            console.info(d);
        }

        function debug5x5(s) { // debug of state s in 5×5 format 64-bit words
            const d = transpose(s)
                .map(plane => plane.map(lane => lane.toString(16).padStart(16, '0')).join(' '))
                .join('\n');
            console.info(d);
        }

        function transpose(array) { // to iterate across y (columns) before x (rows)
            return array.map((row, r) => array.map(col => col[r]));
        }
    }

}


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

export default Sha3;
