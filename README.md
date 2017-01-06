crypto
======

Reference implementations of AES & SHA cryptographic functions in JavaScript.

These annotated implementations follow the standards very closely, in order to assist in studying 
the standards and underlying algorithms. Note for production use I would recommend the
[Web Cryptography API](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto) for the browser, 
or the [crypto](https://nodejs.org/api/crypto.html) library in Node.js.

aes.js
------

This is a reference implementation of the AES (Rijndael cipher) algorithm described in the FIPS-197 
standard.

This comprises:

- `cipher`: takes a 128-bit input block and applies the cipher algorithm to produce a 128-bit output block
- `keyExpansion`: applies a key expansion to a 128-/192-/256-bit cipher key to produce a 2D byte-array
  key schedule for the cipher routine

More details are available at www.movable-type.co.uk/scripts/aes.html.

aes-ctr.js
----------

This is a counter-mode (CTR) wrapper for the AES function.

This comprises:

- `encrypt`: encrypt a plaintext using a supplied password
- `decrypt`: decrypt an encrypted ciphertext using a supplied password

Note that there are no standards for data storage formats of AES encryption mode wrapper functions,
so this is unlikely to inter-operate with standard library functions.

More details are available at www.movable-type.co.uk/scripts/aes.html.

sha1.js
-------

This is a reference implementation of the SHA-1 algorithm described in the FIPS-180-4 standard.

This comprises:

- `hash`: takes a (Unicode) string and generates a hash (of the UTF-8 encoded string)

More details are available at www.movable-type.co.uk/scripts/sha1.html.

sha256.js
---------

This is a reference implementation of the SHA-256 algorithm described in the FIPS-180-4 standard.

This comprises:

- `hash`: takes a (Unicode) string and generates a hash (of the UTF-8 encoded string)

Note that while SHA-256 and SHA-512 are both members of the SHA-2 family, there is little common
code, so they are in separate files here.

More details are available at www.movable-type.co.uk/scripts/sha256.html.

sha512.js
---------

This is a reference implementation of the SHA-512 algorithm described in the FIPS-180-4 standard.

This comprises:

- `hash`: takes a (Unicode) string and generates a hash (of the UTF-8 encoded string)

Note that while SHA-256 and SHA-512 are both members of the SHA-2 family, there is little common
code, so they are in separate files here.

More details are available at www.movable-type.co.uk/scripts/sha512.html.

sha3.js
-------

This is a reference implementation of the SHA-3 (Keccak) algorithm described in the FIPS-202 standard.

This comprises:

- `hash224`: takes a (Unicode) string and generates a SHA3/224 hash (of the UTF-8 encoded string)
- `hash256`: takes a (Unicode) string and generates a SHA3/256 hash (of the UTF-8 encoded string)
- `hash384`: takes a (Unicode) string and generates a SHA3/384 hash (of the UTF-8 encoded string)
- `hash512`: takes a (Unicode) string and generates a SHA3/512 hash (of the UTF-8 encoded string)

More details are available at www.movable-type.co.uk/scripts/sha3.html.


tea-block.js
------------

Wheeler & Needham’s *Tiny Encryption Algorithm* is a simple but powerful encryption algorithm which
provides strong encryption in just a few lines of concise, clear code. This implements the (corrected)
‘Block TEA’ variant (xxtea).

The library includes:

- `encrypt` a text with a password
- `decrypt` an encrypted text
- `encode` an array of longs using a 128-bit key
- `decode` an encoded array of longs

More details are available at www.movable-type.co.uk/scripts/tea-block.html.

Documentation
-------------

Documentation for all these methods is available at www.movable-type.co.uk/scripts/js/crypto/docs.

JavaScript
----------

Cryptographically-speaking, browsers are 
[inherently](//www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2011/august/javascript-cryptography-considered-harmful)
[insecure](//tonyarcieri.com/whats-wrong-with-webcrypto) (Node.js does not suffer the same problems),
but these implementations are intended for study rather than production use. With its untyped C-style 
syntax, JavaScript reads remarkably close to pseudo-code: exposing the algorithms with a minimum of 
syntactic distractions.

These implementations are written in ES2015 version of JavaScript; ES2015 `class`es are both clearer
and more familiar to users of other languages than the ES5 equivalents, and `let` and `const` are
good practice and communicate intent better than `var`. Other idiomatic JavaScript which might be 
less familiar to users of other languages has generally been avoided.
