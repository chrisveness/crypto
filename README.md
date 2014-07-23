crypto
======

Libraries of cryptographic functions implemented in JavaScript.

aes.js
------

This is a reference implementation of the algorithm described in the FIPS-197 standard. It implements
the standard very closely, in order to aid in understanding the standard and the algorithm itself.

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

More details are available at www.movable-type.co.uk/scripts/aes.html.

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
