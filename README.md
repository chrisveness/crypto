crypto
======

Libraries of cryptographic functions implemented in JavaScript.

tea-block.js
------------

Wheeler & Needham’s *Tiny Encryption Algorithm* is a simple but powerful encryption algorithm which provides strong encryption in just a few lines of concise, clear code. This implements the (corrected) ‘Block TEA’ variant (xxtea).

The library includes:

- `encrypt` a text with a password
- `decrypt` an encrypted text
- `encode` an array of longs using a 128-bit key
- `decode` an encoded array of longs

More details are available at www.movable-type.co.uk/scripts/tea-block.html.
