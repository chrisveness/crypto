/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* Crypto Test Harness - SHA-3                                        (c) Chris Veness 2016-2019  */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

import Sha3 from '../src/sha3.js';

if (typeof window == 'undefined') { // node
    import('chai').then(chai => { global.should = chai.should(); });
} else {                            // browser
    // eslint-disable-next-line no-undef
    window.should = chai.should();
}


describe('SHA-3', function() {

    // csrc.nist.gov/groups/ST/toolkit/examples.html#aHashing (0-bit files)
    describe('NIST CSRC FIPS 180-2 SHA-3 examples', function() {
        it("hashes '' @ 224", function() { Sha3.hash224('', { outFormat: 'hex-b' }).should.equal('6b 4e 03 42 36 67 db b7 3b 6e 15 45 4f 0e b1 ab d4 59 7f 9a 1b 07 8e 3f 5b 5a 6b c7'); });
        it("hashes '' @ 256", function() { Sha3.hash256('', { outFormat: 'hex-b' }).should.equal('a7 ff c6 f8 bf 1e d7 66 51 c1 47 56 a0 61 d6 62 f5 80 ff 4d e4 3b 49 fa 82 d8 0a 4b 80 f8 43 4a'); });
        it("hashes '' @ 384", function() { Sha3.hash384('', { outFormat: 'hex-b' }).should.equal('0c 63 a7 5b 84 5e 4f 7d 01 10 7d 85 2e 4c 24 85 c5 1a 50 aa aa 94 fc 61 99 5e 71 bb ee 98 3a 2a c3 71 38 31 26 4a db 47 fb 6b d1 e0 58 d5 f0 04'); });
        it("hashes '' @ 512", function() { Sha3.hash512('', { outFormat: 'hex-b' }).should.equal('a6 9f 73 cc a2 3a 9a c5 c8 b5 67 dc 18 5a 75 6e 97 c9 82 16 4f e2 58 59 e0 d1 dc c1 47 5c 80 a6 15 b2 12 3a f1 f5 f9 4c 11 e3 e9 40 2c 3a c5 58 f5 00 19 9d 95 b6 d3 e3 01 75 85 86 28 1d cd 26'); });
    });

    // www.di-mgt.com.au/sha_testvectors.html
    describe('DI Management test vectors', function() {
        this.timeout(10000);
        it('hashes abc 224', function() { Sha3.hash224('abc', { outFormat: 'hex-w' }).should.equal('e642824c3f8cf24a d09234ee7d3c766f c9a3a5168d0c94ad 73b46fdf'); });
        it('hashes abc 256', function() { Sha3.hash256('abc', { outFormat: 'hex-w' }).should.equal('3a985da74fe225b2 045c172d6bd390bd 855f086e3e9d525b 46bfe24511431532'); });
        it('hashes abc 384', function() { Sha3.hash384('abc', { outFormat: 'hex-w' }).should.equal('ec01498288516fc9 26459f58e2c6ad8d f9b473cb0fc08c25 96da7cf0e49be4b2 98d88cea927ac7f5 39f1edf228376d25'); });
        it('hashes abc 512', function() { Sha3.hash512('abc', { outFormat: 'hex-w' }).should.equal('b751850b1a57168a 5693cd924b6b096e 08f621827444f70d 884f5d0240d2712e 10e116e9192af3c9 1a7ec57647e39340 57340b4cf408d5a5 6592f8274eec53f0'); });
        const msg448 = 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq';
        it('hashes msg l448 224', function() { Sha3.hash224(msg448, { outFormat: 'hex-w' }).should.equal('8a24108b154ada21 c9fd5574494479ba 5c7e7ab76ef264ea d0fcce33'); });
        it('hashes msg l448 256', function() { Sha3.hash256(msg448, { outFormat: 'hex-w' }).should.equal('41c0dba2a9d62408 49100376a8235e2c 82e1b9998a999e21 db32dd97496d3376'); });
        it('hashes msg l448 384', function() { Sha3.hash384(msg448, { outFormat: 'hex-w' }).should.equal('991c665755eb3a4b 6bbdfb75c78a492e 8c56a22c5c4d7e42 9bfdbc32b9d4ad5a a04a1f076e62fea1 9eef51acd0657c22'); });
        it('hashes msg l448 512', function() { Sha3.hash512(msg448, { outFormat: 'hex-w' }).should.equal('04a371e84ecfb5b8 b77cb48610fca818 2dd457ce6f326a0f d3d7ec2f1e91636d ee691fbe0c985302 ba1b0d8dc78c0863 46b533b49c030d99 a27daf1139d6e75e'); });
        const msg1M = 'a'.repeat(1e6);
        it('hashes msg l1M 224', function() { Sha3.hash224(msg1M, { outFormat: 'hex-w' }).should.equal('d69335b93325192e 516a912e6d19a15c b51c6ed5c15243e7 a7fd653c'); });
        it('hashes msg l1M 256', function() { Sha3.hash256(msg1M, { outFormat: 'hex-w' }).should.equal('5c8875ae474a3634 ba4fd55ec85bffd6 61f32aca75c6d699 d0cdcb6c115891c1'); });
        it('hashes msg l1M 384', function() { Sha3.hash384(msg1M, { outFormat: 'hex-w' }).should.equal('eee9e24d78c18553 37983451df97c8ad 9eedf256c6334f8e 948d252d5e0e7684 7aa0774ddb90a842 190d2c558b4b8340'); });
        it('hashes msg l1M 512', function() { Sha3.hash512(msg1M, { outFormat: 'hex-w' }).should.equal('3c3a876da14034ab 60627c077bb98f7e 120a2a5370212dff b3385a18d4f38859 ed311d0a9d5141ce 9cc5c66ee689b266 a8aa18ace8282a0e 0db596c90b0a7b87'); });
    });

    // UTF-8
    describe('UTF-8', function() {
        it('hashes ☺', function() { Sha3.hash512('☺').should.equal('323dea2a28f42085c70e7bcf59fb1be710ba4e85b9d5f53a94928eed73d2e17940a17682820b7b938f2beaedb51590cfe0883d55f5cceeb7b18ff2d02c33bac0'); });
    });

    // csrc.nist.gov/groups/STM/cavp/secure-hashing.html#test-vectors
    describe('NIST CSRC test vectors', function() {
        if (typeof module != 'undefined' && this.module != module) { // only run these tests within node (s/o 4224606)
            responseTestVectors('SHA3_224ShortMsg', Sha3.hash224);
            responseTestVectors('SHA3_224LongMsg', Sha3.hash224);
            responseTestVectors('SHA3_256ShortMsg', Sha3.hash256);
            responseTestVectors('SHA3_256LongMsg', Sha3.hash256);
            responseTestVectors('SHA3_384ShortMsg', Sha3.hash384);
            responseTestVectors('SHA3_384LongMsg', Sha3.hash384);
            responseTestVectors('SHA3_512ShortMsg', Sha3.hash512);
            responseTestVectors('SHA3_512LongMsg', Sha3.hash512);
        }
    });

    function responseTestVectors(file, fn) {
        const fs = require('fs');
        const rsp = fs.readFileSync(`./test/${file}.rsp`, 'utf8');
        const msg = rsp.split('\r\n').filter(line => line.slice(0, 6) == 'Msg = ').map(line => line.slice(6));
        const md = rsp.split('\r\n').filter(line => line.slice(0, 5) == 'MD = ').map(line => line.slice(5));
        for (let t=0; t<msg.length; t++) {
            if (msg[t] == '00') msg[t] = ''; // what are NIST up to? '00'.length == 0? duh!
            it(`hashes ${file} Len ${msg[t].length}`, function() { fn(msg[t], { msgFormat: 'hex-bytes' }).should.equal(md[t]); });
        }
    }
});


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
