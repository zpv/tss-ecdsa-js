import { expect } from 'chai';
import { compressPubkey, range } from '../src/utils';
import { signMessage, getPubkey, initKeygen } from '../src/bindings';
import * as BN from 'bn.js';
import * as ec from 'secp256k1';
import 'mocha';
import * as bitcoin from 'bitcoinjs-lib';

const MANAGER_URL = 'http://localhost:8001';

for (let n = 2; n < 15; n++) {
  for (let t = 1; t < n - 1; t++) {
    testScheme(t, n, '0/1/3');
  }
}

function testScheme(t, n, path) {
  describe(`${t + 1}-of-${n} Signature Scheme`, function () {
    let keys;

    before(async () => {
      keys = await Promise.all(
        range(n).map((i) => initKeygen(MANAGER_URL, t, n))
      );
    });

    it(`pubkeys from ${n} shares match`, async () => {
      const pubkeys = range(n).map((i) => getPubkey(keys[i], path));

      pubkeys.forEach((pubkey) => {
        expect(pubkey).to.deep.equal(pubkeys[0]);
      });
    });

    it('signs message with valid signature', async () => {
      this.timeout(0);
      const message = bitcoin.crypto.sha256(
        Buffer.from(
          'The Times 03/Jan/2009 Chancellor on brink of second bailout for banks'
        )
      );

      const signatures: any[] = await Promise.all(
        range(t + 1).map((i) =>
          signMessage(keys[i], MANAGER_URL, path, t, n, message.toString('hex'))
        )
      );

      const pubkey = await getPubkey(keys[0], path);

      let x = new BN(pubkey.x, 16, 'be').toArrayLike(Buffer, 'be', 32);
      let y = new BN(pubkey.y, 16, 'be').toArrayLike(Buffer, 'be', 32);

      const compressedPubkey = compressPubkey(x, y);

      signatures.forEach((signature) => {
        expect(signature).to.deep.equal(signatures[0]);
      });

      let r = new BN(signatures[0].r, 16, 'be');
      let s = new BN(signatures[0].s, 16, 'be');

      const signatureBytes = Buffer.concat([
        r.toArrayLike(Buffer, 'be', 32),
        s.toArrayLike(Buffer, 'be', 32),
      ]);

      expect(
        ec.ecdsaVerify(
          ec.signatureNormalize(signatureBytes),
          message,
          compressedPubkey
        )
      ).to.be.true;
    });
  });
}
