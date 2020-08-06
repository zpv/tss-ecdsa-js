import * as BN from 'bn.js';
import { compressPubkey } from './utils';

const path = require('path');
const bindings: any = require(path.join(__dirname, '../native'));

function timeout(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export const initKeygen = async (
  server: string,
  threshold: number,
  parties: number
) =>
  new Promise((resolve, reject) => {
    bindings.initKeygen(server, threshold, parties, (err, val) => {
      if (err) return reject(err);
      resolve(JSON.parse(val));
    });
  });

export const signMessage = (
  keydata: any,
  server: string,
  path: string,
  threshold: number,
  parties: number,
  message: string
) =>
  new Promise((resolve, reject) => {
    bindings.signMessage(
      keydata,
      server,
      path,
      threshold,
      parties,
      message,
      (err, val) => {
        if (err) return reject(err);
        resolve(JSON.parse(val));
      }
    );
  });

export const getPubkey = (keydata: any, path: string) => {
  const pubkey = JSON.parse(bindings.getPubkey(keydata, path));
  const x: Buffer = new BN(pubkey.x, 16, 'be').toArrayLike(Buffer, 'be', 32);
  const y: Buffer = new BN(pubkey.y, 16, 'be').toArrayLike(Buffer, 'be', 32);

  return { x, y, path: pubkey.path };
};

export const getCompressedPubkey = (keydata: any, path: string) => {
  const pubkey = getPubkey(keydata, path);
  return compressPubkey(pubkey.x, pubkey.y);
};
