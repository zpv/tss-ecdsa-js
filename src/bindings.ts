import { threadId } from 'worker_threads';

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
    console.log('called!');
    // timeout(Math.random() * 2000).then(() =>
    bindings.initKeygen(server, threshold, parties, (err, val) => {
      if (err) return reject(err);
      resolve(JSON.parse(val));
    });
    // );
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
    console.log('called sign!');
    timeout(Math.random() * 2000).then(() =>
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
      )
    );
  });

export const getPubkey = (keydata: any, path: string) =>
  JSON.parse(bindings.getPubkey(keydata, path));
