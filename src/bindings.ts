import { threadId } from 'worker_threads';

const path = require('path');
const bindings: any = require(path.join(__dirname, '../native'));

export const initKeygen = (
  server: string,
  threshold: number,
  parties: number
) => JSON.parse(bindings.initKeygen(server, threshold, parties));

export const signMessage = (
  keydata: any,
  server: string,
  path: string,
  threshold: number,
  parties: number,
  message: string
) =>
  JSON.parse(
    bindings.signMessage(keydata, server, path, threshold, parties, message)
  );

export const getPubkey = (keydata: any, path: string) =>
  JSON.parse(bindings.getPubkey(keydata, path));
