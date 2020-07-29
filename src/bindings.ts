import { threadId } from 'worker_threads';

const path = require('path');
const bindings: any = require(path.join(__dirname, '../native'));

export const initKeygen = (
  server: string,
  threshold: number,
  parties: number
) => {
  return JSON.parse(bindings.initKeygen(server, threshold, parties));
};

export const signMessage = (
  keydata: any,
  server: string,
  path: string,
  threshold: number,
  parties: number,
  message: string
) => {
  return bindings.signMessage(
    keydata,
    server,
    path,
    threshold,
    parties,
    message
  );
};
