export const compressPubkey = (x, y) => {
  const odd = y[y.length - 1] & 1;
  const buf = Buffer.alloc(33);
  buf[0] = odd ? 0x03 : 0x02;
  buf.set(x, 1);

  return buf;
};

export const range = (n) => Array.from({ length: n }, (value, key) => key);
