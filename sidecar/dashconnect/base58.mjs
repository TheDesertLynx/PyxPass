//
// base58.mjs — dependency-free Bitcoin/Dash base58 codec.
//
// Verified against canonical vectors (leading-zero handling) and by
// round-tripping real 32-byte Dash Platform identifiers (identity id
// 5dNzK6FTWkBXyvwRvG2awxcbi3LmJaHCyGiyas7MXJtf and the yappr key-exchange
// contract 7UaqHGBJBbRLJ4fUWS45cnud8PPUugJWoGTt1SKwHJ2P both decode to 32
// bytes and re-encode to their exact original).
//

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Encode bytes to a base58 string.
 * @param {Uint8Array|number[]} source
 * @returns {string}
 */
export function base58Encode(source) {
  const bytes = Uint8Array.from(source);
  if (bytes.length === 0) return '';

  const digits = [0];
  for (let i = 0; i < bytes.length; i += 1) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j += 1) {
      const num = digits[j] * 256 + carry;
      digits[j] = num % 58;
      carry = Math.floor(num / 58);
    }
    while (carry) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }

  // digits is little-endian; emit most-significant first, skipping trailing zeros.
  let str = '';
  let i = digits.length - 1;
  while (i >= 0 && digits[i] === 0) i -= 1;
  for (; i >= 0; i -= 1) str += ALPHABET[digits[i]];

  // Leading '1' per leading zero byte.
  for (let z = 0; z < bytes.length && bytes[z] === 0; z += 1) str = `1${str}`;
  return str;
}

/**
 * Decode a base58 string to bytes.
 * @param {string} source
 * @returns {Uint8Array}
 */
export function base58Decode(source) {
  const values = [];
  for (const ch of source) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) throw new Error(`Invalid base58 character: ${ch}`);
    values.push(v);
  }

  const digits = [0];
  for (const v of values) {
    let carry = v;
    for (let j = 0; j < digits.length; j += 1) {
      const num = digits[j] * 58 + carry;
      digits[j] = num % 256;
      carry = Math.floor(num / 256);
    }
    while (carry) {
      digits.push(carry % 256);
      carry = Math.floor(carry / 256);
    }
  }

  const out = [];
  let i = digits.length - 1;
  while (i >= 0 && digits[i] === 0) i -= 1;
  for (; i >= 0; i -= 1) out.push(digits[i]);
  for (let z = 0; z < source.length && source[z] === '1'; z += 1) out.unshift(0);
  return new Uint8Array(out);
}
