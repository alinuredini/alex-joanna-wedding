// One-off helper to encrypt the gift PDF for client-side decryption.
//
//   node encrypt.mjs <password> [input.pdf] [output.enc]
//
// Defaults: input=spa-coupon.pdf, output=spa-coupon.enc
//
// Format of the output file (binary):
//   bytes  0..15  -> PBKDF2 salt (16 bytes)
//   bytes 16..27  -> AES-GCM IV (12 bytes)
//   bytes 28..    -> AES-GCM ciphertext || auth tag
//
// Matches the decryption code in alex-joanna-gift.html.

import { webcrypto } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';

const PBKDF2_ITERATIONS = 310_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;

async function deriveKey(password, salt) {
  const material = await webcrypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey'],
  );
  return webcrypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
}

async function main() {
  const [password, inputPath = 'spa-coupon.pdf', outputPath = 'spa-coupon.enc'] = process.argv.slice(2);
  if (!password) {
    console.error('Usage: node encrypt.mjs <password> [input.pdf] [output.enc]');
    process.exit(1);
  }

  const plaintext = await readFile(inputPath);
  const salt = webcrypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = webcrypto.getRandomValues(new Uint8Array(IV_BYTES));
  const key = await deriveKey(password, salt);

  const ciphertext = new Uint8Array(
    await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext),
  );

  const out = new Uint8Array(SALT_BYTES + IV_BYTES + ciphertext.byteLength);
  out.set(salt, 0);
  out.set(iv, SALT_BYTES);
  out.set(ciphertext, SALT_BYTES + IV_BYTES);

  await writeFile(outputPath, out);
  console.log(`Encrypted ${plaintext.byteLength} bytes -> ${out.byteLength} bytes (${outputPath})`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
