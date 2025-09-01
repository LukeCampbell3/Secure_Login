import 'dotenv/config';
import argon2 from 'argon2';
import crypto from 'crypto';
import fs from 'fs';

// --- CONFIG (change ONLY if you want to test a different password) ---
const PLAINTEXT = 'password'; // what you type in the form

// --- Load from .env exactly as the server will ---
const USERNAME = (process.env.LOGIN_USERNAME || '').trim();
const PEPPER   = (process.env.PEPPER || '').trim();
let   HASH     = (process.env.LOGIN_HASH || '').trim();

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

const pwhex = sha256Hex(PLAINTEXT);               // client-side pw_hash
const input = pwhex + PEPPER;                     // verifier input

console.log('ENV PREVIEW', {
  USERNAME,
  PEPPER_len: PEPPER.length,
  HASH_startsWith: HASH.slice(0, 10),
  HASH_len: HASH.length,
  pwhex_sample: pwhex.slice(0, 8),
  pwhex_len: pwhex.length
});

let ok = false;
try {
  ok = await argon2.verify(HASH, input);
} catch (e) {
  console.log('verify threw:', e.message);
}
console.log('verify(current HASH)=', ok);

if (!ok) {
  console.log('\n--- REGENERATING A MATCHING HASH NOW ---');
  // match the params you’ve been using (seen in your hash: m=65536, t=3, p=4; type = argon2id)
  const newHash = await argon2.hash(input, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
  });
  console.log('NEW_LOGIN_HASH=', newHash);

  // sanity: this must be true
  const ok2 = await argon2.verify(newHash, input);
  console.log('verify(newHash)=', ok2);

  // OPTIONAL: auto-write a patched .env (commented out by default)
  // const envPath = new URL('../.env', import.meta.url).pathname;
  // const envText = fs.readFileSync(envPath, 'utf8').replace(/^LOGIN_HASH=.*$/m, `LOGIN_HASH=${newHash}`);
  // fs.writeFileSync(envPath, envText);
  // console.log('Wrote new LOGIN_HASH into server/.env');
}