import argon2 from 'argon2';

// Usage: npm run make-hash
// Provide either PASSWORD (plaintext) or CLIENT_PW_HASH (sha256 hex), and PEPPER
const passwordOrClientHash = process.env.PASSWORD || process.env.CLIENT_PW_HASH;
const pepper = process.env.PEPPER || '';

if (!passwordOrClientHash) {
  console.error('Set PASSWORD (plaintext) or CLIENT_PW_HASH (sha256 hex) in env.');
  process.exit(1);
}

const input = passwordOrClientHash + pepper;
const hash = await argon2.hash(input, { type: argon2.argon2id });
console.log('LOGIN_HASH=', hash);
