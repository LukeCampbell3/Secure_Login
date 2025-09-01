import 'dotenv/config';
import fs from 'fs';
import http from 'http';
import https from 'https';
import express from 'express';
import helmet from 'helmet';
import session from 'express-session';
import rateLimit from 'express-rate-limit';
import argon2 from 'argon2';
import compression from 'compression';
import csurf from 'csurf';

// Optional deps (loaded only if enabled)
let connectRedis, createRedisClient;
try {
  // Don’t crash if user didn’t install redis/connect-redis
  ({ default: connectRedis } = await import('connect-redis').catch(() => ({ default: null })));
  ({ createClient: createRedisClient } = await import('redis').catch(() => ({ createClient: null })));
} catch (_) {}

import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

const isProd = process.env.NODE_ENV === 'production';
const useRedis = String(process.env.USE_REDIS || '').toLowerCase() === 'true';
const useSecrets = String(process.env.USE_SECRETS_MANAGER || '').toLowerCase() === 'true';

async function loadSecretsFromAWS() {
  if (!useSecrets) return {};
  const client = new SecretsManagerClient({ region: process.env.AWS_REGION || 'us-east-1' });
  const id = process.env.SECRET_ID;
  if (!id) return {};
  const out = await client.send(new GetSecretValueCommand({ SecretId: id }));
  const json = out.SecretString ? JSON.parse(out.SecretString) : {};
  return json; // expected keys: SESSION_SECRET, PEPPER, LOGIN_USERNAME, LOGIN_HASH, REDIS_URL
}

const secrets = await loadSecretsFromAWS();
function pick(key, fallback = undefined) {
  return secrets[key] ?? process.env[key] ?? fallback;
}

const app = express();
app.set('trust proxy', 1);

// Helmet + baseline hardening
app.use(helmet());
app.use(compression());
app.use(express.json());

// Tight CSP — the API doesn’t serve HTML, but set anyway for defense-in-depth
const baseCsp = {
  "default-src": ["'self'"],
  "base-uri": ["'self'"],
  "frame-ancestors": ["'none'"],
  "img-src": ["'self'", "data:"],
  "object-src": ["'none'"],
  "style-src": ["'self'", "'unsafe-inline'"],
  "connect-src": ["'self'"]
};
// In dev, Vite HTTPS proxy + HMR may require relaxed connect-src
if (!isProd) {
  baseCsp["connect-src"].push("https://localhost:3000", "https://localhost:5173", "wss://localhost:5173");
}
app.use(helmet.contentSecurityPolicy({ directives: baseCsp }));

// Rate limit login attempts
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api/login', limiter);

// TLS detection
const useTls = (() => {
  const cert = pick('TLS_CERT_PATH');
  const key = pick('TLS_KEY_PATH');
  return cert && key && fs.existsSync(cert) && fs.existsSync(key);
})();
const sessionCookieSecure = useTls || isProd; // require HTTPS to set cookie in browsers

// ----- Session store (Redis optional) -----
let sessionMiddleware;
if (useRedis) {
  if (!connectRedis || !createRedisClient) {
    console.error('USE_REDIS=true but redis/connect-redis not installed. Install them or set USE_REDIS=false.');
    process.exit(1);
  }
  const redisUrl = pick('REDIS_URL', 'redis://localhost:6379');
  const redisClient = createRedisClient({ url: redisUrl });
  try {
    await redisClient.connect();
  } catch (e) {
    console.error(`Failed to connect to Redis at ${redisUrl}. Set USE_REDIS=false to skip Redis.`, e?.message || e);
    process.exit(1);
  }
  const RedisStore = connectRedis(session);
  sessionMiddleware = session({
    name: 'sid',
    store: new RedisStore({ client: redisClient, prefix: 'sess:' }),
    secret: pick('SESSION_SECRET', 'fallback_please_replace'),
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: sessionCookieSecure,
      sameSite: 'lax', // set 'strict' if UX allows
      maxAge: 1000 * 60 * 30
    }
  });
  console.log('Sessions: Redis store enabled');
} else {
  // Dev-only MemoryStore (not for production)
  sessionMiddleware = session({
    name: 'sid',
    secret: pick('SESSION_SECRET', 'fallback_please_replace'),
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: sessionCookieSecure,
      sameSite: 'lax',
      maxAge: 1000 * 60 * 30
    }
  });
  console.log('Sessions: MemoryStore enabled (dev/testing). Do not use in production.');
}
app.use(sessionMiddleware);

// CSRF (session-based)
const csrfProtection = csurf({ cookie: false });
app.get('/api/csrf', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ----- Auth config -----
// ----- Auth config -----
const USERNAME = (pick('LOGIN_USERNAME') || '').trim();       
const HASH = pick('LOGIN_HASH');
const PEPPER = (pick('PEPPER', '') || '').trim();               
if (!USERNAME || !HASH) {
  console.error('Missing LOGIN_USERNAME or LOGIN_HASH. Configure server/.env (or Secrets Manager).');
  process.exit(1);
}

import crypto from 'crypto';

// helper
function sha256Hex(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

// Strong validator for 64-hex
const HEX64 = /^[0-9a-fA-F]{64}$/;

app.post('/api/login', csrfProtection, async (req, res) => {
  try {
    const { username, pw_hash, password } = req.body || {};

    // 1) Basic shape check
    if (typeof username !== 'string' || (!pw_hash && !password)) {
      return res.status(400).json({ error: 'Bad payload' });
    }

    // 2) Username must match
    // Trim the request username before comparing
    const userIn = username.trim();
    if (userIn !== USERNAME) {
      await new Promise(r => setTimeout(r, 150));
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // 3) Normalize to the SAME verifier input: clientPwHex = lowercase sha256 hex
    let clientPwHex = null;

    if (typeof password === 'string') {
      // Accept plaintext path (dev-friendly) — hash it here
      clientPwHex = sha256Hex(password);
    } else if (typeof pw_hash === 'string') {
      const h = pw_hash.trim().toLowerCase();
      if (!HEX64.test(h)) {
        // If someone sent unexpected format (length/case), bail with uniform error
        await new Promise(r => setTimeout(r, 150));
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      clientPwHex = h;
    }

    // 4) Verify with Argon2id: stored LOGIN_HASH must have been created from ( clientPwHex + PEPPER )
    const ok = await argon2.verify(HASH, clientPwHex + PEPPER);
    if (!ok) {
      if (process.env.DEBUG_AUTH === 'true') {
        console.log('DEBUG_AUTH verify=false', {
          userMatch: true,
          pwHexLen: clientPwHex?.length,
          pwHexSample: clientPwHex?.slice(0, 8),
          pepperLen: (PEPPER || '').length
        });
      }
      await new Promise(r => setTimeout(r, 150));
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // 5) Rotate session and sign in
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: 'Session error' });
      req.session.auth = true;
      req.session.user = USERNAME;
      return res.json({ ok: true, username: USERNAME });
    });
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', csrfProtection, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/health', (req, res) => {
  res.json({
    ok: true,
    nodeEnv: process.env.NODE_ENV,
    tls: useTls,
    usernameConfigured: Boolean(USERNAME),
    hashPresent: Boolean(HASH),
    pepperLen: (PEPPER || '').length,
    sessionCookieSecure: sessionCookieSecure
  });
});

// Basic diagnostics (safe: no secrets)
console.log({
  NODE_ENV: process.env.NODE_ENV,
  TLS: useTls,
  USE_REDIS: useRedis,
  USE_SECRETS_MANAGER: useSecrets,
  USERNAME_configured: Boolean(USERNAME),
  HASH_present: Boolean(HASH),
  PEPPER_len: (PEPPER || '').length
});

app.post('/api/_debug_auth', csrfProtection, async (req, res) => {
    if (process.env.DEBUG_AUTH !== 'true') return res.status(404).end();
    const { username, pw_hash, password } = req.body || {};
    const u = typeof username === 'string' ? username.trim() : '';
    // reuse helpers from your file
    let clientPwHex = null;
    if (typeof password === 'string') clientPwHex = sha256Hex(password);
    else if (typeof pw_hash === 'string') {
      const h = pw_hash.trim().toLowerCase();
      clientPwHex = HEX64.test(h) ? h : null;
    }
    const verifierInputLen = clientPwHex ? (clientPwHex + PEPPER).length : 0;
    let ok = false;
    if (clientPwHex) {
      try { ok = await argon2.verify(HASH, clientPwHex + PEPPER); } catch {}
    }
    res.json({
      nodeEnv: process.env.NODE_ENV,
      tls: useTls,
      usernameConfigured: USERNAME.length > 0,
      userMatch: u === USERNAME,
      pwHexLen: clientPwHex?.length || 0,
      pwHexSample: clientPwHex ? clientPwHex.slice(0, 8) : null,
      pepperLen: (PEPPER || '').length,
      verifierInputLen,
      verifyOk: ok
    });
  });

const PORT = Number(process.env.PORT || 3000);
if (useTls) {
  const cert = pick('TLS_CERT_PATH');
  const key = pick('TLS_KEY_PATH');
  const server = https.createServer({
    cert: fs.readFileSync(cert),
    key: fs.readFileSync(key)
  }, app);
  server.listen(PORT, () => console.log(`Auth server (HTTPS) on :${PORT}`));
} else {
  const server = http.createServer(app);
  server.listen(PORT, () => console.log(`Auth server (HTTP) on :${PORT} — Secure cookies will NOT be set by browsers over HTTP`));
}