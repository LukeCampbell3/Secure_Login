This little vite/react js project securely logs in users by utilizing:

TLS (HTTPS)

  -Server can run with a real certificate (prod) or mkcert (dev).
  
  -Ensures credentials + cookies aren’t sniffable in transit.

Session cookie hardening

  -HttpOnly (inaccessible to JS), Secure (HTTPS only), SameSite=Lax (helps against CSRF), rolling 30-min expiry.
  
  -Session fixation protection: on successful login the server regenerates the session ID.

Server-side sessions

  -Uses express-session. In dev it’s MemoryStore; in prod you can switch on Redis for durability and multi-instance support.

CSRF protection

  -csurf middleware issues a per-session CSRF token and the client must send it as X-CSRF-Token on state-changing requests (/api/login, /api/logout).
  
  -Combined with SameSite cookies, this blocks cross-site form and fetch attacks.

Password handling
  
  -The browser never stores the password; it can send SHA-256(password) as pw_hash (or plaintext; the server hashes it before verify).
  
  -On the server, verification uses Argon2id (memory-hard KDF) against a stored Argon2 hash of (sha256(password) + PEPPER).
  
  -A secret pepper (in .env or a secrets manager) means a database/ENV leak alone isn’t enough to crack passwords quickly.

Rate limiting
  
  -/api/login is behind an IP-based rate limiter to slow brute force and credential-stuffing.

Security headers via Helmet
  
  -CSP (tight): blocks inline scripts/frames/objects by default; only allows your own origin + HMR in dev.
  
  -frame-ancestors 'none' (prevents clickjacking/iframing).
  
  -HSTS (under TLS; Helmet enables sensible defaults).
  
  -Other standard hardening headers turned on.

Minimal attack surface

  -API only; no server-rendered HTML.
  
  -Uniform error messages (“Invalid credentials”) to avoid username enumeration.
  
  -Inputs are normalized/validated (trim, 64-hex for pw_hash) to avoid silly mismatches.


Operational safeguards

  -Logout endpoint destroys the session.
  
  -Compression enabled; proxy trust set (so secure cookies behave correctly behind a reverse proxy).
