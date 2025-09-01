import { useEffect, useState } from "react";

async function sha256Hex(text) {
  const enc = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest("SHA-256", enc);
  const arr = Array.from(new Uint8Array(buf));
  return arr.map(b => b.toString(16).padStart(2, "0")).join("");
}

export default function App() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [msg, setMsg] = useState("");
  const [signedIn, setSignedIn] = useState(false);
  const [csrf, setCsrf] = useState("");

  // Fetch CSRF token at start and whenever needed
  async function getCsrf() {
    const r = await fetch("/api/csrf", { credentials: "include" });
    if (r.ok) {
      const { csrfToken } = await r.json();
      setCsrf(csrfToken);
    } else {
      setCsrf("");
    }
  }

  useEffect(() => { getCsrf(); }, []);

  const onSubmit = async (e) => {
    e.preventDefault();
    setMsg("");

    try {
      // 1) CSRF
      const csrfRes = await fetch("/api/csrf", { credentials: "include" });
      if (!csrfRes.ok) throw new Error("CSRF fetch failed");
      const { csrfToken } = await csrfRes.json();

      // 2) hash password (lowercase hex, 64 chars)
      const enc = new TextEncoder().encode(password);
      const digest = await crypto.subtle.digest("SHA-256", enc);
      const hex = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2,"0")).join("");

      // 3) POST /api/login with pw_hash
      const res = await fetch("/api/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken,
        },
        credentials: "include",
        body: JSON.stringify({ username: username.trim(), pw_hash: hex }),
      });

      if (!res.ok) {
        const e = await res.json().catch(() => ({}));
        throw new Error(e?.error || "Login failed");
      }

      const data = await res.json();
      setMsg(`You have signed in via credentials ${data.username} and ${password}.`);
      setSignedIn(true);
      setPassword("");
    } catch (err) {
      setSignedIn(false);
      setMsg(err.message || "Login error");
    }
  };


  const onLogout = async () => {
    if (!csrf) await getCsrf();
    await fetch("/api/logout", {
      method: "POST",
      headers: { "X-CSRF-Token": csrf },
      credentials: "include"
    });
    setSignedIn(false);
    setMsg("You have been signed out.");
  };

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-gray-50 p-6">
      <div className="w-full max-w-sm rounded-2xl shadow-md bg-white p-6">
        <h1 className="text-2xl font-semibold text-center mb-6">Secure React Login</h1>
        {!signedIn ? (
          <form onSubmit={onSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1" htmlFor="username">Username</label>
              <input id="username" type="text" value={username}
                     onChange={(e) => setUsername(e.target.value)}
                     className="w-full rounded-xl border px-3 py-2 outline-none focus:ring-2 focus:ring-indigo-500"
                     placeholder="Enter username" required />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1" htmlFor="password">Password</label>
              <input id="password" type="password" value={password}
                     onChange={(e) => setPassword(e.target.value)}
                     className="w-full rounded-xl border px-3 py-2 outline-none focus:ring-2 focus:ring-indigo-500"
                     placeholder="Enter password" required />
            </div>
            <button type="submit"
              className="w-full rounded-xl bg-indigo-600 text-white font-medium py-2 hover:opacity-90 active:opacity-80">
              Sign in
            </button>
            {msg && <p className="text-sm text-center text-gray-700 mt-2">{msg}</p>}
          </form>
        ) : (
          <div className="space-y-4 text-center">
            <p className="text-lg">{msg}</p>
            <button onClick={onLogout} className="rounded-xl bg-gray-200 px-4 py-2 hover:bg-gray-300">Sign out</button>
          </div>
        )}
      </div>
    </div>
  );
}