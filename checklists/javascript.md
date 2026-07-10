# 🟨 JavaScript / Node.js — Secure Code Review

A rich set of vulnerable × fixed patterns for JS/TS and Node.js (Express, Nest, front-end). Mapped to the [OWASP Top 10:2025](https://owasp.org/Top10/2025/).

**Jump to:** [Injection](#injection) · [XSS](#cross-site-scripting-xss) · [Deserialization & prototypes](#deserialization--prototype-pollution) · [Crypto & secrets](#cryptography--secrets) · [Access control](#access-control) · [SSRF & requests](#ssrf--outbound-requests) · [Auth & sessions](#authentication--sessions) · [Resources & errors](#resources--errors) · [Mini-case](#-mini-case-express-route-before--after)

---

## Injection

### SQL injection · `A05`

**❌ Vulnerable**:

```js
const q = `SELECT * FROM users WHERE email = '${email}'`;   // template string
await db.query("SELECT * FROM users WHERE email = '" + email + "'");  // concat
```

**✅ Fixed** — parameterized:

```js
await db.query("SELECT * FROM users WHERE email = $1", [email]);   // pg
await db.execute("SELECT * FROM users WHERE email = ?", [email]);  // mysql2
```

### NoSQL injection (MongoDB) · `A05`

**❌ Vulnerable** — raw object into the query:

```js
User.findOne({ user: req.body.user, pw: req.body.pw });
// { "pw": { "$ne": null } } → auth bypass
```

**✅ Fixed** — coerce types / cast to string:

```js
User.findOne({ user: String(req.body.user), pw: String(req.body.pw) });
```

### Command injection · `A05`

**❌ Vulnerable**:

```js
const { exec } = require("child_process");
exec(`convert ${filename} out.png`);       // filename="x; rm -rf /"
```

**✅ Fixed** — arg array, no shell:

```js
const { execFile } = require("child_process");
execFile("convert", [filename, "out.png"], { timeout: 5000 });
```

### Code injection — `eval` / `Function` · `A05`

**❌ Vulnerable**:

```js
const result = eval(req.query.expr);
const fn = new Function("return " + req.body.code);
```

**✅ Fixed** — parse explicitly; never eval user input:

```js
const result = JSON.parse(req.query.data);   // data only
```

---

## Cross-Site Scripting (XSS)

### DOM XSS · `A05`

**❌ Vulnerable**:

```js
element.innerHTML = userComment;                   // parses HTML
document.write(location.hash);
element.insertAdjacentHTML("beforeend", userInput);
```

**✅ Fixed** — text, not HTML; sanitize if HTML is required:

```js
element.textContent = userComment;
import DOMPurify from "dompurify";
element.innerHTML = DOMPurify.sanitize(userComment);
```

### React `dangerouslySetInnerHTML` · `A05`

**❌ Vulnerable**:

```jsx
<div dangerouslySetInnerHTML={{ __html: userComment }} />
```

**✅ Fixed** — render as text (JSX auto-escapes) or sanitize:

```jsx
<div>{userComment}</div>
// or: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userComment) }}
```

### `javascript:` / URL sinks · `A05`

**❌ Vulnerable**:

```jsx
<a href={userUrl}>link</a>                         // userUrl = "javascript:alert(1)"
```

**✅ Fixed** — allow only safe schemes:

```jsx
const safe = /^https?:\/\//.test(userUrl) ? userUrl : "#";
<a href={safe}>link</a>
```

---

## Deserialization & prototype pollution

### Prototype pollution · `A08`

**❌ Vulnerable** — deep-merge of untrusted input:

```js
function merge(t, s) {
  for (const k in s) {
    if (typeof s[k] === "object") merge(t[k] ??= {}, s[k]);
    else t[k] = s[k];                    // __proto__ pollutes Object.prototype
  }
}
```

**✅ Fixed** — block dangerous keys (or `Object.create(null)` / `Map`):

```js
const BLOCKED = new Set(["__proto__", "constructor", "prototype"]);
function merge(t, s) {
  for (const k of Object.keys(s)) {
    if (BLOCKED.has(k)) continue;
    if (s[k] && typeof s[k] === "object") merge(t[k] ??= {}, s[k]);
    else t[k] = s[k];
  }
}
```

### Unsafe deserialization libs · `A08`

**❌ Vulnerable**:

```js
const obj = require("node-serialize").unserialize(req.body);  // RCE
```

**✅ Fixed**:

```js
const obj = JSON.parse(req.body);       // data only
```

---

## Cryptography & secrets

### Hard-coded secrets · `A04`

**❌ Vulnerable**:

```js
const stripe = require("stripe")("sk_live_51H8...redacted");
```

**✅ Fixed**:

```js
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
```

> Ensure `.env` is git-ignored and secrets aren't inlined into client bundles.

### Weak password hashing · `A04`

**❌ Vulnerable**:

```js
const hash = crypto.createHash("md5").update(pw).digest("hex");
```

**✅ Fixed** — bcrypt/argon2:

```js
const bcrypt = require("bcrypt");
const hash = await bcrypt.hash(pw, 12);
const ok = await bcrypt.compare(pw, hash);
```

### Insecure randomness · `A04`

**❌ Vulnerable**:

```js
const token = Math.random().toString(36).slice(2);   // predictable
```

**✅ Fixed** — CSPRNG:

```js
const token = require("crypto").randomBytes(32).toString("hex");
```

### Timing-unsafe compare · `A07`

**❌ Vulnerable**:

```js
if (provided === expected) { /* ... */ }
```

**✅ Fixed**:

```js
const crypto = require("crypto");
const a = Buffer.from(provided), b = Buffer.from(expected);
if (a.length === b.length && crypto.timingSafeEqual(a, b)) { /* ... */ }
```

---

## Access control

### IDOR / missing authorization · `A01`

**❌ Vulnerable**:

```js
app.get("/api/orders/:id", async (req, res) => {
  res.json(await Order.findById(req.params.id));    // any user, any order
});
```

**✅ Fixed** — verify ownership:

```js
app.get("/api/orders/:id", requireAuth, async (req, res) => {
  const o = await Order.findById(req.params.id);
  if (!o || String(o.userId) !== req.user.id) return res.sendStatus(403);
  res.json(o);
});
```

### Path traversal · `A01`

**❌ Vulnerable**:

```js
res.sendFile(path.join(BASE, req.query.name));      // ../../etc/passwd
```

**✅ Fixed** — resolve and confine:

```js
const full = path.resolve(BASE, req.query.name);
if (!full.startsWith(path.resolve(BASE) + path.sep)) return res.sendStatus(400);
res.sendFile(full);
```

---

## SSRF & outbound requests

### SSRF · `A06`

**❌ Vulnerable**:

```js
const resp = await fetch(req.query.url);            // user controls destination
```

**✅ Fixed** — allowlist + block internal IPs:

```js
import { lookup } from "node:dns/promises";
import ipaddr from "ipaddr.js";
const ALLOWED = new Set(["api.partner.com"]);
async function safeFetch(raw) {
  const url = new URL(raw);
  if (!ALLOWED.has(url.hostname)) throw new Error("host not allowed");
  const { address } = await lookup(url.hostname);
  if (ipaddr.parse(address).range() !== "unicast") throw new Error("internal blocked");
  return fetch(url, { redirect: "manual", signal: AbortSignal.timeout(5000) });
}
```

### Open redirect · `A01`

**❌ Vulnerable**:

```js
res.redirect(req.query.next);           // next=https://evil.tld
```

**✅ Fixed** — relative paths only:

```js
const next = req.query.next || "/";
res.redirect(next.startsWith("/") && !next.startsWith("//") ? next : "/");
```

---

## Authentication & sessions

### JWT — unverified / `alg:none` · `A07`

**❌ Vulnerable**:

```js
const payload = jwt.decode(token);      // no signature check
```

**✅ Fixed** — verify with an explicit algorithm:

```js
const payload = jwt.verify(token, PUBLIC_KEY, { algorithms: ["RS256"] });
```

### Insecure cookies · `A07`

**❌ Vulnerable**:

```js
res.cookie("session", id);              // no flags
```

**✅ Fixed**:

```js
res.cookie("session", id, { httpOnly: true, secure: true, sameSite: "strict", maxAge: 3600_000 });
```

### Permissive CORS · `A02`

**❌ Vulnerable**:

```js
app.use(cors({ origin: "*", credentials: true }));   // any site + credentials
```

**✅ Fixed** — explicit allowlist:

```js
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
```

---

## Resources & errors

### ReDoS — catastrophic regex · `A10`

**❌ Vulnerable**:

```js
if (/^(\w+\s?)*$/.test(userInput)) { /* ... */ }   // hangs the event loop
```

**✅ Fixed** — bounded, linear pattern + length cap:

```js
if (userInput.length <= 256 && /^[\w ]+$/.test(userInput)) { /* ... */ }
```

### Swallowed security errors · `A09`/`A10`

**❌ Vulnerable**:

```js
try { await verifyWebhookSignature(req); } catch (e) { /* ignore */ }
processPayment(req.body);               // forged webhooks pass through
```

**✅ Fixed** — deny + log on failure:

```js
try { await verifyWebhookSignature(req); }
catch (e) { logger.warn("bad webhook sig", { err: e.message }); return res.sendStatus(400); }
processPayment(req.body);
```

### Missing security headers · `A02`

**❌ Vulnerable** — no CSP/HSTS/etc.

**✅ Fixed**:

```js
const helmet = require("helmet");
app.use(helmet());                      // sane defaults; tune CSP per app
```

---

## 🧪 Mini-case: Express route (before → after)

**❌ Vulnerable**:

```js
app.get("/files/:id", async (req, res) => {
  const doc = await Doc.findById(req.params.id);          // A01: IDOR
  const html = `<h1>${doc.title}</h1>`;                   // A05: XSS
  res.sendFile(path.join(BASE, req.query.name));          // A01: path traversal
  console.log("served", doc.id, "key", API_KEY);          // A09: secret in logs
});
```

**✅ Fixed**:

```js
app.get("/files/:id", requireAuth, async (req, res) => {
  const doc = await Doc.findById(req.params.id);
  if (!doc || String(doc.userId) !== req.user.id) return res.sendStatus(403);  // A01
  const full = path.resolve(BASE, req.query.name || "");
  if (!full.startsWith(path.resolve(BASE) + path.sep)) return res.sendStatus(400); // A01
  logger.info("served doc", { id: doc.id });              // A09: no secrets
  res.render("doc", { title: doc.title });                // A05: template auto-escapes
});
```

---

### 🔎 Node/JS review shortlist

- `eval`, `new Function`, `child_process.exec`, `innerHTML`, `dangerouslySetInnerHTML`, `node-serialize` → justify or reject.
- `jwt.decode` used for auth (must be `jwt.verify`); `cors({origin:"*", credentials:true})`.
- `Math.random()` for tokens/secrets → `crypto.randomBytes`; `===` on tokens → `timingSafeEqual`.
- `npm audit` clean; lockfile committed; `helmet()` on; body size limits set.

---

### 📚 References

- OWASP: [XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) · [DOM XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html) · [Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) · [Node.js Security](https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html) · [Content Security Policy](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) · [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- Tools: [npm audit](https://docs.npmjs.com/cli/commands/npm-audit) · [eslint-plugin-security](https://github.com/eslint-community/eslint-plugin-security) · [Semgrep](https://semgrep.dev/) · [DOMPurify](https://github.com/cure53/DOMPurify)
