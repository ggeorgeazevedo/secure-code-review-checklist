# 🐍 Python — Secure Code Review

A rich set of vulnerable × fixed patterns for reviewing Python (Django, Flask, FastAPI, plain). Mapped to the [OWASP Top 10:2025](https://owasp.org/Top10/2025/).

> How to read this: each ❌ is something to catch in a diff; each ✅ is the fix to request. Many topics show **multiple variations** of the same bug — real code hides it in different places.

**Jump to:** [Injection](#injection) · [Deserialization & code exec](#deserialization--code-execution) · [Crypto & secrets](#cryptography--secrets) · [Access control](#access-control) · [SSRF & requests](#ssrf--outbound-requests) · [Web/XSS/templates](#web-xss--templates) · [Auth & sessions](#authentication--sessions) · [Files & resources](#files--resources) · [Errors & logging](#errors--logging) · [Mini-case](#-mini-case-flask-endpoint-before--after)

---

## Injection

### SQL injection — raw query · `A05`

**❌ Vulnerable** — string formatting:

```python
cur.execute("SELECT * FROM users WHERE id = '%s'" % user_id)     # %
cur.execute(f"SELECT * FROM users WHERE id = '{user_id}'")       # f-string
cur.execute("SELECT * FROM users WHERE id = '" + user_id + "'")  # concat
```

**✅ Fixed** — parameterized:

```python
cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### SQL injection — Django ORM escape hatches · `A05`

**❌ Vulnerable** — `.raw()` / `.extra()` with interpolation:

```python
User.objects.raw("SELECT * FROM users WHERE name = '%s'" % name)
User.objects.extra(where=["name = '%s'" % name])
```

**✅ Fixed** — pass params; prefer the ORM:

```python
User.objects.raw("SELECT * FROM users WHERE name = %s", [name])
User.objects.filter(name=name)          # best: no raw SQL at all
```

### SQL injection — SQLAlchemy `text()` · `A05`

**❌ Vulnerable**:

```python
db.execute(text(f"SELECT * FROM t WHERE email = '{email}'"))
```

**✅ Fixed** — bound parameters:

```python
db.execute(text("SELECT * FROM t WHERE email = :email"), {"email": email})
```

### NoSQL injection — MongoDB · `A05`

**❌ Vulnerable** — user dict merged into the query:

```python
db.users.find({"user": request.json["user"], "pw": request.json["pw"]})
# attacker sends {"pw": {"$ne": null}} → auth bypass
```

**✅ Fixed** — coerce to the expected type:

```python
user = str(request.json["user"]); pw = str(request.json["pw"])
db.users.find({"user": user, "pw": pw})
```

### OS command injection · `A05`

**❌ Vulnerable** — the shell parses attacker input:

```python
os.system("ping -c 1 " + host)
subprocess.run(f"nslookup {host}", shell=True)
subprocess.check_output("gzip " + path, shell=True)
```

**✅ Fixed** — no shell, argument list:

```python
subprocess.run(["ping", "-c", "1", host], check=True, timeout=5)  # shell=False default
```

### Server-Side Template Injection (SSTI) · `A05`

**❌ Vulnerable** — user input compiled as a template:

```python
from flask import render_template_string
render_template_string("Hi " + request.args["name"])   # {{7*7}} → RCE via Jinja
```

**✅ Fixed** — render a static template, pass data as context:

```python
render_template_string("Hi {{ name }}", name=request.args["name"])
```

### XXE — XML external entities · `A05`

**❌ Vulnerable** — default parser resolves entities:

```python
from lxml import etree
tree = etree.fromstring(xml_bytes)      # external entity / billion laughs
```

**✅ Fixed** — disable entity resolution:

```python
parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False)
tree = etree.fromstring(xml_bytes, parser)
# stdlib: prefer defusedxml.ElementTree
```

---

## Deserialization & code execution

### `pickle` on untrusted data · `A08`

**❌ Vulnerable**:

```python
obj = pickle.loads(request.data)        # arbitrary code execution
```

**✅ Fixed** — data-only format:

```python
obj = json.loads(request.data)
```

### `yaml.load` without a safe loader · `A08`

**❌ Vulnerable**:

```python
cfg = yaml.load(user_yaml)              # can instantiate arbitrary objects
```

**✅ Fixed**:

```python
cfg = yaml.safe_load(user_yaml)
```

### `eval` / `exec` on input · `A05`

**❌ Vulnerable**:

```python
result = eval(request.args["expr"])     # RCE
exec(user_supplied_code)
```

**✅ Fixed** — parse explicitly; never eval:

```python
import ast
result = ast.literal_eval(request.args["expr"])   # only literals, no code
```

---

## Cryptography & secrets

### Hard-coded secrets · `A04`

**❌ Vulnerable**:

```python
API_KEY = "sk_live_51H8...redacted"
DJANGO_SECRET_KEY = "hunter2"
```

**✅ Fixed** — environment / secret manager:

```python
API_KEY = os.environ["API_KEY"]
```

> Block the PR if a secret is in the diff — it's compromised the moment it's pushed. Rotate it.

### Weak password hashing · `A04`

**❌ Vulnerable**:

```python
pw_hash = hashlib.md5(password.encode()).hexdigest()
pw_hash = hashlib.sha256(password.encode()).hexdigest()   # fast, unsalted — still wrong
```

**✅ Fixed** — slow, salted KDF:

```python
import bcrypt
pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
ok = bcrypt.checkpw(password.encode(), pw_hash)
```

### Insecure randomness for security tokens · `A04`

**❌ Vulnerable**:

```python
token = "".join(random.choice(string.ascii_letters) for _ in range(32))
otp = random.randint(100000, 999999)
```

**✅ Fixed** — CSPRNG:

```python
import secrets
token = secrets.token_urlsafe(32)
otp = secrets.randbelow(900000) + 100000
```

### Weak symmetric crypto — ECB / static IV · `A04`

**❌ Vulnerable**:

```python
cipher = AES.new(key, AES.MODE_ECB)     # reveals patterns
cipher = AES.new(key, AES.MODE_CBC, iv=b"0000000000000000")  # static IV
```

**✅ Fixed** — authenticated mode with a random nonce:

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
nonce = os.urandom(12)
ct = AESGCM(key).encrypt(nonce, plaintext, associated_data)
```

### Disabled TLS verification · `A04`

**❌ Vulnerable**:

```python
requests.get(url, verify=False)         # MITM-able
```

**✅ Fixed**:

```python
requests.get(url, verify=True)          # default; fix the cert chain instead of disabling
```

---

## Access control

### IDOR — missing ownership check · `A01`

**❌ Vulnerable**:

```python
@app.get("/invoices/<int:invoice_id>")
def invoice(invoice_id):
    return db.get_invoice(invoice_id)   # any user reads any invoice
```

**✅ Fixed** — scope to the caller:

```python
@app.get("/invoices/<int:invoice_id>")
@login_required
def invoice(invoice_id):
    inv = db.get_invoice(invoice_id)
    if inv.owner_id != current_user.id:
        abort(403)
    return inv
```

### Missing authorization on an admin action · `A01`

**❌ Vulnerable**:

```python
@app.post("/admin/delete-user")
def delete_user():                      # no auth check at all
    db.delete(request.json["id"]); return "ok"
```

**✅ Fixed** — require role, default-deny:

```python
@app.post("/admin/delete-user")
@login_required
def delete_user():
    if not current_user.is_admin:
        abort(403)
    db.delete(request.json["id"]); return "ok"
```

### Path traversal · `A01`

**❌ Vulnerable**:

```python
path = os.path.join(UPLOAD_DIR, request.args["name"])   # ../../etc/passwd
return open(path).read()
```

**✅ Fixed** — resolve and confine:

```python
base = os.path.realpath(UPLOAD_DIR)
path = os.path.realpath(os.path.join(base, request.args["name"]))
if not path.startswith(base + os.sep):
    abort(400)
return open(path).read()
```

### Mass assignment — Django `fields = '__all__'` · `A08`

**❌ Vulnerable**:

```python
class UserForm(ModelForm):
    class Meta:
        model = User; fields = "__all__"   # user can set is_staff/is_superuser
```

**✅ Fixed** — allow-list fields:

```python
class UserForm(ModelForm):
    class Meta:
        model = User; fields = ["first_name", "last_name", "email"]
```

---

## SSRF & outbound requests

### SSRF — user-controlled URL · `A06`

**❌ Vulnerable**:

```python
r = requests.get(request.args["url"])   # → http://169.254.169.254/ (cloud metadata)
```

**✅ Fixed** — allowlist host + block internal ranges:

```python
import ipaddress, socket
from urllib.parse import urlparse

ALLOWED = {"api.partner.com"}

def safe_fetch(url):
    host = urlparse(url).hostname
    if host not in ALLOWED:
        raise ValueError("host not allowed")
    ip = ipaddress.ip_address(socket.gethostbyname(host))
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError("internal address blocked")
    return requests.get(url, timeout=5, allow_redirects=False)
```

### Open redirect · `A01`

**❌ Vulnerable**:

```python
return redirect(request.args["next"])   # next=https://evil.tld → phishing
```

**✅ Fixed** — only allow relative/known paths:

```python
from urllib.parse import urlparse
nxt = request.args.get("next", "/")
if urlparse(nxt).netloc:                 # has a host → external
    nxt = "/"
return redirect(nxt)
```

---

## Web, XSS & templates

### XSS — autoescaping bypassed · `A05`

**❌ Vulnerable**:

```python
from markupsafe import Markup
return Markup(f"<div>{comment}</div>")   # or Jinja: {{ comment | safe }}
# Django: mark_safe(comment)
```

**✅ Fixed** — let the template engine escape:

```python
return render_template("comment.html", comment=comment)   # Jinja auto-escapes {{ comment }}
```

### CSRF protection disabled · `A01`

**❌ Vulnerable**:

```python
@csrf_exempt                             # Django: state-changing view unprotected
def transfer(request): ...
```

**✅ Fixed** — keep CSRF on; use tokens for forms/AJAX:

```python
def transfer(request): ...              # CSRF middleware enforces the token
```

---

## Authentication & sessions

### JWT — unverified / `alg:none` · `A07`

**❌ Vulnerable**:

```python
payload = jwt.decode(token, options={"verify_signature": False})
```

**✅ Fixed** — verify with an explicit algorithm:

```python
payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
```

### Timing-unsafe secret comparison · `A07`

**❌ Vulnerable**:

```python
if provided_token == expected_token:    # early-exit leaks length/content via timing
    ...
```

**✅ Fixed** — constant-time compare:

```python
import hmac
if hmac.compare_digest(provided_token, expected_token):
    ...
```

---

## Files & resources

### Insecure file upload · `A08`

**❌ Vulnerable** — trusts the client filename/type:

```python
f = request.files["file"]
f.save(os.path.join(UPLOAD_DIR, f.filename))   # ../, .php, executable
```

**✅ Fixed** — sanitize name, validate type, store outside webroot:

```python
from werkzeug.utils import secure_filename
name = secure_filename(f.filename)
if not name.lower().endswith((".png", ".jpg", ".pdf")):
    abort(400)
f.save(os.path.join(SAFE_UPLOAD_DIR, name))    # served via a controlled handler, not statically
```

### Insecure temp file / race (TOCTOU) · `A10`

**❌ Vulnerable**:

```python
name = "/tmp/report.tmp"
if not os.path.exists(name):             # gap between check and use
    open(name, "w").write(data)
```

**✅ Fixed** — atomic creation:

```python
import tempfile
fd, name = tempfile.mkstemp()
with os.fdopen(fd, "w") as fh:
    fh.write(data)
```

### ReDoS — catastrophic regex · `A10`

**❌ Vulnerable**:

```python
re.match(r"^(\w+\s?)*$", user_input)     # pathological input hangs the worker
```

**✅ Fixed** — bound length and simplify:

```python
if len(user_input) <= 256 and re.match(r"^[\w ]+$", user_input):
    ...
```

---

## Errors & logging

### Failing open on errors · `A10`

**❌ Vulnerable**:

```python
def is_admin(user):
    try:
        return check_admin_service(user)
    except Exception:
        return True                      # service down → everyone is admin
```

**✅ Fixed** — fail closed:

```python
def is_admin(user):
    try:
        return check_admin_service(user)
    except Exception:
        log.exception("admin check failed")
        return False
```

### Logging secrets / PII · `A09`

**❌ Vulnerable**:

```python
log.info("login ok user=%s password=%s token=%s", user, password, token)
```

**✅ Fixed** — never log credentials:

```python
log.info("login ok user=%s", user)      # no secrets, minimal PII
```

---

## 🧪 Mini-case: Flask endpoint (before → after)

A realistic handler that packs several review findings at once.

**❌ Vulnerable**:

```python
@app.route("/report")
def report():
    uid = request.args["uid"]
    # A01: no auth, IDOR on uid   |  A05: SQL injection
    row = db.execute(f"SELECT * FROM reports WHERE user_id = {uid}").fetchone()
    # A05: SSTI / XSS via template string
    html = render_template_string("<h1>Report for " + row["name"] + "</h1>")
    # A09: secret in logs
    app.logger.info(f"served report uid={uid} apikey={API_KEY}")
    return html
```

**✅ Fixed**:

```python
@app.route("/report")
@login_required
def report():
    uid = request.args.get("uid", type=int)              # validated type
    if uid != current_user.id and not current_user.is_admin:
        abort(403)                                        # A01: authorized
    row = db.execute(                                     # A05: parameterized
        "SELECT name FROM reports WHERE user_id = %s", (uid,)
    ).fetchone()
    if row is None:
        abort(404)                                        # A10: fail closed
    app.logger.info("served report uid=%s", uid)          # A09: no secrets
    return render_template("report.html", name=row["name"])  # A05: auto-escaped
```

---

### 🔎 Python review shortlist

- `eval`, `exec`, `pickle.loads`, `yaml.load`, `subprocess(..., shell=True)`, `render_template_string(<input>)`, `verify=False` → justify or reject.
- Any secret literal in the diff → reject and rotate.
- Django/Flask: `DEBUG=False`, CSRF enabled, `SECRET_KEY`/keys from env, `ALLOWED_HOSTS` set.
- ORM escape hatches (`.raw()`, `.extra()`, `text()`) → confirm parameterization.
- `==` comparing tokens/HMACs → require `hmac.compare_digest`.

---

### 📚 References

- OWASP: [SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) · [OS Command Injection](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) · [Deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) · [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) · [SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) · [XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) · [Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- Tools: [Bandit](https://bandit.readthedocs.io/) (SAST) · [pip-audit](https://pypi.org/project/pip-audit/) / [Safety](https://pyup.io/safety/) (SCA) · [Semgrep](https://semgrep.dev/) · [defusedxml](https://pypi.org/project/defusedxml/)
