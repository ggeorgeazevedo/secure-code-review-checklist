# 🐹 Go — Secure Code Review

A rich set of vulnerable × fixed patterns for Go. Mapped to the [OWASP Top 10:2025](https://owasp.org/Top10/2025/).

**Jump to:** [Injection](#injection) · [Crypto & secrets](#cryptography--secrets) · [Access control](#access-control) · [SSRF](#ssrf--outbound-requests) · [Auth](#authentication--sessions) · [Errors & concurrency](#errors--concurrency) · [Mini-case](#-mini-case-http-handler-before--after)

---

## Injection

### SQL injection · `A05`

**❌ Vulnerable**:

```go
q := fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", email)
rows, _ := db.Query(q)
```

**✅ Fixed** — placeholders:

```go
rows, err := db.Query("SELECT * FROM users WHERE email = $1", email)
```

### Command injection · `A05`

**❌ Vulnerable**:

```go
exec.Command("sh", "-c", "ping "+host).Run()
```

**✅ Fixed** — explicit args, no shell:

```go
exec.Command("ping", "-c", "1", host).Run()
```

### XSS — `text/template` for HTML · `A05`

**❌ Vulnerable**:

```go
t := template.Must(template.New("p").Parse("<div>{{.}}</div>"))   // text/template
t.Execute(w, template.HTML(userInput))                            // or bypass with HTML type
```

**✅ Fixed** — `html/template` auto-escapes; keep input as string:

```go
import "html/template"
t := template.Must(template.New("p").Parse("<div>{{.}}</div>"))
t.Execute(w, userInput)
```

---

## Cryptography & secrets

### Hard-coded secrets · `A04`

**❌ Vulnerable**:

```go
const apiKey = "sk_live_...redacted"
```

**✅ Fixed**:

```go
apiKey := os.Getenv("API_KEY")
if apiKey == "" { log.Fatal("API_KEY not set") }
```

### Weak hashing & randomness · `A04`

**❌ Vulnerable**:

```go
token := fmt.Sprintf("%d", rand.Int())          // math/rand → predictable
sum := md5.Sum([]byte(password))                // fast, unsalted
```

**✅ Fixed** — CSPRNG + bcrypt:

```go
b := make([]byte, 32); _, _ = crand.Read(b)     // crypto/rand
token := hex.EncodeToString(b)
hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
```

### Disabled TLS verification · `A04`

**❌ Vulnerable**:

```go
tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
```

**✅ Fixed** — verify certs (fix the chain, don't skip):

```go
tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
```

---

## Access control

### Path traversal · `A01`

**❌ Vulnerable**:

```go
http.ServeFile(w, r, filepath.Join(base, r.URL.Query().Get("name")))
```

**✅ Fixed** — clean and confine:

```go
name := filepath.Clean(r.URL.Query().Get("name"))
full := filepath.Join(base, name)
if !strings.HasPrefix(full, filepath.Clean(base)+string(os.PathSeparator)) {
    http.Error(w, "invalid path", http.StatusBadRequest); return
}
http.ServeFile(w, r, full)
```

### IDOR · `A01`

**❌ Vulnerable**:

```go
order := store.Get(r.URL.Query().Get("id"))     // any user's order
json.NewEncoder(w).Encode(order)
```

**✅ Fixed** — check ownership against the session user:

```go
order := store.Get(id)
if order == nil || order.UserID != currentUser(r).ID {
    http.Error(w, "forbidden", http.StatusForbidden); return
}
json.NewEncoder(w).Encode(order)
```

---

## SSRF & outbound requests

### SSRF · `A06`

**❌ Vulnerable**:

```go
resp, _ := http.Get(r.URL.Query().Get("url"))
```

**✅ Fixed** — allowlist host + block private IPs:

```go
u, _ := url.Parse(raw)
if !allowed[u.Hostname()] { http.Error(w, "host not allowed", 400); return }
ips, _ := net.LookupIP(u.Hostname())
for _, ip := range ips {
    if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
        http.Error(w, "internal blocked", 400); return
    }
}
resp, err := http.Get(raw)
```

### Open redirect · `A01`

**❌ Vulnerable**:

```go
http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
```

**✅ Fixed** — relative paths only:

```go
next := r.URL.Query().Get("next")
if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") { next = "/" }
http.Redirect(w, r, next, http.StatusFound)
```

---

## Authentication & sessions

### JWT — ignored parse error · `A07`

**❌ Vulnerable**:

```go
token, _ := jwt.Parse(raw, keyFunc)     // error ignored → invalid token trusted
claims := token.Claims
```

**✅ Fixed** — check error and validity, fail closed:

```go
token, err := jwt.Parse(raw, keyFunc)
if err != nil || !token.Valid {
    http.Error(w, "unauthorized", http.StatusUnauthorized); return
}
claims := token.Claims
```

### Timing-unsafe token compare · `A07`

**❌ Vulnerable**:

```go
if provided == expected { /* ... */ }
```

**✅ Fixed**:

```go
if subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1 { /* ... */ }
```

---

## Errors & concurrency

### Ignored security errors · `A10`

**❌ Vulnerable** — the `_` on an error hides a failure on a security path:

```go
valid, _ := verifySignature(payload, sig)   // error dropped
if valid { process(payload) }
```

**✅ Fixed** — handle every error, deny on failure:

```go
valid, err := verifySignature(payload, sig)
if err != nil || !valid {
    http.Error(w, "invalid signature", http.StatusBadRequest); return
}
process(payload)
```

### Race condition on shared state · `A10`

**❌ Vulnerable** — unsynchronized map (also a data race):

```go
balances[user] -= amount            // concurrent requests corrupt state
```

**✅ Fixed** — guard with a mutex (or use the DB atomically):

```go
mu.Lock(); balances[user] -= amount; mu.Unlock()
// better: do it in a single atomic SQL UPDATE with a balance check
```

---

## 🧪 Mini-case: HTTP handler (before → after)

**❌ Vulnerable**:

```go
func report(w http.ResponseWriter, r *http.Request) {
    id := r.URL.Query().Get("id")
    row := db.QueryRow("SELECT title FROM reports WHERE id = " + id)   // A05
    var title string; row.Scan(&title)
    log.Printf("served %s key %s", id, apiKey)                         // A09
    fmt.Fprintf(w, "<h1>%s</h1>", title)                              // A05 XSS
}
```

**✅ Fixed**:

```go
func report(w http.ResponseWriter, r *http.Request) {
    u := currentUser(r)
    if u == nil { http.Error(w, "unauthorized", 401); return }        // A01
    id := r.URL.Query().Get("id")
    var title string
    err := db.QueryRow(                                               // A05: parameterized
        "SELECT title FROM reports WHERE id = $1 AND owner_id = $2", id, u.ID).Scan(&title)
    if err != nil { http.Error(w, "not found", 404); return }         // A10
    log.Printf("served %s", id)                                       // A09
    tmpl.Execute(w, title)                                            // A05: html/template escapes
}
```

---

### 🔎 Go review shortlist

- `text/template` for HTML, `template.HTML(userInput)`, `exec.Command("sh","-c",...)`, `InsecureSkipVerify:true` → justify or reject.
- Every `_ =` swallowing an error on an auth/crypto/IO path → question it.
- `math/rand` for tokens/secrets → `crypto/rand`; `==` on tokens → `subtle.ConstantTimeCompare`.
- Run `go test -race`; deps checked with `govulncheck`; modules pinned in `go.sum`.

---

### 📚 References

- OWASP: [Go Secure Coding Practices](https://owasp.org/www-project-go-secure-coding-practices-guide/) · [SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) · [Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- Tools: [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) · [gosec](https://github.com/securego/gosec) · [Semgrep](https://semgrep.dev/)
