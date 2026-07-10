# ☕ Java — Secure Code Review

A rich set of vulnerable × fixed patterns for Java / Spring. Mapped to the [OWASP Top 10:2025](https://owasp.org/Top10/2025/).

**Jump to:** [Injection](#injection) · [Deserialization & XXE](#deserialization--xxe) · [Crypto & secrets](#cryptography--secrets) · [Access control](#access-control) · [SSRF](#ssrf--outbound-requests) · [Auth](#authentication--sessions) · [Errors](#errors--configuration) · [Mini-case](#-mini-case-spring-controller-before--after)

---

## Injection

### SQL injection · `A05`

**❌ Vulnerable**:

```java
Statement st = conn.createStatement();
ResultSet rs = st.executeQuery("SELECT * FROM users WHERE email = '" + email + "'");
// JPA:
em.createQuery("FROM User WHERE email = '" + email + "'");
```

**✅ Fixed** — `PreparedStatement` / bound JPQL:

```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE email = ?");
ps.setString(1, email);
em.createQuery("FROM User WHERE email = :email").setParameter("email", email);
```

### Command injection · `A05`

**❌ Vulnerable**:

```java
Runtime.getRuntime().exec("ping " + host);
```

**✅ Fixed** — arg array, no shell:

```java
new ProcessBuilder("ping", "-c", "1", host).start();
```

### Expression Language / SpEL injection · `A05`

**❌ Vulnerable** — evaluating user input as SpEL:

```java
Expression exp = new SpelExpressionParser().parseExpression(userInput);   // RCE
exp.getValue();
```

**✅ Fixed** — never parse user input as an expression; if templating is needed, use a restricted context and a fixed template.

### Path traversal / Zip Slip · `A01`

**❌ Vulnerable** — zip entry name used directly:

```java
File out = new File(destDir, entry.getName());       // "../../etc/cron.d/x"
```

**✅ Fixed** — validate the canonical path stays under destDir:

```java
File out = new File(destDir, entry.getName());
if (!out.getCanonicalPath().startsWith(destDir.getCanonicalPath() + File.separator))
    throw new SecurityException("zip slip blocked");
```

---

## Deserialization & XXE

### Native deserialization · `A08`

**❌ Vulnerable**:

```java
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();           // gadget-chain RCE
```

**✅ Fixed** — avoid native serialization; fixed-type data format:

```java
MyDto dto = new ObjectMapper().readValue(json, MyDto.class);   // no polymorphic typing
```

> Never enable Jackson `activateDefaultTyping()` / `@JsonTypeInfo` on untrusted input.

### XXE — XML External Entity · `A05`

**❌ Vulnerable**:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
Document doc = dbf.newDocumentBuilder().parse(input);
```

**✅ Fixed** — disable DTDs / external entities:

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
Document doc = dbf.newDocumentBuilder().parse(input);
```

---

## Cryptography & secrets

### Weak password hashing · `A04`

**❌ Vulnerable**:

```java
String hash = DigestUtils.md5Hex(password);
```

**✅ Fixed** — BCrypt (Spring Security):

```java
PasswordEncoder enc = new BCryptPasswordEncoder();
String hash = enc.encode(password);
boolean ok = enc.matches(password, hash);
```

### Hard-coded secrets · `A04`

**❌ Vulnerable**:

```java
private static final String API_KEY = "sk_live_...redacted";
```

**✅ Fixed**:

```java
@Value("${api.key}")                     // env / Vault / config server
private String apiKey;
```

### Insecure randomness · `A04`

**❌ Vulnerable**:

```java
String token = Long.toString(new Random().nextLong());
```

**✅ Fixed** — `SecureRandom`:

```java
byte[] b = new byte[32];
new SecureRandom().nextBytes(b);
String token = HexFormat.of().formatHex(b);
```

---

## Access control

### Missing authorization · `A01`

**❌ Vulnerable**:

```java
@GetMapping("/admin/users")
public List<User> all() { return repo.findAll(); }   // anyone
```

**✅ Fixed** — method security:

```java
@PreAuthorize("hasRole('ADMIN')")
@GetMapping("/admin/users")
public List<User> all() { return repo.findAll(); }
```

### IDOR · `A01`

**❌ Vulnerable**:

```java
@GetMapping("/invoices/{id}")
public Invoice get(@PathVariable Long id) { return repo.findById(id).orElseThrow(); }
```

**✅ Fixed** — check ownership against the principal:

```java
@GetMapping("/invoices/{id}")
public Invoice get(@PathVariable Long id, @AuthenticationPrincipal UserDetails me) {
    Invoice inv = repo.findById(id).orElseThrow();
    if (!inv.getOwner().equals(me.getUsername())) throw new AccessDeniedException("nope");
    return inv;
}
```

---

## SSRF & outbound requests

### SSRF · `A06`

**❌ Vulnerable**:

```java
InputStream in = new URL(userSuppliedUrl).openStream();
```

**✅ Fixed** — allowlist host + reject private ranges:

```java
URI uri = URI.create(userSuppliedUrl);
if (!ALLOWED.contains(uri.getHost())) throw new SecurityException("host not allowed");
InetAddress addr = InetAddress.getByName(uri.getHost());
if (addr.isSiteLocalAddress() || addr.isLoopbackAddress() || addr.isLinkLocalAddress())
    throw new SecurityException("internal blocked");
```

### Open redirect · `A01`

**❌ Vulnerable**:

```java
return "redirect:" + request.getParameter("next");
```

**✅ Fixed** — allow only relative paths:

```java
String next = request.getParameter("next");
if (next == null || !next.startsWith("/") || next.startsWith("//")) next = "/";
return "redirect:" + next;
```

---

## Authentication & sessions

### CSRF disabled globally · `A01`

**❌ Vulnerable**:

```java
http.csrf(csrf -> csrf.disable());       // blanket disable on a session-cookie app
```

**✅ Fixed** — keep CSRF for browser flows (disable only for stateless token APIs, deliberately):

```java
http.csrf(Customizer.withDefaults());
```

### Verbose auth errors · `A07`

**❌ Vulnerable**:

```java
if (!userExists(u)) throw new RuntimeException("no such user");   // user enumeration
```

**✅ Fixed** — generic message for both cases:

```java
if (!authenticate(u, p)) throw new BadCredentialsException("invalid credentials");
```

---

## Errors & configuration

### Leaking stack traces · `A10`

**❌ Vulnerable**:

```java
} catch (Exception e) { return ResponseEntity.status(500).body(e.toString()); }
```

**✅ Fixed** — log internally, generic response:

```java
} catch (Exception e) {
    log.error("operation failed", e);
    return ResponseEntity.status(500).body("Unexpected error");
}
```

---

## 🧪 Mini-case: Spring controller (before → after)

**❌ Vulnerable**:

```java
@GetMapping("/report/{id}")
public String report(@PathVariable Long id) {
    Report r = em.createQuery("FROM Report WHERE id = " + id, Report.class)  // A05
                 .getSingleResult();
    log.info("served {} key {}", id, apiKey);                                // A09
    return "<h1>" + r.getTitle() + "</h1>";                                  // A05 XSS
}
```

**✅ Fixed**:

```java
@GetMapping("/report/{id}")
public String report(@PathVariable Long id, @AuthenticationPrincipal UserDetails me, Model model) {
    Report r = repo.findById(id).orElseThrow();                              // A05: no raw JPQL
    if (!r.getOwner().equals(me.getUsername())) throw new AccessDeniedException("nope"); // A01
    log.info("served {}", id);                                               // A09
    model.addAttribute("report", r);
    return "report";                                                          // A05: template escapes
}
```

---

### 🔎 Java review shortlist

- `readObject()`, `Runtime.exec` w/ strings, default XML parsers, `activateDefaultTyping`, SpEL on input → justify or reject.
- Spring: `@PreAuthorize`/method security present, CSRF not blindly disabled, actuator endpoints secured.
- Secrets via `@Value`/Vault, never in committed `application.properties`.
- `new Random()`/`Math.random()` for tokens → `SecureRandom`; Zip Slip guarded on extraction.

---

### 📚 References

- OWASP: [Cheat Sheet Series](https://cheatsheetseries.owasp.org/) · [XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) · [Deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) · [SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) · [Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- Tools: [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) · [find-sec-bugs](https://find-sec-bugs.github.io/) · [Semgrep](https://semgrep.dev/)
