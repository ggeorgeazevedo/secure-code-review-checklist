# 🟦 C# / .NET — Secure Code Review

A rich set of vulnerable × fixed patterns for C# / ASP.NET Core. Mapped to the [OWASP Top 10:2025](https://owasp.org/Top10/2025/).

**Jump to:** [Injection](#injection) · [Deserialization](#deserialization--integrity) · [Crypto & secrets](#cryptography--secrets) · [Access control](#access-control) · [SSRF](#ssrf--outbound-requests) · [Auth](#authentication--sessions) · [Errors](#errors--configuration) · [Mini-case](#-mini-case-controller-before--after)

---

## Injection

### SQL injection · `A05`

**❌ Vulnerable**:

```csharp
var sql = $"SELECT * FROM Users WHERE Email = '{email}'";
var cmd = new SqlCommand(sql, conn);
// EF Core:
db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Email = '{email}'");
```

**✅ Fixed** — parameters / interpolated-safe API / LINQ:

```csharp
var cmd = new SqlCommand("SELECT * FROM Users WHERE Email = @email", conn);
cmd.Parameters.AddWithValue("@email", email);
db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Email = {email}");  // parameterized
db.Users.Where(u => u.Email == email);                                       // best
```

### Command injection · `A05`

**❌ Vulnerable**:

```csharp
Process.Start("cmd.exe", "/c ping " + host);
```

**✅ Fixed** — args, no shell:

```csharp
var psi = new ProcessStartInfo("ping") { UseShellExecute = false };
psi.ArgumentList.Add("-n"); psi.ArgumentList.Add("1"); psi.ArgumentList.Add(host);
Process.Start(psi);
```

### LDAP injection · `A05`

**❌ Vulnerable**:

```csharp
var filter = $"(uid={username})";       // username = "*)(uid=*"
```

**✅ Fixed** — encode the filter value:

```csharp
var filter = $"(uid={LdapEncoder.FilterEncode(username)})";
```

### XXE · `A05`

**❌ Vulnerable**:

```csharp
var doc = new XmlDocument();
doc.LoadXml(userXml);                    // DTD processing on by default in older configs
```

**✅ Fixed** — disable DTD/external resolvers:

```csharp
var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
var doc = new XmlDocument();
using var reader = XmlReader.Create(new StringReader(userXml), settings);
doc.Load(reader);
```

---

## Deserialization & integrity

### Insecure deserialization · `A08`

**❌ Vulnerable**:

```csharp
var obj = new BinaryFormatter().Deserialize(stream);        // RCE; obsolete & banned
JsonConvert.DeserializeObject(json, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All });
```

**✅ Fixed** — data-only serializer, fixed type:

```csharp
var obj = JsonSerializer.Deserialize<MyDto>(json);          // System.Text.Json
```

### Mass assignment / over-posting · `A08`

**❌ Vulnerable**:

```csharp
[HttpPost] public IActionResult Update(User user) { ... }   // attacker sets IsAdmin=true
```

**✅ Fixed** — bind to a DTO with allowed fields only:

```csharp
public record UserUpdateDto(string Name, string Email);
[HttpPost] public IActionResult Update(UserUpdateDto dto) {
    var u = _db.Users.Find(CurrentUserId);
    u.Name = dto.Name; u.Email = dto.Email;                 // IsAdmin never touched
    _db.SaveChanges(); return Ok();
}
```

---

## Cryptography & secrets

### Hard-coded secrets · `A04`

**❌ Vulnerable**:

```csharp
var conn = "Server=db;User Id=sa;Password=P@ssw0rd!;";
```

**✅ Fixed** — configuration / secret store:

```csharp
var conn = builder.Configuration.GetConnectionString("Db");  // user-secrets / Key Vault / env
```

### Weak password hashing · `A04`

**❌ Vulnerable**:

```csharp
var hash = Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(pw)));
```

**✅ Fixed** — Identity `PasswordHasher` (PBKDF2) or argon2/bcrypt:

```csharp
var hasher = new PasswordHasher<User>();
user.PasswordHash = hasher.HashPassword(user, pw);
var result = hasher.VerifyHashedPassword(user, user.PasswordHash, pw);
```

### Insecure randomness · `A04`

**❌ Vulnerable**:

```csharp
var token = new Random().Next().ToString();     // predictable
```

**✅ Fixed** — CSPRNG:

```csharp
var bytes = RandomNumberGenerator.GetBytes(32);
var token = Convert.ToHexString(bytes);
```

---

## Access control

### Missing authorization · `A01`

**❌ Vulnerable**:

```csharp
[HttpGet("admin/users")]
public IActionResult AllUsers() => Ok(_db.Users.ToList());  // anyone
```

**✅ Fixed** — require authentication + role:

```csharp
[Authorize(Roles = "Admin")]
[HttpGet("admin/users")]
public IActionResult AllUsers() => Ok(_db.Users.ToList());
```

### IDOR · `A01`

**❌ Vulnerable**:

```csharp
[HttpGet("invoices/{id}")]
public IActionResult Get(int id) => Ok(_db.Invoices.Find(id));   // any user
```

**✅ Fixed** — scope to the caller:

```csharp
[Authorize]
[HttpGet("invoices/{id}")]
public IActionResult Get(int id) {
    var uid = User.FindFirstValue(ClaimTypes.NameIdentifier);
    var inv = _db.Invoices.Find(id);
    if (inv is null || inv.OwnerId != uid) return Forbid();
    return Ok(inv);
}
```

### Path traversal · `A01`

**❌ Vulnerable**:

```csharp
var path = Path.Combine(BaseDir, req.Name);      // ..\..\ escapes BaseDir
return PhysicalFile(path, "application/octet-stream");
```

**✅ Fixed** — resolve and confine:

```csharp
var full = Path.GetFullPath(Path.Combine(BaseDir, req.Name));
if (!full.StartsWith(Path.GetFullPath(BaseDir) + Path.DirectorySeparatorChar))
    return BadRequest();
return PhysicalFile(full, "application/octet-stream");
```

---

## SSRF & outbound requests

### SSRF · `A06`

**❌ Vulnerable**:

```csharp
var data = await _http.GetStringAsync(userUrl);
```

**✅ Fixed** — allowlist + block private IPs:

```csharp
var uri = new Uri(userUrl);
if (!Allowed.Contains(uri.Host)) return BadRequest();
var ip = (await Dns.GetHostAddressesAsync(uri.Host)).First();
if (IsPrivate(ip)) return BadRequest();
var data = await _http.GetStringAsync(uri);
```

### Open redirect · `A01`

**❌ Vulnerable**:

```csharp
return Redirect(returnUrl);                      // external URL → phishing
```

**✅ Fixed** — only local URLs:

```csharp
if (!Url.IsLocalUrl(returnUrl)) returnUrl = "/";
return Redirect(returnUrl);
```

---

## Authentication & sessions

### XSS via `Html.Raw` · `A05`

**❌ Vulnerable**:

```csharp
@Html.Raw(Model.Comment)
```

**✅ Fixed** — let Razor encode:

```csharp
@Model.Comment
```

### Antiforgery disabled · `A01`

**❌ Vulnerable**:

```csharp
[IgnoreAntiforgeryToken]
[HttpPost] public IActionResult Transfer(...) { ... }
```

**✅ Fixed** — keep CSRF protection on state-changing actions:

```csharp
[ValidateAntiForgeryToken]
[HttpPost] public IActionResult Transfer(...) { ... }
```

---

## Errors & configuration

### Leaking details on error · `A10`

**❌ Vulnerable**:

```csharp
catch (Exception ex) { return StatusCode(500, ex.ToString()); }   // internals to client
```

**✅ Fixed** — log internally, generic response:

```csharp
catch (Exception ex) {
    _logger.LogError(ex, "Update failed for {UserId}", CurrentUserId);
    return Problem("An unexpected error occurred.");
}
```

---

## 🧪 Mini-case: controller (before → after)

**❌ Vulnerable**:

```csharp
[HttpGet("report/{id}")]
public IActionResult Report(int id) {
    var r = _db.Reports.FromSqlRaw($"SELECT * FROM Reports WHERE Id={id}").First();  // A05
    _logger.LogInformation($"served {id} key {_apiKey}");                             // A09
    return Content($"<h1>{r.Title}</h1>", "text/html");                               // A05 XSS
}
```

**✅ Fixed**:

```csharp
[Authorize]
[HttpGet("report/{id}")]
public IActionResult Report(int id) {
    var uid = User.FindFirstValue(ClaimTypes.NameIdentifier);
    var r = _db.Reports.FirstOrDefault(x => x.Id == id && x.OwnerId == uid);  // A01 + A05 (LINQ)
    if (r is null) return NotFound();                                          // A10
    _logger.LogInformation("served {Id}", id);                                 // A09
    return View(r);                                                            // A05: Razor encodes
}
```

---

### 🔎 .NET review shortlist

- `BinaryFormatter`, `Html.Raw`, `FromSqlRaw` + interpolation, `TypeNameHandling.All`, `new Random()` for tokens → justify or reject.
- `[Authorize]` on every non-public action; `[ValidateAntiForgeryToken]` on state-changing forms.
- Secrets via `IConfiguration`/Key Vault, never committed `appsettings.json`.
- Detailed errors off in production; `Url.IsLocalUrl` for redirects.

---

### 📚 References

- OWASP: [.NET Security](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html) · [SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) · [Deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) · [Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html) · [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- Tools: [Security Code Scan](https://security-code-scan.github.io/) · [dotnet list package --vulnerable](https://learn.microsoft.com/nuget/consume-packages/finding-and-choosing-packages) · [Semgrep](https://semgrep.dev/)
