# 🧭 General Secure Code Review Checklist

Language-agnostic review items, organized by the **[OWASP Top 10:2025](https://owasp.org/Top10/2025/)**. Use this alongside the language-specific checklist for the code you're reviewing.

> How to read this: each item is something to actively look for in the diff. If you can't answer "yes" to the check, request a change.

---

## A01:2025 — Broken Access Control

- [ ] Every sensitive endpoint/action performs an **authorization check server-side**, not just in the UI.
- [ ] Object references are validated against the **current user** (no IDOR — Insecure Direct Object Reference).
- [ ] Access decisions are **default-deny**; new routes are protected unless explicitly made public.
- [ ] No authorization logic relies on client-supplied roles/claims that aren't re-verified.

**Ask:** *"If I change the ID in this request to another user's, what stops me from reading/modifying their data?"*

---

## A02:2025 — Security Misconfiguration

- [ ] Debug modes, verbose errors, and stack traces are **off in production**.
- [ ] Default credentials, sample endpoints, and admin consoles are removed or locked down.
- [ ] Security headers are set (CSP, HSTS, `X-Content-Type-Options`, etc.) where applicable.
- [ ] CORS is not set to a wildcard for credentialed requests.

**Ask:** *"Does this config leak internals or widen the attack surface if deployed as-is?"*

---

## A03:2025 — Software Supply Chain Failures

- [ ] New dependencies are **pinned** (lockfile) and come from trusted sources.
- [ ] Dependencies are scanned (SCA) and free of known criticals; no abandoned/typosquatted packages.
- [ ] Build/CI steps don't execute untrusted scripts or pull unpinned artifacts.
- [ ] Integrity is verified (checksums/signatures) for downloaded binaries and base images.

**Ask:** *"Do I trust every new package and build step this change introduces?"*

---

## A04:2025 — Cryptographic Failures

- [ ] Sensitive data is encrypted **in transit (TLS)** and **at rest** where required.
- [ ] Passwords use a **slow, salted hash** (bcrypt/argon2/scrypt) — never MD5/SHA-1/plain.
- [ ] No hard-coded keys, secrets, or tokens in source; secrets come from a vault/secret manager.
- [ ] Modern algorithms and secure randomness (CSPRNG) are used; no ECB mode, no static IVs.

**Ask:** *"Is any secret or PII stored/transmitted in a way an attacker could read?"*

---

## A05:2025 — Injection

- [ ] All queries use **parameterized statements / prepared queries** — no string concatenation.
- [ ] OS commands avoid the shell; arguments are passed as arrays, never interpolated.
- [ ] User input reaching interpreters (SQL, NoSQL, LDAP, XPath, template engines) is validated/escaped.
- [ ] Output is context-aware **encoded** before rendering (see XSS in language checklists).

**Ask:** *"Can user input change the structure of a query, command, or template here?"*

---

## A06:2025 — Insecure Design

- [ ] The feature has a **threat model** appropriate to its risk; abuse cases are considered.
- [ ] Security controls (rate limits, quotas, workflow limits) exist by design, not bolted on.
- [ ] Trust boundaries are explicit; the design doesn't assume clients behave.

**Ask:** *"Is this insecure because of a bug, or because the design itself is missing a control?"*

---

## A07:2025 — Authentication Failures

- [ ] Login enforces rate limiting / lockout and protects against credential stuffing.
- [ ] Session tokens are random, rotated on privilege change, and invalidated on logout.
- [ ] MFA is available for sensitive accounts; password reset flows don't leak account existence.
- [ ] Cookies are `HttpOnly`, `Secure`, and `SameSite` where appropriate.

**Ask:** *"Could an attacker authenticate as someone else, or keep a session they shouldn't?"*

---

## A08:2025 — Software or Data Integrity Failures

- [ ] Untrusted data is **never deserialized** into arbitrary objects.
- [ ] Auto-update / plugin mechanisms verify signatures before executing code.
- [ ] CI/CD artifacts and IaC are integrity-checked; no unsigned code paths to production.

**Ask:** *"Could tampered data or an unsigned artifact end up executing here?"*

---

## A09:2025 — Security Logging and Alerting Failures

- [ ] Security-relevant events (auth, access denials, high-value actions) are **logged**.
- [ ] Logs **never contain secrets, passwords, tokens, or full PII**.
- [ ] Logs are tamper-resistant and actually feed alerting/monitoring.

**Ask:** *"If this were abused in production, would we see it and be able to investigate?"*

---

## A10:2025 — Mishandling of Exceptional Conditions

- [ ] Errors **fail closed** (deny) for security decisions, not open (allow).
- [ ] Exceptions are handled explicitly; no empty `catch` swallowing security failures.
- [ ] Error messages to users are generic; details go to logs, not the response body.
- [ ] Resource cleanup (files, connections, locks) happens on every path, including errors.

**Ask:** *"When something goes wrong here, does the system stay safe — or does it leak/allow?"*

---

## ✅ Reviewer's quick pass

Before approving, confirm:

1. **Input** — is every external input validated and treated as hostile?
2. **Output** — is everything encoded for its destination context?
3. **AuthN/AuthZ** — is the acting user verified and authorized for this exact action?
4. **Secrets** — nothing sensitive hard-coded, logged, or returned?
5. **Dependencies** — anything new trustworthy and pinned?
6. **Errors** — do failures deny rather than allow?
7. **AI/LLM** — if the code touches an LLM, did you run the [LLM checklist](../ai-llm/owasp-llm-top-10.md)?

---

## 📚 OWASP references per category

Go deeper on any category with the official OWASP guidance:

| Category | OWASP reference |
|---|---|
| A01 Broken Access Control | [Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) · [Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) |
| A02 Security Misconfiguration | [Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) |
| A03 Software Supply Chain Failures | [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/) · [CycloneDX (SBOM)](https://cyclonedx.org/) |
| A04 Cryptographic Failures | [Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) · [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) · [Secrets Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) |
| A05 Injection | [Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html) · [SQL Injection Prevention](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) · [XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) · [OS Command Injection](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) |
| A06 Insecure Design | [Threat Modeling](https://owasp.org/www-community/Threat_Modeling) · [OWASP Proactive Controls](https://owasp.org/www-project-proactive-controls/) |
| A07 Authentication Failures | [Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) · [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) |
| A08 Software or Data Integrity Failures | [Deserialization](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) · [Mass Assignment](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html) |
| A09 Security Logging and Alerting Failures | [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) |
| A10 Mishandling of Exceptional Conditions | [Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html) |

**Cross-cutting:** [OWASP Top 10:2025](https://owasp.org/Top10/2025/) · [ASVS](https://owasp.org/www-project-application-security-verification-standard/) · [WSTG](https://owasp.org/www-project-web-security-testing-guide/) · [Cheat Sheet Series](https://cheatsheetseries.owasp.org/) · [Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
