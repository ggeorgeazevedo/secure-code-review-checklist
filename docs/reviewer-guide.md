# 🧑‍⚖️ Reviewer Guide — How to run a secure code review

A short, repeatable process for using this repository during a pull-request review. The goal is to catch the high-impact issues quickly, without turning every PR into a security audit.

---

## The mindset

Two ideas carry most of the value:

1. **Treat every external input as hostile** — user input, API responses, files, queue messages, and (for AI features) **model output** all count.
2. **Follow the data.** Trace untrusted input from where it enters to where it's used (a query, a command, the DOM, a file path, another service). Vulnerabilities live on that path.

---

## A 5-step pass

**1. Understand the change (2 min).**
Read the PR description and the diff. What's the feature? What data does it touch? Who can reach it? If there's no context, ask for it before reviewing.

**2. Map the trust boundaries.**
Where does untrusted data enter this change, and where does it cross into something dangerous (DB, OS, browser, file system, another service, an LLM)? Those crossings are your review targets.

**3. Run the relevant checklist.**
Open the [general checklist](../checklists/general.md) plus the language file for the code under review:
[Python](../checklists/python.md) · [JavaScript](../checklists/javascript.md) · [C#](../checklists/csharp.md) · [Java](../checklists/java.md) · [Go](../checklists/go.md).
If the change calls an LLM, also run the [AI/LLM checklist](../ai-llm/owasp-llm-top-10.md).
For each ❌ pattern that matches the diff, request the ✅ fix.

**4. Check the "boring" but critical basics.**
Secrets in the diff? Authorization on the new endpoint? Errors that fail open? A new dependency you don't recognize? These four catch a large share of real incidents.

**5. Write actionable comments.**
Point at the exact line, name the risk (link the checklist item / OWASP category), and show the safe alternative. "This concatenates user input into SQL (`A05`) — use a parameterized query, see [Python checklist](../checklists/python.md#sql-injection--a052025-injection)." beats "this looks insecure."

---

## Severity: what blocks a merge

| Severity | Examples | Action |
|---|---|---|
| 🔴 **Blocker** | Injection, auth bypass, secret in code, RCE via deserialization/output handling | Request changes — do not merge |
| 🟠 **Major** | Missing authorization check, weak crypto, SSRF, IDOR | Request changes; fix before release |
| 🟡 **Minor** | Missing rate limit, verbose errors, weak logging | Comment; fix soon / follow-up issue |
| 🔵 **Nit** | Hardening suggestions, defense-in-depth extras | Suggest; non-blocking |

---

## Tips that keep reviews healthy

- **Automate the repetitive checks.** Let SAST/SCA/secret-scanning catch the mechanical stuff so humans focus on logic and authorization — the things tools miss.
- **Review design, not just code.** Some issues are `A06 Insecure Design`: the code is "correct" but a control is missing by design. Flag those early.
- **Be specific and kind.** You're reviewing code, not the person. Concrete, linked feedback gets fixed faster and builds a security culture.
- **Right-size it.** A config tweak doesn't need the full pass; a new authentication flow does.

---

<sub>Part of the <a href="../README.md">Secure Code Review Checklist</a>.</sub>
