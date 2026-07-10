<div align="center">

# 🔐 Secure Code Review Checklist

**A practical, example-driven checklist for reviewing code securely — mapped to the [OWASP Top 10:2025](https://owasp.org/Top10/2025/) and the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/).**

**120+ vulnerable × fixed examples** across 5 languages and the full AI/LLM risk set — so a reviewer knows exactly what to look for and how to fix it.

![Maintenance](https://img.shields.io/badge/maintained-yes-3fb950?style=flat-square)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-8a63d2?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)

![OWASP Top 10:2025](https://img.shields.io/badge/OWASP-Top_10:2025-000000?style=flat-square&logo=owasp)
![OWASP LLM Top 10](https://img.shields.io/badge/OWASP-LLM_Top_10-8a63d2?style=flat-square&logo=owasp)
![Languages](https://img.shields.io/badge/languages-Python_·_JS_·_C%23_·_Java_·_Go-4b91f1?style=flat-square)

</div>

---

## 📖 What this is

Code review is one of the cheapest, highest-leverage security controls in the SSDLC — but only if the reviewer knows what to look for. This repository is a **field guide for secure code review**: a set of checklists you can run through during a pull-request review, organized by risk category and by language, each backed by real vulnerable-vs-fixed snippets.

It's built for **AppSec engineers, security champions, and developers** who want to shift security left without slowing delivery down.

## 🧭 How to use it

1. **During a PR review**, open the checklist for the language you're reviewing plus the [general checklist](checklists/general.md).
2. For AI/LLM-powered features, also run the [OWASP Top 10 for LLM checklist](ai-llm/owasp-llm-top-10.md).
3. Treat each ❌/✅ pair as a pattern: if the diff looks like the ❌ example, request the ✅ fix.
4. New to running reviews? Follow the [reviewer guide](docs/reviewer-guide.md) for a step-by-step process and severity model.
5. Adopt the [PR template](.github/PULL_REQUEST_TEMPLATE.md) so every pull request ships with a security self-review.

## 📚 Contents

| Section | Focus |
|---|---|
| [General checklist](checklists/general.md) | Language-agnostic review items mapped to OWASP Top 10:2025 |
| [Python](checklists/python.md) | Vulnerable × fixed patterns in Python |
| [JavaScript / Node.js](checklists/javascript.md) | Vulnerable × fixed patterns in JS/TS |
| [C# / .NET](checklists/csharp.md) | Vulnerable × fixed patterns in C# |
| [Java](checklists/java.md) | Vulnerable × fixed patterns in Java / Spring |
| [Go](checklists/go.md) | Vulnerable × fixed patterns in Go |
| [AI / LLM](ai-llm/owasp-llm-top-10.md) | Reviewing LLM-powered apps against the OWASP Top 10 for LLM 2025 |
| [Reviewer guide](docs/reviewer-guide.md) | How to run a secure review, step by step + severity model |
| [Resources](resources.md) | OWASP material, hands-on labs, channels & courses |
| [PR template](.github/PULL_REQUEST_TEMPLATE.md) | Drop-in security-aware pull-request template |

## 🗺️ OWASP Top 10:2025 — quick reference

| Code | Category |
|---|---|
| A01:2025 | Broken Access Control |
| A02:2025 | Security Misconfiguration |
| A03:2025 | Software Supply Chain Failures |
| A04:2025 | Cryptographic Failures |
| A05:2025 | Injection |
| A06:2025 | Insecure Design |
| A07:2025 | Authentication Failures |
| A08:2025 | Software or Data Integrity Failures |
| A09:2025 | Security Logging and Alerting Failures |
| A10:2025 | Mishandling of Exceptional Conditions |

## 🤖 OWASP Top 10 for LLM Applications 2025 — quick reference

| Code | Category |
|---|---|
| LLM01 | Prompt Injection |
| LLM02 | Sensitive Information Disclosure |
| LLM03 | Supply Chain |
| LLM04 | Data and Model Poisoning |
| LLM05 | Improper Output Handling |
| LLM06 | Excessive Agency |
| LLM07 | System Prompt Leakage |
| LLM08 | Vector and Embedding Weaknesses |
| LLM09 | Misinformation |
| LLM10 | Unbounded Consumption |

## 🔗 Related

- [trilha-devsecops-azure](https://github.com/ggeorgeazevedo/trilha-devsecops-azure) — a free, hands-on DevSecOps-on-Azure learning track by the same author.
- More references, labs, and courses in [resources.md](resources.md).

## 🤝 Contributing

Found a missing pattern or a better fix? PRs are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Each new item should include a short rationale, a ❌ vulnerable example, and a ✅ fixed example.

## ⚠️ Disclaimer

The vulnerable snippets in this repository are **intentionally insecure** and exist only to illustrate what to avoid. Never copy them into production. Examples are simplified for teaching; always adapt fixes to your framework and threat model.

## 📄 License

Released under the [MIT License](LICENSE).

---

<div align="center">
<sub>Maintained by <a href="https://github.com/ggeorgeazevedo">George Azevedo</a> — building security into every layer. 🔐</sub>
</div>
