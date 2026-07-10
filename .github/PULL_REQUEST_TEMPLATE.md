<!--
  Security-aware PR template. Adapt freely for your own projects.
  Reviewers: pair this with the checklists in /checklists and /ai-llm.
-->

## What & why

<!-- Briefly: what does this change do, and why? Link the issue/ticket. -->

## Security self-review

Confirm the items relevant to this change (delete what doesn't apply):

- [ ] **Input** — all external input is validated and treated as untrusted
- [ ] **Injection** — queries/commands are parameterized; no string-built SQL/OS/templates (`A05`)
- [ ] **Output** — data is encoded for its destination context (HTML/SQL/shell) (`A05`)
- [ ] **AuthN/AuthZ** — the acting user is verified and authorized for this exact action; no IDOR (`A01`, `A07`)
- [ ] **Secrets** — nothing sensitive is hard-coded, logged, or returned in responses (`A04`, `A09`)
- [ ] **Crypto** — passwords use a slow salted KDF; strong algorithms and CSPRNG only (`A04`)
- [ ] **Dependencies** — new packages are pinned, trusted, and scanned (`A03`)
- [ ] **Errors** — failures fail closed (deny); no secrets/stack traces leaked to users (`A10`)
- [ ] **Logging** — security-relevant events are logged without sensitive data (`A09`)

### If this change touches an LLM / AI feature

- [ ] Untrusted content is separated from instructions; model output is treated as untrusted (`LLM01`, `LLM05`)
- [ ] Tools/permissions follow least privilege; high-impact actions gated (`LLM06`)
- [ ] RAG retrieval is scoped to the current tenant/user (`LLM08`)
- [ ] No secrets/PII in prompts; rate/token/loop limits in place (`LLM02`, `LLM07`, `LLM10`)

## Notes for the reviewer

<!-- Anything reviewers should pay special attention to, threat model notes, out-of-scope items. -->
