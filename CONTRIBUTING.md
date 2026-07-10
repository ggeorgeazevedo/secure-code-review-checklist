# Contributing

Thanks for helping make secure code review easier for everyone! 🙌

## How to add a checklist item

Open a PR that adds or improves an item. Every item should have:

1. **A title** mapped to the relevant OWASP category (e.g. `A05:2025 Injection` or `LLM05`).
2. **A short rationale** — one or two lines on why it matters and what to look for in a diff.
3. **A ❌ vulnerable example** — minimal, realistic, clearly insecure.
4. **A ✅ fixed example** — the same scenario done safely.

## Guidelines

- Keep snippets short and focused on the single issue being shown.
- Vulnerable examples are for teaching only — add a comment marking why they're unsafe.
- Prefer framework-idiomatic fixes over hand-rolled ones.
- New language file? Mirror the structure of the existing ones in `checklists/`.

## Adding a new language

Create `checklists/<language>.md`, follow the existing format, and link it from the
table in `README.md`.
