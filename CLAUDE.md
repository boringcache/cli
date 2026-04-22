# CLAUDE

This repository's working rules live in `AGENTS.md`.

Before changing CLI code:

1. Read `AGENTS.md`.
2. Read `/Users/gaurav/boringcache/skills/categories/coding-principles/boringcache-engineering-guide/SKILL.md`.
3. For CLI/cache/proxy/release work, use `/Users/gaurav/.codex/skills/cli-expert/SKILL.md` as a Codex-facing pointer to the same CLI rules and comprehension map.
4. Update `docs/comprehension` before handoff when command surface, flags, env/config behavior, cache lifecycle, proxy/adapters, release workflows, module ownership, support reachability, or file coverage changes.

Write idiomatic Rust with the same clarity expected from good Ruby: clear ownership, small APIs, low ceremony, and explicit performance tradeoffs.

Do not duplicate shared policy here. If reusable guidance changes, update `/Users/gaurav/boringcache/skills`.
