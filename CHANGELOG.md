# Changelog

All notable changes to defcod-engine are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [0.1.1] — 2026-07-26

Noise reduction release. A run across 54 public "vibe-coded" repositories
(apps built with Lovable / Bolt / Replit) showed that roughly a quarter of all
findings were false positives. This release fixes the three sources of that
noise, with regression tests on both sides of each fix: the noise must not be
reported, and a genuine leak of the same kind must still be caught.

### Fixed

- **Private keys (PEM) no longer trigger on a bare header.** The rule matched
  the single line `-----BEGIN PRIVATE KEY-----` even when it was a string
  literal in code that assembles a key from an environment variable — the most
  common shape by far in real projects. A finding now requires actual key
  material: at least 100 base64 characters of body after the header. Keys
  inlined in a JS string with escaped newlines are still detected, as are keys
  whose closing `-----END-----` line is missing. On a sample of 8 repositories
  containing PEM headers this cut `private_key` findings from 32 to 9, and an
  independent check confirmed all 9 contain real key material.

- **A committed `.env` is no longer always critical.** In 12 of the 15
  repositories that had committed a `.env`, everything inside was public by
  design (`VITE_SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SUPABASE_PUBLISHABLE_KEY`,
  `SUPABASE_PROJECT_ID`) — values every visitor's browser already receives.
  Severity now depends on the contents:
  - only public values → new finding type `env_file_public`, severity `info`,
    explaining that nothing is leaking but the habit is worth fixing;
  - anything sensitive (secret keys, passwords, `service_role`, payment tokens)
    → `env_file`, severity `critical`, as before.

  A browser-facing prefix does **not** make a value safe: `VITE_OPENAI_API_KEY`
  holding a real key stays critical (and is in fact the worst case, since it
  ships to the browser).

- **`hardcoded_secret` stopped reporting noise.** It now filters HTTP header
  names (`apiKeyHeader = "X-API-Key"`), placeholders, values that are really an
  environment-variable *name* (`secrets = "ANTHROPIC_API_KEY"`), variables
  marked as test data (`TEST_SECRET`, `testPassword`), known public test keys
  (Cloudflare Turnstile, Stripe/`*_test_*`, reCAPTCHA demo pair), values inside
  `*.example` / `*.sample` / `*.template` files, single dictionary words, and
  values below a minimum entropy. Genuinely weak but real passwords such as
  `password123` are deliberately still reported — that is a real hole, not
  noise. On a sample of 8 repositories this cut `hardcoded_secret` findings
  from 103 to 60.

### Added

- `env_file_public` finding type, with canned EN/RU explanations.
- Extensible filter lists exported from the package so they are easy to grow:
  `PUBLIC_ENV_NAMES`, `PUBLIC_ENV_PREFIXES`, `SENSITIVE_ENV_MARKERS`,
  `KNOWN_PUBLIC_TEST_VALUES`.
- Helpers exported for testing and reuse: `classifyEnvFile`, `isPublicEnvVar`,
  `isLikelySecretValue`, `isKnownPublicTestValue`, `isExampleFile`,
  `hasPrivateKeyBody`, `shannonEntropy`.
- `isAnonJwt` — recognises a Supabase anon key as public by design.
- 50 new test assertions (29 → 79 checks), including an end-to-end pair of
  in-memory archives: a leaky app that must produce findings, and a tidy app
  that must stay clean. The tidy app deliberately contains all three former
  noise patterns.

### Notes

- No public API was removed. `PRIVATE_KEY_RE`, `HARDCODED_SECRET_RE`,
  `envLineHasRealValue` and the rest are still exported unchanged.
- Consumers that switch exhaustively on `FindingType` need to handle the new
  `env_file_public` member.

## [0.1.0] — 2026-07-07

Initial release: in-memory secret-leak scanner engine.

- Rules for leaked provider keys (OpenAI, Anthropic, Stripe live, AWS, Google),
  Supabase `service_role` JWTs, private keys, committed `.env` files and
  hardcoded secrets.
- GitHub repository download and ZIP upload, both entirely in memory —
  nothing is written to disk and nothing is stored.
- Secret masking: findings never carry a full secret value.
- Canned EN/RU explanations for every finding type, so the engine works with no
  external API.
