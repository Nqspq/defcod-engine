# Changelog

All notable changes to defcod-engine are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [0.1.2] — 2026-07-30

Follow-up to the noise work in 0.1.1, driven by a second run across 54 public
vibe-coded repositories. Two remaining noise sources are gone, and — most
importantly — values that are public *by design* no longer show up as red
"critical". Flagging a browser token as critical is simply wrong, and a
technical reader spots it immediately.

### Fixed

- **`hardcoded_secret` no longer reports descriptive phrases.** Values made only
  of lowercase words joined by `_`, `-` or `.` (`user-provided-key`,
  `a_different_secret`) are descriptions of a setting, not secrets — real keys
  and passwords virtually always contain digits, capitals or symbols. The
  trade-off is deliberate and documented in the code: an all-lowercase
  passphrase is filtered too, but for this audience that is far rarer than a
  description string. Passphrases containing a digit are still reported.

- **`hardcoded_secret` no longer reports UI text.** Values containing letters
  outside the Latin range (Cyrillic, CJK, Arabic, …) are interface strings,
  caught only because the variable was named `passwordMismatch` or similar.
  Latin letters with diacritics (`é`, `ü`) are *not* treated as another script,
  so a password like `Café-Süd-92!` is still reported.

- **Values that are public by design are no longer "critical".** A Google Maps
  key, a payment provider's client token and a publishable key are sent to every
  visitor's browser — secrecy is not how they are protected. Two changes:
  - `isPublicEnvVar` now checks the variable *name* before the provider-key
    pattern, so `VITE_..._GOOGLE_MAPS_BROWSER_KEY` grades as public even though
    its value looks like any other `AIza…` key;
  - a Google key sitting in a browser-named variable is reported as the new
    `google_key_public` type at severity `info`, with the advice that actually
    applies — restrict the key by HTTP referrer and set a quota.

  Two guardrails are enforced and tested: a `service_role` JWT or a private key
  is **never** public regardless of the variable name, and the `KEY_RULES`
  provider patterns run independently of `.env` grading, so a real key of another
  provider hiding in a "public" variable is still reported as critical.

### Added

- `google_key_public` finding type, with canned EN/RU explanations focused on
  restricting the key rather than deleting it.
- `PUBLIC_ENV_SUFFIXES` — name suffixes that declare a value browser-public
  (`BROWSER_KEY`, `PUBLIC_KEY`, `PUBLIC_TOKEN`, `CLIENT_TOKEN`,
  `PUBLISHABLE_KEY`, `SITE_KEY`). Matching by suffix rather than enumerating
  every vendor; `CLIENT_SECRET` deliberately does not match.
- New public entries in `PUBLIC_ENV_NAMES`: Google Maps browser keys and
  payment client tokens (Braintree, PayPal, Lovable's payments connector).
- `isBrowserPublicName` and `assignmentNameAt` exported; variable names are now
  normalised to `UPPER_SNAKE_CASE`, so `mapsBrowserKey` in code and
  `VITE_MAPS_BROWSER_KEY` in `.env` are recognised the same way.
- 20 new test assertions (79 → 99 checks), including the guardrail cases above
  and the two new noise patterns added to the "tidy app" end-to-end archive.

### Measured effect

On a fresh sample of 54 public vibe-coded repositories, v0.1.1 → v0.1.2:

| | v0.1.1 | v0.1.2 |
|---|---|---|
| Findings total | 52 | 44 |
| Repositories with a critical finding | 4 | 2 |
| `hardcoded_secret` | 22 | 14 |
| `.env` graded critical | 4 | 1 |
| Google key graded critical | 2 | 1 |

Nothing genuine was lost: the 8 removed `hardcoded_secret` cards were all
descriptive phrases or UI strings, and an independent check (not using the
engine) confirmed that no `.env` graded public contains a real provider key or
`service_role`. Cards still needing a human look dropped from 16 to 8 — and all
8 are genuinely ambiguous short passwords, with zero clear noise remaining.

### Notes

- Consumers that switch exhaustively on `FindingType` need to handle the new
  `google_key_public` member.
- No public API was removed.

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
