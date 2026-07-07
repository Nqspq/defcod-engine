# defcod-engine

The scanner engine behind [DEFCOD](https://defcod.vercel.app) — a tool that checks
apps built with AI/no-code tools (Lovable, Bolt, Replit, …) for the most damaging
beginner mistakes: leaked API keys, committed `.env` files, a Supabase
`service_role` key shipped to the browser.

This repository is published so that anyone can verify two claims we make on the
site: **what exactly we scan for** and **that scanned code is never stored**.

## What it is (and what it is not)

A small TypeScript library, no framework attached:

- **Input** — one of:
  - a public GitHub repository URL,
  - a ZIP archive as bytes,
  - a plain list of `{ path, content }` files.
- **Output** — a list of findings: type, severity, file, line numbers, a **masked**
  secret, and a plain-language explanation (English and Russian) with concrete
  fix steps.

It is deliberately simple: regex- and heuristic-based detection of a short list
of high-impact leaks (see [Checks](#checks)). It is **not** a replacement for
mature scanners like gitleaks, TruffleHog or Semgrep — if you are comfortable
running those, run those. This engine exists for people who are not, and it
targets the mistakes that actually burn non-programmers who ship AI-generated
apps.

## How a scan works, step by step

Using the GitHub mode as the example (`src/github.ts` → `src/engine.ts`):

1. **Download.** The engine fetches the repository tarball from
   `codeload.github.com` into a memory buffer, counting bytes as they stream in
   and aborting past ~30 MB (`downloadArchive` in [`src/github.ts`](src/github.ts)).
2. **Unpack — in memory.** The tarball is gunzipped with a decompression size cap
   (anti zip-bomb) and the tar format is parsed directly from the buffer
   (`untar` in [`src/github.ts`](src/github.ts)). Binary files, oversized files
   and oversized archives are skipped. Nothing is written to disk at any point.
3. **Scan.** Every text file is matched against the rules in
   [`src/rules.ts`](src/rules.ts) by [`src/engine.ts`](src/engine.ts).
   Placeholder values (`your_api_key`, `sk-xxxx`, …) are ignored.
4. **Mask immediately.** The moment a secret matches, only a masked form
   (first few characters + `****`) is kept in the finding
   (`maskSecret` in [`src/rules.ts`](src/rules.ts)). The full secret value never
   leaves the scanning function — it is not part of the engine's output type.
5. **Group and explain.** Findings of the same type in the same file collapse
   into one finding with a list of line numbers (`groupFindings` in
   [`src/engine.ts`](src/engine.ts)); each finding gets canned EN/RU
   explanations and fix steps ([`src/explain.ts`](src/explain.ts)).
6. **Return and forget.** The findings array is returned; the buffers holding
   the downloaded code go out of scope and are garbage-collected. There is no
   step 7.

The ZIP mode ([`src/zip.ts`](src/zip.ts)) is the same idea: `unzipSync` from
[fflate](https://github.com/101arrowz/fflate) unpacks the uploaded archive in
memory, with per-file and total size caps checked against the ZIP headers
*before* decompression.

## Why "nothing is stored" is verifiable

Claims like this are usually a privacy-policy sentence you have to take on
faith. Here you can check the code instead:

- **No filesystem access.** None of the engine modules import `fs` or write
  anywhere. Verify: `grep -rn '"fs"\|writeFile\|createWriteStream' src/` — no matches.
- **No network calls except the one download.** The only `fetch` in the engine
  is the GitHub tarball download in [`src/github.ts`](src/github.ts). The engine
  never sends the scanned code anywhere.
- **No logging of contents.** The engine does not log file contents or secrets.
  The only logging is an opt-in debug counter of file *names* behind the
  `SCAN_DEBUG` env var in [`src/engine.ts`](src/engine.ts), off by default.
- **Secrets are masked at the source.** The `Finding` type in
  [`src/rules.ts`](src/rules.ts) has no field for the raw secret — only
  `masked`. There is nothing downstream code *could* accidentally store.

One honest caveat: reading this code proves what the engine does, not what any
particular server runs. If that distinction matters to you, don't take our
word for it — run the engine yourself (see below) or scan with the established
tools it is inspired by.

## Checks

| Check | Severity |
| --- | --- |
| OpenAI API keys (`sk-…`, `sk-proj-…`) | critical |
| Anthropic API keys (`sk-ant-…`) | critical |
| Live Stripe secret keys (`sk_live_…`, `rk_live_…`) | critical |
| AWS access key IDs (`AKIA…`, `ASIA…`) | critical |
| Google API keys (`AIza…`) | critical |
| Supabase `service_role` JWT — flagged extra if found in client code | critical |
| Private key files/blocks (PEM headers) | critical |
| Committed `.env` files with real values | critical |
| Hardcoded passwords/secrets/tokens in code | warning |

Limits: archives up to ~30 MB compressed / 120 MB unpacked, files up to 512 KB,
4000 files per scan. Bigger inputs are rejected with a typed error, not
truncated silently.

## Usage

```ts
import { fetchRepoFiles, filesFromZip, scanFiles, cannedExplanations } from "defcod-engine";

// GitHub mode
const { files } = await fetchRepoFiles("https://github.com/owner/repo");
const { findings } = scanFiles(files);
const explained = cannedExplanations(findings); // + EN/RU texts and fix steps

// ZIP mode: filesFromZip(bytes) → same scanFiles() call
// Raw mode: scanFiles([{ path: "src/app.js", content: "..." }])
```

Errors that are the user's to fix (bad URL, private repo, archive too big,
not-a-zip, …) are thrown as `ScanUserError` with a typed `code`, so an app can
map them to friendly messages.

## Running the tests

```bash
npm install
npm test
```

The test suite (`scripts/test-scanner.ts`) builds a deliberately vulnerable
fake project **in memory at runtime** and asserts that every planted leak is
found, clean files produce no false positives, secrets are masked in the
output, grouping works, and both archive modes behave. The fake keys are
assembled from string fragments at runtime on purpose: this way neither
gitleaks nor this engine itself reports anything when pointed at this
repository — try it: `gitleaks git .` should find 0 leaks.

## License

[MIT](LICENSE).

---

defcod-engine powers **DEFCOD** — a one-minute security check for AI-built
apps, in plain language: https://defcod.vercel.app
