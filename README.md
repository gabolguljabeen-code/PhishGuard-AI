# PhishGuard AI

**Intelligent Phishing Email & Fake Website Detection System** is a BSCS Information Security educational project. It provides transparent, rule-based analysis of email text, URLs, and pasted HTML snippets. Analysis runs in the browser; Turso stores only anonymous scan type, score, classification, and timestamp for history.

> **Educational tool, not a security verdict.** A low score does not prove content is safe. Rules can miss threats and can flag legitimate content. Verify requests with the organization through a known channel.

## Features

- Dashboard with saved scan counts and history scoped to a random browser workspace cookie.
- Email inspection for urgency, account verification, credentials/OTPs, links, attachment language, unusual sender addresses, and display-name mismatches when sender fields are supplied.
- Static URL parsing for HTTP, length, IP hosts, Unicode/punycode, subdomains, shorteners, selected unusual TLDs, embedded user information, encoded delimiters, and common brand lookalikes.
- HTML snippet awareness checks for password forms, mismatched form hosts when an optional `<!-- page-host: example.org -->` comment is supplied, recognizable brand cues, and external scripts. Snippets are never inserted into the DOM or executed.
- Weighted indicators with an explanation, contribution points, a 0–100 total, and next steps.
- Optional Turso-backed history retains only scan type, score, classification, and timestamp. Email text, HTML, URL strings, hostnames, sender data, extracted links, and rule explanations are not sent to the server. History is scoped to a random HttpOnly browser cookie, capped at 30 scans, and expires after 30 days. Clearing history deletes the rows for that browser workspace.
- Security learning cards, quiz, and educational one-click examples.
- Responsive dark interface and keyboard focus states.

## Requirements and local setup

- Node.js 20.9 or newer
- npm
- A Turso database and its URL and auth token for persistent history

```bash
npm install
npm run dev
```

Copy `.env.example` to `.env.local` and fill in `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN`. Create a Turso database and token with the Turso CLI:

```bash
turso auth login
turso db create phishguard-ai
turso db show phishguard-ai --url
turso db tokens create phishguard-ai
```

On the first request, the app creates the `scans` table and index defined in `db/schema.sql`. Without Turso credentials, analysis still works locally, but persistent history is unavailable. Open [http://localhost:3000](http://localhost:3000). The App Router entry point is `app/page.tsx`; the scoring logic is `lib/analyzer.ts`.

## Detection algorithm

The engine is deterministic and additive. Each matching rule contributes its documented points; the sum is capped at 100.

| Score | Classification |
| --- | --- |
| 0–29 | Low Risk |
| 30–59 | Suspicious |
| 60–100 | High Risk |

Email points include urgent/threat language (18), account verification (18), password/OTP requests (35), link calls (8, with a bounded increment for more links), attachment mentions (14), malformed sender addresses (16), public mailbox plus organization display name (30), and sender-domain/display-name mismatch (20). More than one independent warning can raise the score. A regular announcement without those patterns scores zero.

URL points include HTTP instead of HTTPS (10), URL length over 100 characters (10), IP address host (28), IDN/punycode (24), many subdomains (12), known shortener (22), selected unusual TLD (10), embedded user information (26), encoded delimiters (12), brand word embedded in a different host (20), one-edit brand lookalike (30), and invisible formatting characters (24). These are signals, not proof. HTTPS earns no safety points and does not prove legitimacy. The application parses URLs locally and never resolves DNS, follows redirects, opens URLs, or sends arbitrary URLs to a server.

HTML points include password form (25), declared form host mismatch (30), external script reference (12), and possible brand impersonation cue (18). Since pasted markup has no verified origin, output is explicitly limited to static text-pattern awareness. No submitted HTML is rendered.

The indicator details explain the signal. Scores are bounded at 100. Pattern matching is intentionally inspectable for a class project; it is not machine learning, malware analysis, domain registration analysis, certificate validation, or a blacklist lookup.

## Example cases

The dashboard and practice lab include synthetic examples: fake university login, bank verification, password reset, legitimate university announcement, a shortened URL, a misspelled PayPal-like domain, and a normal HTTPS URL. URL examples use reserved/example or well-known educational hosts and are not opened.

Automated tests cover normal and suspicious mail, sender mismatch, shortener, typo domain, IP/Unicode/HTTP URLs, invalid/empty/long inputs, malicious-looking HTML as inert text, and score boundaries.

```bash
npm test
npm run lint
npm run typecheck
npm run build
```

## GitHub

1. Create an empty repository on GitHub.
2. From this project folder, initialize and push the source:

```bash
git init
git add .
git commit -m "Build PhishGuard AI security analysis app"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
git push -u origin main
```

Do not commit `.env` files or credentials. Turso URL and token are required for persistent history.

## Deploy on Vercel

1. Import the GitHub repository in Vercel.
2. Keep the detected framework as **Next.js** and the project root as the repository root.
3. In Vercel Project Settings → Environment Variables, add `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN`. Keep the token private and never add `.env.local` to GitHub.
4. Deploy. Vercel runs the Next.js build. Later pushes to the connected branch create deployments.

You can also deploy from the CLI with `npx vercel` and `npx vercel --prod`.

## University presentation outline

1. **Problem:** users face impersonation, urgency, fake login pages, and lookalike domains.
2. **Threat model:** the app analyzes user-provided text and addresses; it does not interact with suspected sites or require real credentials.
3. **Architecture:** Next.js App Router + TypeScript; browser-side rules; optional Turso history API; Vercel-compatible deployment.
4. **Method:** show the weights, score thresholds, and indicator explanations. Compare the fake university email with the legitimate notice.
5. **Safety design:** no URL fetching (reduces SSRF exposure), no HTML execution (reduces XSS exposure), no passwords/OTPs requested, and only scan type, score, classification, and time sent to the database.
6. **Evaluation:** run the bundled unit tests and demonstrate both false-positive and false-negative limitations.
7. **Future work:** optionally add a trusted URL reputation provider via a serverless route. Keep the key server-side, validate inputs, apply strict domain and rate limits, and clearly show when a lookup actually occurred. Never silently imply a reputation check.

## Limitations and responsible use

- A rule-based detector cannot determine intent and will miss novel or carefully written attacks.
- Benign messages can match a rule. A score is prioritization guidance, not a verdict.
- URL analysis uses static parsing and a short illustrative heuristic list, not a live reputation service or registered-domain database.
- Email headers and sender authentication are not available from pasted body text. Display names can be forged.
- Static HTML cannot prove how a hosted page behaves or who controls it.
- Use synthetic or redacted samples for demonstrations. Do not paste secrets or personal data.
- Reputation API integration is not configured in this version; no blacklist check is claimed.
