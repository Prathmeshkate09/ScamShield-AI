# ScamShield AI Optimization Execution Plan

- Status: approved execution plan and live phase-gate tracker
- Prepared: 2026-09-04
- Baseline reviewed: `origin/main` at `c0e5d3f`

## Execution progress

- Phase 0: complete in the working tree.
- Verified Phase 0: 53 backend tests, 5 frontend tests, frontend type-check, production frontend build, Python syntax checks, Alembic SQL generation, and migration `0003` upgrade/downgrade/re-upgrade against disposable PostgreSQL 17.
- Migration safety result: all 10 additive fields appeared at `0003`, were absent after downgrade to `0002`, and reappeared after upgrading to `0003`; no project database or named volume was used.
- Phase A1: complete in the working tree. Unicode/zero-width normalization, modular contextual rules, stable signal codes, duplicate-code validation, deterministic ordering, safe-advice suppression, deduplication, and the 30-point rule contribution cap are implemented.
- Verified Phase A1: 61 backend tests pass, including safe delivery, credential advice, OTP request, urgency, investment, recruitment fee, payment advice, repeated terms, deterministic extraction, and invalid rule configuration.
- Phase A2: ready to begin.

## 1. Product outcome

Evolve the existing hackathon MVP into a purpose-built digital scam investigation and protection workflow without rebuilding the application or removing working authentication, persistence, rate limiting, storage, or deployment behavior.

The finished product must demonstrate that the LLM is one bounded input to a broader security engine:

```text
Authenticated user input
        |
        v
Normalization and artifact extraction
        |
        +------------------+-------------------+
        |                  |                   |
        v                  v                   v
Deterministic rules   Passive URL checks   AI semantic findings
        |                  |                   |
        +------------------+-------------------+
                           |
                           v
                 Deterministic risk aggregator
                           |
          +----------------+----------------+
          |                |                |
          v                v                v
       Evidence       Attack chain     Recommendations
          |                |                |
          +----------------+----------------+
                           |
                           v
                  Persisted threat report
```

Success is not merely a new UI. The same structured evidence must flow through the backend contract, PostgreSQL, history, and the final report.

## 2. Current implementation audit

### Already implemented and to be preserved

| Capability | Current implementation | Decision |
| --- | --- | --- |
| Frontend | Next.js 16, React 19, TypeScript App Router | Extend, do not replace |
| Authentication | Supabase SSR, email verification, Google OAuth, recovery, Turnstile support | Preserve existing flows |
| API | FastAPI with normalized success/error envelopes | Extend existing endpoints compatibly |
| Persistence | Async SQLAlchemy and PostgreSQL `analyses` table | Add an Alembic migration; never recreate the table |
| Authorization | Supabase token validation and user-scoped repository queries | Preserve and test ownership isolation |
| Rate limiting | Atomic Upstash Redis limits with fail-closed protected routes | Preserve |
| AI providers | OpenAI, Gemini, and explicit demo provider abstraction | Narrow providers to semantic findings |
| URL safety | Passive URL parsing; submitted URLs are never fetched | Expand this implementation |
| Images | MIME, extension, size, and decoded-format validation; private Supabase Storage | Preserve validation and repair lifecycle ordering |
| Voice | Browser speech recognition followed by transcript analysis | Reuse the text security pipeline |
| Dashboard | Statistics, recent history, four input modes, explainable result panel | Decompose and enhance |
| Deployment | Vercel frontend, Render Docker backend, Supabase, Upstash | Preserve stateless topology |
| Tests | Broad backend API/auth coverage and five frontend helper tests | Expand with engine, component, and journey tests |

### Existing partial capabilities

- `url_signals.py` already checks HTTP, IP hosts, punycode, subdomain depth, suspicious TLDs, URL length, sensitive query names, and limited brand-like hostnames.
- AI responses already contain score, type, confidence, flags, explanation, and recommendations, but the AI still supplies the primary score.
- The dashboard already shows risk, confidence, flags, explanation, actions, statistics, and recent records, but does not expose structured evidence or an attack chain.
- Demo mode is explicit and deterministic, but it has only coarse heuristics and does not exercise the proposed full security pipeline.
- Request ID, AI latency, and database latency are partially recorded in logs, but total duration and persisted provider/model metadata are absent.

### Material gaps found during review

1. AI output currently determines most of the assessment instead of being one bounded signal.
2. The proposed weighted average double-counts correlated concepts such as urgency, social engineering, credential theft, and rule matches.
3. A fixed URL weight would distort scores for content that contains no URL.
4. Current risk thresholds are `0-14`, `15-34`, `35-59`, `60-79`, and `80-100`; the proposal uses different thresholds. There must be one centralized definition.
5. Images are uploaded before AI analysis and database persistence, so downstream failure can create orphaned objects.
6. Raw text, URLs, and transcripts are retained without a documented retention or deletion policy.
7. The existing API/database name is `recommendation`; renaming it to `recommendations` would break clients and stored data.
8. The frontend dashboard and authentication components are already large and should not absorb all new presentation logic.
9. There is no idempotency boundary, so retries can duplicate AI cost and database rows.
10. No full browser-level test currently proves the final demonstration journey.

## 3. Corrections to the supplied proposal

The supplied direction is accepted with these changes:

- Use a capped contribution model instead of a naive weighted average.
- Keep `recommendation` as the backward-compatible API/database field; it may be represented as “recommended actions” in the UI.
- Centralize the requested risk bands: `SAFE 0-19`, `LOW 20-39`, `MEDIUM 40-59`, `HIGH 60-79`, `CRITICAL 80-100`.
- Make AI return semantic findings, not the authoritative final score, attack chain, or incident response.
- Generate evidence, scoring, attack chain, and recommendations on the server from typed signals.
- Keep all existing analyze endpoints. Add fields to their response without removing existing fields.
- Make automatic URL extraction from text the demo-critical combined analysis. A general multi-artifact endpoint follows later in Phase C.
- Keep incident-stage selection client-side for the MVP. The backend returns safe guidance by incident stage, but the user's selected stage does not need persistence.
- Do not add unauthenticated analysis. “Try Demo” will load a scenario for an authenticated user and use the same real protected API.
- Analyze validated image bytes before durable upload, then delete the object if database persistence fails.
- Add retention/deletion design before claiming production privacy readiness.

## 4. Canonical domain contracts

Add typed Pydantic models and matching TypeScript types. Names may be adjusted to existing conventions, but their responsibilities must remain separate.

### Risk signal

```text
RiskSignal
  code: stable machine identifier
  title: short user-facing label
  category: urgency | impersonation | credential | financial |
            social_engineering | coercion | url | semantic
  severity: INFO | LOW | MEDIUM | HIGH | CRITICAL
  raw_score: 0..100
  contribution: 0..configured category cap
  confidence: 0..1
  source: rule | url | ai | cross_signal
  evidence: concise factual explanation
```

### Evidence item

```text
EvidenceItem
  id: stable identifier
  title
  category
  severity
  explanation
  source
  score_contribution
  artifact_reference: optional safe reference such as extracted URL index
```

Evidence must not expose internal prompts, provider payloads, credentials, or hidden chain-of-thought. It contains concise product explanations derived from known findings.

### URL intelligence result

```text
UrlIntelligenceResult
  normalized_url
  hostname
  registrable_domain
  scheme
  port
  path
  query_parameter_count
  risk_score
  risk_level
  findings[]
```

The service reports suspicious characteristics, not unverified reputation claims.

### Attack chain

```text
AttackChain
  nodes[]: id, label, type, severity
  edges[]: source, target
```

The builder uses deterministic mappings from confirmed signal categories. It must not invent stages unsupported by evidence.

### Threat report

The existing `ScamAssessment`/`AnalysisResponse` contract will be extended with:

```text
signals[]
evidence[]
extracted_urls[]
url_intelligence[]
attack_chain
incident_response
analysis_duration_ms
ai_provider
model_name
```

Existing fields remain available:

```text
risk_score
risk_level
scam_type
confidence
red_flags
explanation
recommendation
```

`red_flags` becomes a backward-compatible summary projection of evidence titles. `recommendation` remains the canonical action list.

## 5. Deterministic risk model

### Contribution caps

Store all scoring values in one typed configuration module:

| Signal family | Maximum contribution |
| --- | ---: |
| AI semantic findings | 35 |
| Deterministic rules | 30 |
| Passive URL intelligence | 25 |
| Independent-signal corroboration | 10 |
| Total | 100 |

Formula:

```text
final_score = min(
  100,
  semantic_contribution
  + rules_contribution
  + url_contribution
  + corroboration_bonus
)
```

Rules:

- Missing URL evidence contributes zero; it does not reduce or renormalize other categories.
- Deduplicate signals by stable code and artifact reference.
- Apply per-category caps so repeated keywords cannot inflate the score without limit.
- Apply corroboration only when independent sources support compatible findings—for example, a claimed bank plus a mismatched URL plus a credential request.
- AI contribution is bounded by both its semantic score and declared confidence.
- Risk level is calculated only from the final server score.
- Confidence represents evidence coverage and agreement, not probability that a crime occurred.
- All constants and mappings must be versioned and covered by deterministic tests.

The initial constants are a transparent MVP policy, not statistically calibrated truth. Document that limitation and design the configuration so labeled evaluation data can replace the initial values later.

## 6. Rule-engine design

Create small rule definitions rather than one large keyword function.

Each rule contains:

```text
code
category
severity
patterns or predicate
negative/context checks
evidence template
base score
```

Initial rule groups:

- Urgency and deadline pressure
- Threats, suspension, or coercion
- OTP, PIN, password, CVV, UPI PIN, card, and security-code requests
- Payments, transfers, deposits, advance fees, and refund fees
- Bank, government, police, tax, delivery, employer, and technical-support impersonation
- Guaranteed returns and investment pressure
- Recruitment fees and job impersonation
- Secrecy and isolation requests
- Reward and emotional-manipulation tactics

Context requirements:

- Normalize Unicode, whitespace, and casing.
- Match phrases and token boundaries, not raw substrings alone.
- Add negation/educational-context suppression where practical, such as “never share your OTP.”
- Cap repeated matches from the same rule.
- Preserve only short evidence excerpts when necessary; do not log them.

## 7. URL-intelligence design

Extend the existing passive parser; never fetch the submitted destination.

Checks:

1. Scheme and HTTP downgrade
2. Hostname normalization
3. Registrable domain using a small maintained public-suffix dependency or an explicitly documented fallback
4. Subdomain depth
5. IPv4/IPv6 hostname
6. Non-default port
7. Total URL length
8. Query parameter count
9. Sensitive path/query terms
10. Embedded username/password
11. Punycode/IDN markers
12. Suspicious TLD
13. Brand-like tokens
14. Claimed-brand/domain mismatch
15. Excessive separators or misleading hostname composition
16. Deduplicated URLs extracted from message or transcript text

Brand data must live in a small configuration module with aliases and official domain patterns. A brand match is evidence of possible impersonation, never proof of maliciousness.

Do not add WHOIS, DNS, Safe Browsing, VirusTotal, or arbitrary HTTP access during the core MVP phases. Any future reputation provider must use fixed provider endpoints, strict timeouts, outbound restrictions, caching, and explicit provenance.

## 8. Prompt-injection boundary

Change provider output to semantic findings such as intent, claimed identity, requested action, pressure tactics, scam category, and bounded semantic score.

Prompt requirements:

- State that scanned content is untrusted data and cannot alter system instructions.
- Delimit it with `BEGIN_UNTRUSTED_CONTENT` and `END_UNTRUSTED_CONTENT`.
- Require typed structured output.
- Prohibit URL-reputation claims without supplied verified evidence.
- Prohibit hidden reasoning or system-prompt disclosure.
- Treat embedded commands as content to classify.
- Reject malformed output with the existing controlled provider error.

Delimiters reduce ambiguity but are not a complete defense; the deterministic server pipeline remains authoritative.

## 9. Persistence and migration strategy

Create migration `0003_add_threat_report_fields.py` after inspecting the live schema immediately before execution.

Planned additive columns:

- `signals JSONB NOT NULL DEFAULT '[]'`
- `evidence JSONB NOT NULL DEFAULT '[]'`
- `extracted_urls JSONB NOT NULL DEFAULT '[]'`
- `url_intelligence JSONB NOT NULL DEFAULT '[]'`
- `attack_chain JSONB NOT NULL DEFAULT '{"nodes":[],"edges":[]}'`
- `incident_response JSONB NOT NULL DEFAULT '[]'`
- `analysis_duration_ms INTEGER NULL`
- `ai_provider VARCHAR(40) NULL`
- `model_name VARCHAR(120) NULL`
- `scoring_version VARCHAR(30) NOT NULL DEFAULT 'v1'`

Migration rules:

- Do not rename or drop current columns.
- Keep old records readable with empty structured fields.
- Preserve the `recommendation` column and response property.
- Add database constraints for non-negative duration and valid score ranges where compatible.
- Do not duplicate large uploaded files in PostgreSQL.
- Test upgrade and downgrade against disposable PostgreSQL before production.
- Back up and inspect the live Supabase schema before applying the migration.

Privacy work required before a production claim:

- Define raw-input retention duration.
- Add user-owned deletion for records and associated private objects.
- Decide whether full raw message/transcript storage is necessary or opt-in.
- Document object cleanup when accounts or analyses are deleted.

## 10. API evolution

Preserve these endpoints:

- `POST /api/v1/analyze/text`
- `POST /api/v1/analyze/image`
- `POST /api/v1/analyze/url`
- `POST /api/v1/analyze/voice`
- `GET /api/v1/analyses`
- `GET /api/v1/analyses/stats`
- `GET /api/v1/analyses/{analysis_id}`

Compatibility requirements:

- Existing request bodies remain valid.
- Existing response fields remain present with the same meaning where possible.
- New structured fields are additive.
- Risk-band changes are explicitly tested and documented.
- Continue returning `404` for another user's analysis.

History query additions:

```text
risk_level
scam_type
input_type
created_from
created_to
page
page_size
```

All filters remain user-scoped and use aggregate database queries for statistics.

After automatic text URL extraction is stable, add an optional authenticated multi-artifact endpoint:

```text
POST /api/v1/analyze/combined
multipart fields: text?, url?, file?
```

At least one artifact is required. Limit artifact counts and combined request size. The four existing endpoints remain supported.

## 11. Screenshot and storage lifecycle

Target flow:

```text
Read bounded upload
  -> validate MIME, extension, bytes, dimensions, and decompression limits
  -> perform vision/OCR analysis from memory
  -> extract and analyze text/URLs
  -> build final threat report
  -> upload private object only if retention is enabled
  -> persist report and object path
  -> delete uploaded object if database persistence fails
```

Implementation requirements:

- Distinguish “bucket missing” from permission/network failures.
- Add a storage delete operation for compensation and record-cleanup workflows.
- Never return a public object URL.
- Do not store screenshots locally.
- Add decoded pixel/dimension limits to reduce decompression-bomb risk.
- Keep OCR optional behind an interface. Prefer existing provider vision for the demo unless a local OCR dependency is proven necessary.

## 12. Incident-response model

Return defensive guidance for these stages:

- Received only
- Clicked link
- Entered information
- Shared credential or OTP
- Sent money

Guidance is selected from deterministic, threat-aware templates. It must:

- Prioritize urgent defensive steps.
- Recommend official support/reporting channels generically unless current authoritative contact data is verified.
- Never invent phone numbers.
- Never provide offensive, bypass, or retaliation instructions.
- Clearly separate pre-incident prevention from post-interaction response.

For the MVP, the selected stage is client state. The report may persist the available guidance catalog, not the user's selected incident stage.

## 13. Frontend decomposition and UX

Create focused components instead of extending the existing 468-line dashboard indefinitely:

```text
frontend/components/analysis/
  analysis-input.tsx
  analysis-progress.tsx
  threat-report.tsx
  risk-summary.tsx
  evidence-list.tsx
  url-intelligence.tsx
  attack-chain.tsx
  recommendation-panel.tsx
  incident-response.tsx

frontend/components/dashboard/
  stats-grid.tsx
  recent-analyses.tsx
  why-scamshield.tsx
```

UX requirements:

- Keep Message, Screenshot, URL, and Voice modes.
- Show “AI-generated assessment + deterministic security signals.”
- Use cautious wording such as “High-risk indicators detected.”
- Present score, level, type, confidence, evidence, URL findings, chain, and actions in that order.
- Add an accessible vertical CSS attack chain; do not add a graph dependency.
- Add `aria-live` result/error announcements, `aria-pressed` mode state, keyboard support, and reduced-motion styles.
- Correct voice wording so recording and analysis are separate actions.
- Represent unknown health/provider mode as unknown, not demo.
- Add a concise “Why ScamShield?” section without disparaging general LLM products.

## 14. Demo scenarios

Create five typed scenarios that use the same protected API as user input:

1. Safe delivery update
2. Banking OTP/credential scam
3. Fake KYC message with extracted phishing URL
4. Guaranteed-return investment scam
5. Recruitment-fee job scam

Each fixture contains:

- Input artifacts
- Expected signal codes
- Expected risk band or bounded range
- Expected evidence categories
- Expected recommended actions
- Expected attack-chain stages

The primary judging scenario is the SBI suspension/KYC message with an embedded lookalike `.xyz` URL. The exact numeric score must come from versioned configuration and tests—not a special-case hard-coded output.

## 15. Phased execution plan

Each phase must leave the application runnable. Do not begin the next phase until its gate passes or the exception is recorded.

### Phase 0 — Contract and baseline

Deliverables:

- Capture current API fixtures and risk-band behavior.
- Define typed signal, evidence, URL, chain, semantic-finding, and report models.
- Centralize scoring configuration and new risk thresholds.
- Add the additive migration and repository mappings.
- Add compatibility serialization tests for existing frontend fields.

Gate:

- Existing API/auth tests pass.
- Migration upgrade/downgrade passes on disposable PostgreSQL.
- Old stored records deserialize with empty new fields.
- Frontend type-check passes.

### Phase A1 — Normalization and deterministic rules

Deliverables:

- `text_normalizer.py`
- `signal_extractor.py`
- Modular `rules_engine.py`
- Rule configuration and stable codes
- Negation/context handling for common false positives
- Tests for safe, urgency, OTP, investment, job, coercion, and educational messages

Gate:

- Same input produces identical deterministic findings.
- “Never share your OTP” is not scored like “Send me your OTP.”
- Repeated keywords cannot exceed category caps.

### Phase A2 — URL extraction, intelligence, and brand mismatch

Deliverables:

- Upgrade `url_signals.py` or replace it compatibly with `url_intelligence.py`.
- Deduplicated URL extraction from text and transcripts.
- Configurable brand aliases and official-domain patterns.
- Passive URL findings with no network access.
- Unit tests for IP hosts, credentials in URL, ports, IDN, suspicious TLDs, subdomains, brand mismatch, and benign official domains.

Gate:

- No submitted destination is fetched or resolved.
- Embedded URLs appear once in the report.
- Brand findings use cautious, evidence-based language.

### Phase A3 — AI semantic contract and final risk engine

Deliverables:

- Change all providers to return typed semantic findings.
- Add explicit untrusted-content prompt boundaries.
- Implement capped risk aggregation and scoring version.
- Implement evidence, recommendation, incident-guidance, and attack-chain builders.
- Update demo provider to emit semantic findings through the same pipeline.

Gate:

- Final risk score is calculated only by server aggregation.
- Provider output cannot directly override risk level.
- Malformed provider output remains a controlled error.
- Prompt-injection fixture is treated as scan data.
- Core demo scenario produces the expected critical band and evidence categories.

### Phase A4 — Persistence and API integration

Deliverables:

- Persist the complete structured report.
- Return additive fields from all four current analysis endpoints.
- Preserve user ownership and response compatibility.
- Record total latency, provider, model, and scoring version.

Gate:

- Text, URL, voice, and image responses validate against Pydantic.
- History/detail round-trip the structured report.
- Cross-user access remains `404`.
- Database failure remains explicit and does not report false persistence.

### Phase B1 — Threat report and evidence UI

Deliverables:

- Decompose the dashboard.
- Add risk summary, evidence cards, URL-intelligence panel, actions, and trust disclaimer.
- Add progress and empty/error states.

Gate:

- Component tests cover loading, success, partial/empty findings, and controlled errors.
- Keyboard and screen-reader state are exposed.
- Mobile layouts work at 430, 760, and desktop widths.

### Phase B2 — Attack chain and incident response

Deliverables:

- Accessible vertical attack-chain visualization.
- “Have you already interacted?” selector.
- Threat-aware urgent-action rendering.
- “Why ScamShield?” differentiator cards.

Gate:

- Chain contains only evidence-supported stages.
- Every incident stage renders safe defensive guidance.
- No unverified emergency contact data is shown.

### Phase C1 — Screenshot pipeline hardening

Deliverables:

- Vision semantic findings merged with rules and extracted URL intelligence.
- Optional OCR abstraction only if provider vision does not reliably return text.
- Safe upload/persistence ordering and compensating object deletion.
- Dimension/decompression defenses.

Gate:

- Invalid, oversized, spoofed, and decompression-risk images fail safely.
- Provider/database failure leaves no orphaned object.
- Screenshot evidence is persisted and displayed.

### Phase C2 — Voice and combined artifacts

Deliverables:

- Voice transcript uses the same normalization/rules/URL/risk pipeline.
- Separate record and analyze controls.
- Add bounded multi-artifact endpoint if the previous phases are stable.
- Deduplicate findings across text, explicit URL, and image-extracted URL.

Gate:

- Voice makes no biometric or caller-identification claim.
- Combined findings do not double-count the same URL/rule.
- Existing single-input clients continue working.

### Phase D1 — History and dashboard

Deliverables:

- Dedicated paginated history route.
- User-scoped filters for level, type, input, and date.
- Complete report detail view.
- Aggregate statistics remain database-side.

Gate:

- Pagination/filter combinations are tested.
- Queries never load all user records for aggregation.
- URL/query filters are bounded and validated.

### Phase D2 — Demo journey and product polish

Deliverables:

- Five typed demo scenarios.
- One-click authenticated demo loading.
- Primary SBI/KYC judging path.
- Responsive and reduced-motion polish.

Gate:

- The full final demo journey works without manually changing data.
- Demo and live modes are clearly labelled.
- No scenario contains real personal or credential data.

### Phase E — Hardening, performance, and documentation

Deliverables:

- Security review: SSRF, prompt injection, XSS, SQL injection, uploads, CORS, secrets, logging, storage, auth, rate limits, and ownership.
- Idempotency strategy for analysis requests.
- Explicit provider timeout and retry policy.
- Redis recovery behavior after transient failure.
- Total-duration/provider metrics and structured failure logs.
- Data-retention and deletion documentation.
- README architecture, scoring, evidence, chain, incident response, deployment, and scaling updates.
- Browser-level final journey test.

Gate:

- Backend tests, frontend tests, type-check, production build, migration test, and container build pass.
- No browser console errors in the final journey.
- No secrets or sensitive scan content appear in logs or repository files.
- Live persistence/storage checks succeed in an approved non-production test account.
- Final review answers “purpose-built security workflow,” not “LLM wrapper.”

## 16. Verification matrix

Run the smallest relevant checks after each change and the complete matrix at phase boundaries.

```text
Backend unit/API:
  python -m pytest -q

Frontend:
  npm test
  npm run typecheck
  npm run build

Containers when Docker is available:
  docker compose config
  docker compose up --build
  GET /health
```

Add targeted suites for:

- Risk aggregation and thresholds
- Signal deduplication and category caps
- Safe-message false positives
- OTP, urgency, phishing, investment, and job rules
- URL parsing and brand mismatch
- Extracted/explicit URL deduplication
- Prompt-injection fixtures
- Evidence and attack-chain generation
- Recommendation and incident-response selection
- Migration upgrade/downgrade
- Image lifecycle compensation
- History filtering and ownership isolation
- Full demo browser journey

## 17. Security and privacy acceptance criteria

- User content is always treated as untrusted data.
- No arbitrary submitted URL is fetched, resolved, or opened.
- No use of unsafe HTML rendering for scan content.
- SQLAlchemy parameters remain the database boundary.
- Private storage paths remain user-scoped.
- Service-role and AI credentials remain backend-only.
- Full messages, passwords, OTPs, provider payloads, and raw prompts are absent from logs.
- AI findings cannot override deterministic authorization, persistence, or score policies.
- Upload failures and cleanup failures are visible and testable, not swallowed.
- Deletion and retention behavior is defined before production readiness is claimed.

## 18. Performance and scalability constraints

- Keep the backend stateless.
- Run independent rules and passive URL analysis without unnecessary provider calls.
- Deduplicate extracted URLs before analysis.
- Avoid a second AI call solely to format a result.
- Use explicit provider timeouts.
- Measure total, AI, and database latency.
- Keep synchronous execution for the hackathon unless measured image latency requires a queue.
- Document a future queue/worker path; do not add Kafka, Kubernetes, or microservices now.

## 19. Rollback and release strategy

- Use one scoped branch and small commits per executable phase.
- Keep schema changes additive until all consumers use the new contract.
- Deploy migration before code that requires new non-null fields, or use safe server defaults.
- Preserve existing fields through at least one full release.
- Do not enable new live-provider behavior without environment validation.
- If a phase gate fails, leave the previous working path available and document the blocker before continuing.
- Do not delete old analysis records or storage objects during this project without explicit approval and a verified backup/cleanup plan.

## 20. Explicit non-goals

- Rebuilding authentication
- Replacing Next.js or FastAPI
- Microservices, Kubernetes, Kafka, or a browser extension
- Active crawling of suspicious URLs
- Voice biometrics or caller identification
- Unverified malicious-domain reputation claims
- Offensive security capabilities
- Large brand databases
- Complex graph libraries
- Anonymous production analysis

## 21. Final demonstration acceptance journey

1. Authenticated user selects the banking/KYC demo.
2. The exact message is loaded into the normal message input.
3. The backend extracts and deduplicates its URL.
4. Rules, URL intelligence, and AI semantic analysis execute.
5. The deterministic aggregator produces a critical risk band.
6. The report shows urgency, impersonation, credential threat, account threat, and suspicious URL evidence where supported.
7. URL intelligence explains the brand/domain mismatch and structural risk without claiming verified malicious reputation.
8. The attack chain shows how the attempt progresses.
9. Defensive recommended actions are displayed.
10. Selecting “I clicked the link” displays appropriate incident-response steps.
11. The complete structured report persists to PostgreSQL.
12. The report appears in user-scoped history and database-backed statistics.

## 22. Execution start point

Begin with Phase 0 only. Before editing:

1. Inspect the live Git status and current schemas again.
2. Confirm backend dependencies and disposable PostgreSQL availability.
3. Capture current API response fixtures.
4. Implement typed contracts and migration as a small, backward-compatible change.
5. Run the Phase 0 gate.

Do not start frontend visual work until the backend report contract and scoring behavior are stable.
