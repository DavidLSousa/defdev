# Implementation Plan: DevSecOps & CSPM Agents

## Phase 0: Monorepo Scaffolding
Setup the project skeleton with npm workspaces, TypeScript configs, and build tooling.

**Packages:**
```
packages/core              — shared types, interfaces, utilities
packages/devsecops-agent   — SAST, SCA, secrets detection
packages/cspm-agent        — IaC parsing, compliance rules
packages/cli               — Commander.js CLI
packages/github-action     — GitHub Actions integration
test-fixtures/             — vulnerable & secure sample code
```

**Dependency graph:**
```
core  <--  devsecops-agent  <--  cli
core  <--  cspm-agent       <--  cli
core  <--  github-action
```

---

## Phase 1: Core Package (shared types & utils)
- `Finding`, `AnalysisReport`, `IaCResource`, `ComplianceViolation`, `ComplianceReport` interfaces
- `IAnalyzer`, `IReporter`, `IIaCAnalyzer` abstract interfaces
- Utilities: file reader, ID generator, report builder, severity helpers

---

## Phase 2: DevSecOps Agent (parallel with Phase 3)
**4 analyzer modules, each with focused rules:**

| Module | Rules | Detection Method |
|--------|-------|-----------------|
| **SAST/Injection** | SQL injection, `eval()`, command injection, `innerHTML`, `$where` | Regex + optional AST |
| **SAST/Auth** | Hardcoded JWT secrets, missing `jwt.verify`, `cors({ origin: '*' })`, `dangerouslySetInnerHTML`, weak crypto | Regex |
| **Secrets** | AWS keys, GitHub tokens, API keys, private keys, connection strings, JWTs, `.env` patterns | Regex + entropy |
| **SCA** | Known CVEs via `npm audit --json`, OSV API fallback, GitHub Advisory DB | External APIs |

---

## Phase 3: CSPM Agent (parallel with Phase 2)
**Parsers:** Terraform (via `hcl2json`) + CloudFormation (via `js-yaml`)

| Service | Rules | CIS Mapping |
|---------|-------|-------------|
| **S3** | Public ACL, no encryption, no versioning, no logging, no public access block | CIS 2.1.x |
| **Security Groups** | SSH/RDP open to `0.0.0.0/0`, all-traffic open | CIS 4.x |
| **IAM** | Wildcard `*` policies, root access keys, no MFA, inline policies | CIS 1.x |

---

## Phase 4: Test Fixtures
Vulnerable + secure samples for both agents:
- `vulnerable-app/` — TypeScript with SQL injection, hardcoded secrets, weak crypto, `eval()`, bad CORS
- `vulnerable-infra/` — Terraform + CloudFormation with public S3, open SGs, wildcard IAM
- `secure-app/` and `secure-infra/` — Correct counterparts (false-positive testing)

---

## Phase 5: CLI
Commands: `security-mvp scan` (DevSecOps) and `security-mvp cspm` (CSPM)

Output formats: **text** (colored console), **JSON**, **SARIF** (GitHub Code Scanning standard)

---

## Phase 6: GitHub Actions Integration
- `action.yml` with inputs for scan type, path, severity threshold
- Annotations inline on PRs, summary tables, SARIF upload
- Bundled with `ncc` into single `dist/index.js`

---

## Phase 7: Documentation & Demo
- Architecture docs with Mermaid diagrams
- Detection rules reference with CWE/CIS mappings
- Limitations doc (regex vs AST, no data flow, no runtime analysis)
- Demo shell scripts running agents against test fixtures
- CI workflow dogfooding the agents

---

## Critical Path (timeline)
```
Week 1:  Phase 0 + Phase 1
Week 2:  Phase 2 + Phase 3 (in parallel)
Week 3:  Phase 4 + Phase 5 (CLI = first working demo)
Week 4:  Phase 6 + Phase 7 + polish
```

---

## Key Risks

| Risk | Mitigation |
|------|-----------|
| `hcl2json` binary not in CI | Docker image or regex fallback for simple `.tf` |
| High false-positive rate (regex SAST) | Tune with fixtures; add confidence scores; document limitations |
| `npm audit` needs `package-lock.json` | Graceful skip + fallback to OSV API |
| TS Compiler API version coupling | Pin version; use only stable `createSourceFile` API |

---

## Detailed Phase Breakdown

### Phase 0 — Root configuration files

1. **`package.json`** - Root workspace definition
   - `workspaces`: `["packages/*"]`
   - `scripts`: build, test, lint, clean
   - `engines`: `{ "node": ">=18" }`

2. **`tsconfig.base.json`** - Shared TypeScript config
   - `target`: ES2022, `module`: Node16, `strict`: true, `composite`: true

3. **`tsconfig.json`** - Root project references file

4. **`.gitignore`** - Standard Node + dist/ + node_modules/ + coverage/

5. **`.nvmrc`** - Pin to `18`

For each of the 5 packages, create:
- `packages/<name>/package.json`
- `packages/<name>/tsconfig.json` — extends `../../tsconfig.base.json`
- `packages/<name>/src/index.ts` — empty barrel export

---

### Phase 1 — Core Package files

| File | Purpose |
|------|---------|
| `types/severity.ts` | `Severity` enum: CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `types/finding.ts` | `Finding` interface + `FindingCategory` enum |
| `types/analysis-report.ts` | `AnalysisReport`, `ReportSummary` interfaces |
| `types/iac.ts` | `IaCResource`, `ComplianceViolation`, `ComplianceReport` interfaces |
| `interfaces/analyzer.ts` | `IAnalyzer` interface + `AnalysisInput`, `FileEntry` types |
| `interfaces/reporter.ts` | `IReporter` interface |
| `interfaces/iac-analyzer.ts` | `IIaCAnalyzer` interface |
| `utils/id-generator.ts` | Deterministic finding ID via SHA-256 hash |
| `utils/file-reader.ts` | `readProjectFiles()` + `readSingleFile()` using fast-glob |
| `utils/severity-utils.ts` | `severityToNumber()`, `getHighestSeverity()` |
| `utils/report-builder.ts` | `buildReport()` — computes summary counts |

---

### Phase 2 — DevSecOps Agent files

| File | Purpose |
|------|---------|
| `agent.ts` | `DevSecOpsAgent` class — orchestrates pipeline |
| `config.ts` | `DevSecOpsConfig` type + defaults |
| `analyzers/sast/index.ts` | `SastAnalyzer` — runs all SAST rules |
| `analyzers/sast/rules/injection-rules.ts` | eval, SQL/NoSQL injection, command injection, innerHTML |
| `analyzers/sast/rules/auth-rules.ts` | JWT, CORS, dangerouslySetInnerHTML, weak crypto |
| `analyzers/sast/rules/crypto-rules.ts` | Math.random, weak algorithms, hardcoded IVs |
| `analyzers/sast/rule-registry.ts` | Maps category → rule functions |
| `analyzers/sast/ast/ts-parser.ts` | TypeScript Compiler API AST parsing |
| `analyzers/sast/ast/ast-visitor.ts` | Generic AST walker |
| `analyzers/secrets/index.ts` | `SecretsAnalyzer` |
| `analyzers/secrets/patterns.ts` | Regex patterns: AWS keys, GitHub tokens, API keys, private keys, connection strings |
| `analyzers/sca/index.ts` | `ScaAnalyzer` — npm audit + OSV API |
| `analyzers/sca/npm-audit-parser.ts` | Parse `npm audit --json` output |
| `analyzers/sca/osv-client.ts` | HTTP client for `api.osv.dev/v1/query` |

---

### Phase 3 — CSPM Agent files

| File | Purpose |
|------|---------|
| `agent.ts` | `CspmAgent` class — orchestrates pipeline |
| `config.ts` | `CspmConfig` type + defaults |
| `parsers/terraform-parser.ts` | HCL → JSON via `hcl2json`, map to `IaCResource[]` |
| `parsers/cloudformation-parser.ts` | YAML → Object via `js-yaml`, map to `IaCResource[]` |
| `parsers/index.ts` | Parser factory by file extension |
| `rules/index.ts` | `ComplianceRule` interface + `runAllRules()` |
| `rules/s3-rules.ts` | Public ACL, no encryption, no versioning, no logging |
| `rules/security-group-rules.ts` | SSH/RDP open, all-traffic, unrestricted egress |
| `rules/iam-rules.ts` | Wildcard policies, root access keys, no MFA, inline policies |
| `rules/compliance-mapping.ts` | CIS AWS Foundations Benchmark mapping table |
| `report-builder.ts` | `buildComplianceReport()` — compliance score + recommendations |

---

### Phase 5 — CLI files

| File | Purpose |
|------|---------|
| `index.ts` | Commander program setup |
| `commands/scan.ts` | DevSecOps scan: `--path`, `--format`, `--severity`, `--output` |
| `commands/cspm.ts` | CSPM scan: `--path`, `--format`, `--framework`, `--output` |
| `formatters/text-formatter.ts` | Colored console output with code snippets |
| `formatters/json-formatter.ts` | Pretty-printed JSON |
| `formatters/sarif-formatter.ts` | SARIF 2.1.0 (GitHub Code Scanning compatible) |
| `bin/security-mvp.ts` | Bin entry point with shebang |

---

### Phase 6 — GitHub Action files

| File | Purpose |
|------|---------|
| `action.yml` | Action metadata: inputs, runs.using=node20 |
| `src/index.ts` | Read inputs, run agents, post results |
| `src/github-reporter.ts` | Inline PR annotations + markdown summary table |
| `src/sarif-uploader.ts` | Upload SARIF to GitHub Code Scanning API |

---

## Dependencies Summary

| Package | Key Dependencies |
|---------|-----------------|
| `core` | `fast-glob` |
| `devsecops-agent` | `@security-mvp/core`, `typescript` (Compiler API) |
| `cspm-agent` | `@security-mvp/core`, `js-yaml`, `hcl2json` |
| `cli` | `@security-mvp/core`, agents, `commander`, `chalk` |
| `github-action` | agents, `@actions/core`, `@actions/github`, `@vercel/ncc` (dev) |
| All (dev) | `typescript`, `vitest`, `eslint`, `prettier` |
