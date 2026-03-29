# DefDev

Dois agentes de segurança para auxiliar desenvolvedores júnior a identificar vulnerabilidades em código e infraestrutura cloud antes de chegarem à produção.

---

## O Problema

Desenvolvedores júnior utilizam IA para gerar código e configurações cloud (Terraform, CloudFormation), mas sem o conhecimento para revisar o que foi gerado. Resultado: código inseguro e infraestrutura mal configurada em produção.

## A Solução

Dois agentes automatizados que detectam problemas conhecidos antes da revisão humana:

| Agente        | Analisa                      | Detecta                                                             |
| ------------- | ---------------------------- | ------------------------------------------------------------------- |
| **DevSecOps** | Código TypeScript/JavaScript | Injection, secrets, dependências vulneráveis, padrões inseguros     |
| **CSPM**      | Terraform / CloudFormation   | Buckets públicos, security groups abertos, políticas IAM excessivas |

---

## Módulos

### `packages/core`

Base compartilhada entre todos os pacotes.

- Tipos: `Finding`, `AnalysisReport`, `IaCResource`, `ComplianceViolation`
- Interfaces: `IAnalyzer`, `IIaCAnalyzer`
- Utilitários: leitor de arquivos, gerador de IDs determinísticos, construtor de relatórios

### `packages/devsecops-agent`

Agente de análise de segurança em código fonte.

**SAST (análise estática):**

- `injection-rules` — `eval()`, SQL injection, command injection, `innerHTML`, MongoDB `$where`
- `auth-rules` — `jwt.decode` sem verificação, JWT secret hardcoded, CORS wildcard, `dangerouslySetInnerHTML`, MD5/SHA1
- `crypto-rules` — `Math.random()` em contextos de segurança, DES/RC4, chaves hardcoded

**Secrets Detection:**

- AWS Access Keys, GitHub tokens, private keys, connection strings com credenciais, API keys genéricas, senhas hardcoded

**SCA (análise de dependências):**

- Executa `npm audit --json` e mapeia CVEs para o formato padrão
- Fallback para a API pública OSV (`api.osv.dev`) se npm audit falhar

### `packages/cspm-agent`

Agente de análise de postura de segurança em cloud (IaC).

**Parsers:**

- Terraform (`.tf`) — parse via `hcl2json` com fallback em regex
- CloudFormation (`.yaml`/`.yml`) — parse via `js-yaml`

**Regras de compliance (CIS AWS Foundations Benchmark):**

- `s3-rules` — ACL pública, sem criptografia, sem versionamento, sem public access block
- `security-group-rules` — SSH/RDP abertos para `0.0.0.0/0`, all-traffic aberto
- `iam-rules` — políticas wildcard `*`, AdministratorAccess, inline policies, password policy fraca

### `packages/cli`

Interface de linha de comando.

```bash
security-mvp scan [path]   # DevSecOps
security-mvp cspm [path]   # CSPM
```

Formatos de saída: `text` (colorido), `json`, `sarif` (GitHub Code Scanning).

### `packages/github-action`

Action para CI/CD. Gera anotações inline no PR, tabela de resumo no GitHub Actions Summary e upload de SARIF.

---

## Como Rodar

### Pré-requisitos

```bash
node --version  # >= 18
npm --version   # >= 9
```

### Instalar e buildar

```bash
npm install
npm run build
```

### Rodar os testes

```bash
# Todos os pacotes
npm run test

# Apenas um pacote específico
npm run test --workspace=packages/core
npm run test --workspace=packages/devsecops-agent
npm run test --workspace=packages/cspm-agent
```

### Rodar os agentes nos fixtures vulneráveis

```bash
# DevSecOps — escaneia código TypeScript vulnerável
node packages/cli/dist/bin/security-mvp.js scan ./test-fixtures/vulnerable-app --no-sca

# CSPM — escaneia infraestrutura Terraform + CloudFormation vulnerável
node packages/cli/dist/bin/security-mvp.js cspm ./test-fixtures/vulnerable-infra

# Gerar relatório JSON
node packages/cli/dist/bin/security-mvp.js scan ./test-fixtures/vulnerable-app --no-sca --format json --output report.json

# Falhar se houver vulnerabilidade HIGH ou acima (útil em CI)
node packages/cli/dist/bin/security-mvp.js scan ./test-fixtures/vulnerable-app --no-sca --fail-on high
```

### Scripts de demo prontos

```bash
bash demo/run-devsecops-demo.sh
bash demo/run-cspm-demo.sh
```

---

## Resultados Esperados nos Fixtures

**DevSecOps** (`test-fixtures/vulnerable-app`):

- 13 CRITICAL · 9 HIGH · 2 MEDIUM = **24 findings**

**CSPM** (`test-fixtures/vulnerable-infra`):

- 3 CRITICAL · 8 HIGH · 5 MEDIUM · 2 LOW = **18 violations · score 42%**

---

## Limitações

- Análise **estática** apenas — não detecta vulnerabilidades em runtime
- SAST baseado em **regex** — pode gerar falsos positivos em código dinâmico legítimo
- SCA requer `package-lock.json` para `npm audit`
- Parser Terraform usa regex como fallback (sem `hcl2json` instalado)
- Não detecta zero-days nem vulnerabilidades em dependências transitivas profundas
