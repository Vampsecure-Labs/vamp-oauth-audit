<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->

  <img src="https://github.com/Vampsecure-Labs/vamp-oauth-audit/actions/workflows/ci.yml/badge.svg" alt="CI"/>
# vamp-oauth-audit

**OAuth 2.0 and OIDC Security Flow Auditor** — VampSecure Labs Security Research Division

> 🇬🇧 [English](#english) · 🇪🇸 [Español](#español)

---

<a name="english"></a>
## 🇬🇧 English

CLI tool for auditing OAuth 2.0 and OIDC configurations for security vulnerabilities.
Analyzes discovery endpoints, authorization URLs, JWT tokens, active token endpoints, and redirect_uri validation.

---

### Installation

```bash
pip install vamp-oauth-audit
# or with Homebrew:
brew install vampsecure-labs/labs/vamp-oauth-audit
```

Or from the repository:

```bash
git clone https://github.com/Vampsecure-Labs/vamp-oauth-audit
cd vamp-oauth-audit
pip install -e .
```

**Dependencies:** Python ≥ 3.9, `aiohttp>=3.9.0`, `rich>=13.7.0`

---

### Usage modes

#### 1. Full target audit (automatic OIDC discovery)

```bash
vamp-oauth-audit --target auth.example.com
```

Automatically builds `https://auth.example.com/.well-known/openid-configuration`,
analyzes the server configuration, and probes the discovered token endpoint.

#### 2. OAuth authorization URL analysis

```bash
vamp-oauth-audit --auth-url "https://auth.example.com/oauth/authorize?response_type=code&client_id=my-app&redirect_uri=https://app.com/callback"
```

Detects missing PKCE, missing state, implicit flow, insecure redirect_uri, and dangerous scope combinations.

#### 3. JWT token inspection

```bash
vamp-oauth-audit \
  --access-token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... \
  --id-token eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... \
  --client-id my-app-id
```

Decodes tokens (without signature verification) and detects alg=none, excessive TTL, PII in claims, and incorrect audience.

#### 4. Audit with proxy (Burp Suite / OWASP ZAP)

```bash
vamp-oauth-audit \
  --target auth.example.com \
  --proxy http://127.0.0.1:8080 \
  --no-ssl-verify
```

Routes traffic through the configured proxy for parallel manual analysis.

#### 5. Full report with HTML and JSON output

```bash
vamp-oauth-audit \
  --target auth.example.com \
  --auth-url "https://auth.example.com/authorize?client_id=app&response_type=token" \
  --access-token eyJhbG... \
  --html oauth_report.html \
  --json findings.json \
  --min-severity HIGH
```

---

### Findings table

| ID         | Severity | Phase         | Description                                              |
|------------|----------|---------------|----------------------------------------------------------|
| OAUTH-000  | INFO     | Discovery     | No OIDC discovery endpoint                               |
| OAUTH-001  | HIGH     | Discovery     | Server does not advertise PKCE S256 support              |
| OAUTH-002  | MEDIUM   | Discovery     | Implicit flow supported by the server                    |
| OAUTH-003  | HIGH     | Discovery     | Server accepts public clients without authentication     |
| OAUTH-004  | HIGH     | Discovery     | ROPC grant supported (OWASP API8:2023)                  |
| OAUTH-005  | CRITICAL | Discovery     | Token endpoint without TLS                               |
| OAUTH-010  | CRITICAL | Auth URL      | Missing state parameter — flow vulnerable to CSRF        |
| OAUTH-011  | HIGH     | Auth URL      | PKCE not used — vulnerable to code interception          |
| OAUTH-012  | HIGH     | Auth URL      | Implicit flow detected (obsolete in OAuth 2.1)           |
| OAUTH-013  | HIGH     | Auth URL      | id_token in frontchannel — token leakage risk            |
| OAUTH-014  | MEDIUM   | Auth URL      | redirect_uri not specified                               |
| OAUTH-015  | HIGH     | Auth URL      | redirect_uri without TLS                                 |
| OAUTH-016  | MEDIUM   | Auth URL      | redirect_uri to localhost (development environment?)     |
| OAUTH-017  | MEDIUM   | Auth URL      | High-privilege scope combination                         |
| OAUTH-018  | LOW      | Auth URL      | Silent authentication — possible SSO bypass              |
| OAUTH-019  | INFO     | Auth URL      | client_id with test environment pattern                  |
| OAUTH-020  | CRITICAL | Auth URL      | Authorization endpoint without TLS                       |
| OAUTH-030  | CRITICAL | Tokens        | Token with alg=none — signature ignored by design        |
| OAUTH-031  | HIGH     | Tokens        | Token missing expiration claim (exp)                     |
| OAUTH-032  | MEDIUM   | Tokens        | Token TTL greater than 24 hours                          |
| OAUTH-033  | MEDIUM   | Tokens        | PII exposed in token claims                              |
| OAUTH-034  | HIGH     | Tokens        | Token with high-privilege scopes                         |
| OAUTH-035  | MEDIUM   | Tokens        | id_token without nonce — vulnerable to replay            |
| OAUTH-036  | HIGH     | Tokens        | Token audience does not match client_id                  |
| OAUTH-037  | INFO     | Tokens        | Access token signed with symmetric HMAC                  |
| OAUTH-040  | MEDIUM   | Token EP      | Token endpoint accepts GET                               |
| OAUTH-041  | MEDIUM   | Token EP      | CORS wildcard on token endpoint                          |
| OAUTH-042  | LOW      | Token EP      | HSTS not configured on token endpoint                    |
| OAUTH-043  | HIGH     | Token EP      | Debug information exposed in error responses             |
| OAUTH-044  | CRITICAL | Token EP      | Token endpoint without TLS (actively confirmed)          |
| OAUTH-050  | CRITICAL | Redirect URI  | Open redirect — server accepts arbitrary redirect_uri    |
| OAUTH-051  | HIGH     | Redirect URI  | redirect_uri validation bypass via URL encoding          |

---

### Environment variables

| Variable                    | Description                          |
|-----------------------------|--------------------------------------|
| `HTTP_PROXY` / `HTTPS_PROXY` | Network proxy (automatically respected with `--no-ssl-verify`) |

---

### Console output example

```
╭──────────────────────────────────────────────────────────────────╮
│ vamp-oauth-audit v1.2 · VampSecure Labs Security Research Division│
╰──────────────────────────────────────────────────────────────────╯

Phase 1 — OIDC Discovery
  → GET https://auth.example.com/.well-known/openid-configuration

Phase 2 — Authorization URL analysis

Phase 4 — Active token endpoint probe
  → Active probe: https://auth.example.com/token

╭─────────────────────────────── Findings ────────────────────────────────╮
│ ID          │ Sev.      │ Phase     │ Description                        │
│ OAUTH-001   │ 🔴 HIGH   │ Discovery │ Server does not advertise PKCE     │
│ OAUTH-010   │ 💀 CRIT   │ Auth URL  │ Missing state parameter            │
│ OAUTH-042   │ 🔵 LOW    │ Token EP  │ HSTS not configured                │
╰──────────────────────────────────────────────────────────────────────────╯

┌─ Global grade: D ─┐

Total: 3 findings — CRITICAL=0 HIGH=1 MEDIUM=0 LOW=1 INFO=0
```

---

### Sample Output

```bash
$ vamp-oauth-audit --target auth.example.com \
    --auth-url "https://auth.example.com/authorize?client_id=web-app&response_type=token&redirect_uri=http://192.168.1.10/callback" \
    --access-token eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIiwiZXhwIjo5OTk5OTk5OTk5fQ. \
    --json findings.json
```

```
╭──────────────────────────────────────────────────────────────────────────────╮
│  vamp-oauth-audit v1.2 · VampSecure Labs Security Research Division          │
╰──────────────────────────────────────────────────────────────────────────────╯

Phase 1 — OIDC Discovery
  → GET https://auth.example.com/.well-known/openid-configuration  [200 OK]
  ✓ Discovery document found — 14 fields analyzed

Phase 2 — Authorization URL analysis
  ⚠ response_type=token detected (implicit flow)
  ⚠ Missing state parameter
  ⚠ redirect_uri without TLS (http://)

Phase 3 — JWT token inspection
  ✗ alg=none — signature ignored by design
  ✗ PII detected in claims: email
  ✗ exp = 2286-11-20 (TTL of 8,400 days)

Phase 4 — Active token endpoint probe
  → POST https://auth.example.com/oauth/token  [401 Unauthorized]
  ⚠ CORS wildcard detected (Access-Control-Allow-Origin: *)

╭─────────────────────────────────── Findings ────────────────────────────────────╮
│ ID         │ Sev.      │ Phase     │ Description                                  │
│ OAUTH-030  │ 💀 CRIT   │ Tokens    │ Token with alg=none — signature ignored      │
│ OAUTH-010  │ 💀 CRIT   │ Auth URL  │ Missing state parameter — CSRF              │
│ OAUTH-012  │ 🔴 HIGH   │ Auth URL  │ Implicit flow detected (obsolete OAuth 2.1) │
│ OAUTH-015  │ 🔴 HIGH   │ Auth URL  │ redirect_uri without TLS                    │
│ OAUTH-033  │ 🟠 MEDIUM │ Tokens    │ PII exposed in claims (email)               │
│ OAUTH-032  │ 🟠 MEDIUM │ Tokens    │ Token TTL greater than 24 hours             │
│ OAUTH-041  │ 🟠 MEDIUM │ Token EP  │ CORS wildcard on token endpoint             │
╰──────────────────────────────────────────────────────────────────────────────────╯

┌─ Global grade: F ─────────────────────────────────────────────────────────────┐
│  Total: 7 findings — CRITICAL=2  HIGH=2  MEDIUM=3  LOW=0  INFO=0             │
└───────────────────────────────────────────────────────────────────────────────┘

JSON report → findings.json
```

---

### Why vamp-oauth-audit vs. Burp Suite OAuth scanner · PortSwigger Web Academy tools · oauth2_proxy audit

| Capability | vamp-oauth-audit | Burp Suite OAuth scanner | oauth2_proxy audit |
|---|---|---|---|
| PKCE enforcement check (RFC 7636) | ✅ | ✅ | ❌ |
| OIDC discovery analysis | ✅ | ✅ | ❌ |
| JWT alg=none + PII in claims detection | ✅ | ❌ | ❌ |
| Active token endpoint probe | ✅ | ✅ | ❌ |
| Open redirect in redirect_uri | ✅ | ✅ | ❌ |
| Implicit flow detection | ✅ | ✅ | ❌ |
| Audience mismatch + nonce replay | ✅ | ❌ | ❌ |
| Self-hosted without commercial license | ✅ | ❌ (commercial) | ✅ |
| JSON + HTML for CI/CD | ✅ | ❌ | ❌ |
| AGPL / open source | ✅ | ❌ | ✅ |

- Full OAuth lifecycle coverage: from OIDC discovery to active token endpoint validation, in a single command with no proxy or browser required.
- JWT checks (alg=none, PII in claims, audience mismatch, excessive TTL) go beyond what generic proxy scanners cover.
- Normalized JSON output following the VSL schema, ready to ingest with `vamp-penreport` or `vamp-orchestrator` without additional steps.
- No GUI dependencies: suitable for CI/CD pipelines and headless environments.

---

### Check Coverage

| Area | Checks included | Representative IDs |
|---|---|---|
| OIDC Discovery | PKCE S256 not advertised, implicit flow on server, ROPC grant enabled, TLS on endpoints | OAUTH-001 – OAUTH-005 |
| Authorization URL — CSRF | Missing `state` parameter | OAUTH-010 |
| Authorization URL — PKCE | Missing `code_challenge` / `code_challenge_method` | OAUTH-011 |
| Implicit / Hybrid flow | `response_type=token`, id_token in frontchannel | OAUTH-012, OAUTH-013 |
| Redirect URI | Without TLS, open redirect, bypass via URL-encoding | OAUTH-015, OAUTH-050, OAUTH-051 |
| JWT token — signature | alg=none, symmetric HMAC in public token | OAUTH-030, OAUTH-037 |
| JWT token — claims | Missing `exp`, TTL > 24h, PII exposed, incorrect audience, missing nonce | OAUTH-031 – OAUTH-036 |
| Token Endpoint | GET accepted, CORS wildcard, missing HSTS, debug in error responses | OAUTH-040 – OAUTH-044 |

---

### Ethical use and legal notice

This tool is designed **exclusively for security audits on systems owned by you or with explicit authorization** from the system owner.

Using vamp-oauth-audit on systems without authorization may constitute a computer crime in most jurisdictions. VampSecure Studios is not responsible for misuse of this tool.

**Recommended compliance:** OWASP API Security Top 10, RFC 6749, RFC 7636 (PKCE), RFC 8252 (Native Apps), OAuth 2.1 (draft-ietf-oauth-v2-1), OpenID Connect Core.

---

### License

AGPL-3.0 License — © VampSecure Studios

---

### Version History

| Version | Main changes |
|---------|-------------|
| v1.2 | Bilingual README (EN/ES) |
| v1.1 | VampSecure Labs Security Research Division — initial public release |

---

*© VampSecure Studios — VampSecure Labs Security Research Division*

---

<a name="español"></a>
## 🇪🇸 Español

Herramienta CLI para auditar configuraciones OAuth 2.0 y OIDC en busca de vulnerabilidades de seguridad.
Analiza endpoints de discovery, URLs de autorización, tokens JWT, token endpoints activos y validación de redirect_uri.

---

### Instalación

```bash
pip install vamp-oauth-audit
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-oauth-audit
```

O desde el repositorio:

```bash
git clone https://github.com/Vampsecure-Labs/vamp-oauth-audit
cd vamp-oauth-audit
pip install -e .
```

**Dependencias:** Python ≥ 3.9, `aiohttp>=3.9.0`, `rich>=13.7.0`

---

### Modos de uso

#### 1. Auditoría completa por target (discovery OIDC automático)

```bash
vamp-oauth-audit --target auth.ejemplo.com
```

Construye automáticamente `https://auth.ejemplo.com/.well-known/openid-configuration`,
analiza la configuración del servidor y sondea el token endpoint descubierto.

#### 2. Análisis de URL de autorización OAuth

```bash
vamp-oauth-audit --auth-url "https://auth.ejemplo.com/oauth/authorize?response_type=code&client_id=mi-app&redirect_uri=https://app.com/callback"
```

Detecta ausencia de PKCE, state, implicit flow, redirect_uri insegura y combinaciones de scopes peligrosas.

#### 3. Inspección de tokens JWT

```bash
vamp-oauth-audit \
  --access-token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... \
  --id-token eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... \
  --client-id mi-app-id
```

Decodifica los tokens (sin verificar firma) y detecta alg=none, TTL excesivo, PII en claims y audience incorrecta.

#### 4. Auditoría con proxy (Burp Suite / OWASP ZAP)

```bash
vamp-oauth-audit \
  --target auth.ejemplo.com \
  --proxy http://127.0.0.1:8080 \
  --no-ssl-verify
```

Enruta el tráfico a través del proxy configurado para análisis manual paralelo.

#### 5. Informe completo con salida HTML y JSON

```bash
vamp-oauth-audit \
  --target auth.ejemplo.com \
  --auth-url "https://auth.ejemplo.com/authorize?client_id=app&response_type=token" \
  --access-token eyJhbG... \
  --html informe_oauth.html \
  --json hallazgos.json \
  --min-severity HIGH
```

---

### Tabla de findings detectados

| ID         | Severidad | Fase          | Descripción                                              |
|------------|-----------|---------------|----------------------------------------------------------|
| OAUTH-000  | INFO      | Discovery     | Sin endpoint de descubrimiento OIDC                      |
| OAUTH-001  | HIGH      | Discovery     | Servidor no anuncia soporte PKCE S256                    |
| OAUTH-002  | MEDIUM    | Discovery     | Implicit flow soportado por el servidor                  |
| OAUTH-003  | HIGH      | Discovery     | Servidor acepta clientes públicos sin autenticación      |
| OAUTH-004  | HIGH      | Discovery     | ROPC grant soportado (OWASP API8:2023)                  |
| OAUTH-005  | CRITICAL  | Discovery     | Token endpoint sin TLS                                   |
| OAUTH-010  | CRITICAL  | Auth URL      | Parámetro state ausente — flujo vulnerable a CSRF        |
| OAUTH-011  | HIGH      | Auth URL      | PKCE no utilizado — vulnerable a code interception       |
| OAUTH-012  | HIGH      | Auth URL      | Implicit flow detectado (obsoleto en OAuth 2.1)          |
| OAUTH-013  | HIGH      | Auth URL      | id_token en frontchannel — riesgo de token leakage       |
| OAUTH-014  | MEDIUM    | Auth URL      | redirect_uri no especificada                             |
| OAUTH-015  | HIGH      | Auth URL      | redirect_uri sin TLS                                     |
| OAUTH-016  | MEDIUM    | Auth URL      | redirect_uri a localhost (¿entorno de desarrollo?)       |
| OAUTH-017  | MEDIUM    | Auth URL      | Combinación de scopes de alto privilegio                 |
| OAUTH-018  | LOW       | Auth URL      | Silent authentication — posible SSO bypass               |
| OAUTH-019  | INFO      | Auth URL      | client_id con patrón de entorno de pruebas               |
| OAUTH-020  | CRITICAL  | Auth URL      | Authorization endpoint sin TLS                           |
| OAUTH-030  | CRITICAL  | Tokens        | Token con alg=none — firma ignorada por diseño           |
| OAUTH-031  | HIGH      | Tokens        | Token sin claim de expiración (exp)                      |
| OAUTH-032  | MEDIUM    | Tokens        | TTL del token superior a 24 horas                        |
| OAUTH-033  | MEDIUM    | Tokens        | PII expuesta en claims del token                         |
| OAUTH-034  | HIGH      | Tokens        | Token con scopes de alto privilegio                      |
| OAUTH-035  | MEDIUM    | Tokens        | id_token sin nonce — vulnerable a replay                 |
| OAUTH-036  | HIGH      | Tokens        | Audience del token no coincide con client_id             |
| OAUTH-037  | INFO      | Tokens        | Access token firmado con HMAC simétrico                  |
| OAUTH-040  | MEDIUM    | Token EP      | Token endpoint acepta GET                                |
| OAUTH-041  | MEDIUM    | Token EP      | CORS wildcard en token endpoint                          |
| OAUTH-042  | LOW       | Token EP      | HSTS no configurado en token endpoint                    |
| OAUTH-043  | HIGH      | Token EP      | Información de depuración expuesta en errores            |
| OAUTH-044  | CRITICAL  | Token EP      | Token endpoint sin TLS (confirmado activamente)          |
| OAUTH-050  | CRITICAL  | Redirect URI  | Open redirect — servidor acepta redirect_uri arbitraria  |
| OAUTH-051  | HIGH      | Redirect URI  | Bypass de validación redirect_uri con URL encoding       |

---

### Variables de entorno

| Variable                    | Descripción                          |
|-----------------------------|--------------------------------------|
| `HTTP_PROXY` / `HTTPS_PROXY` | Proxy de red (respetado automáticamente con `--no-ssl-verify`) |

---

### Ejemplo de salida en consola

```
╭──────────────────────────────────────────────────────────────────╮
│ vamp-oauth-audit v1.2 · VampSecure Labs Security Research Division│
╰──────────────────────────────────────────────────────────────────╯

Fase 1 — OIDC Discovery
  → GET https://auth.ejemplo.com/.well-known/openid-configuration

Fase 2 — Análisis URL de autorización

Fase 4 — Sondeo activo token endpoint
  → Sondeo activo: https://auth.ejemplo.com/token

╭─────────────────────────────── Hallazgos ────────────────────────────────╮
│ ID          │ Sev.      │ Fase      │ Descripción                        │
│ OAUTH-001   │ 🔴 HIGH   │ Discovery │ Servidor no anuncia soporte PKCE   │
│ OAUTH-010   │ 💀 CRIT   │ Auth URL  │ Parámetro state ausente            │
│ OAUTH-042   │ 🔵 LOW    │ Token EP  │ HSTS no configurado                │
╰──────────────────────────────────────────────────────────────────────────╯

┌─ Calificación global: D ─┐

Total: 3 hallazgos — CRITICAL=0 HIGH=1 MEDIUM=0 LOW=1 INFO=0
```

---

### Sample Output

```bash
$ vamp-oauth-audit --target auth.example.com \
    --auth-url "https://auth.example.com/authorize?client_id=web-app&response_type=token&redirect_uri=http://192.168.1.10/callback" \
    --access-token eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIiwiZXhwIjo5OTk5OTk5OTk5fQ. \
    --json hallazgos.json
```

```
╭──────────────────────────────────────────────────────────────────────────────╮
│  vamp-oauth-audit v1.2 · VampSecure Labs Security Research Division          │
╰──────────────────────────────────────────────────────────────────────────────╯

Fase 1 — OIDC Discovery
  → GET https://auth.example.com/.well-known/openid-configuration  [200 OK]
  ✓ Discovery document found — 14 campos analizados

Fase 2 — Análisis URL de autorización
  ⚠ response_type=token detectado (implicit flow)
  ⚠ Parámetro state ausente
  ⚠ redirect_uri sin TLS (http://)

Fase 3 — Inspección de tokens JWT
  ✗ alg=none — firma ignorada por diseño
  ✗ PII detectada en claims: email
  ✗ exp = 2286-11-20 (TTL de 8.400 días)

Fase 4 — Sondeo activo token endpoint
  → POST https://auth.example.com/oauth/token  [401 Unauthorized]
  ⚠ CORS wildcard detectado (Access-Control-Allow-Origin: *)

╭─────────────────────────────────── Hallazgos ────────────────────────────────────╮
│ ID         │ Sev.      │ Fase      │ Descripción                                  │
│ OAUTH-030  │ 💀 CRIT   │ Tokens    │ Token con alg=none — firma ignorada          │
│ OAUTH-010  │ 💀 CRIT   │ Auth URL  │ Parámetro state ausente — CSRF              │
│ OAUTH-012  │ 🔴 HIGH   │ Auth URL  │ Implicit flow detectado (obsoleto OAuth 2.1) │
│ OAUTH-015  │ 🔴 HIGH   │ Auth URL  │ redirect_uri sin TLS                        │
│ OAUTH-033  │ 🟠 MEDIUM │ Tokens    │ PII expuesta en claims (email)              │
│ OAUTH-032  │ 🟠 MEDIUM │ Tokens    │ TTL del token superior a 24 horas           │
│ OAUTH-041  │ 🟠 MEDIUM │ Token EP  │ CORS wildcard en token endpoint             │
╰──────────────────────────────────────────────────────────────────────────────────╯

┌─ Calificación global: F ─────────────────────────────────────────────────────────┐
│  Total: 7 hallazgos — CRITICAL=2  HIGH=2  MEDIUM=3  LOW=0  INFO=0              │
└──────────────────────────────────────────────────────────────────────────────────┘

Informe JSON → hallazgos.json
```

---

### Why vamp-oauth-audit vs. Burp Suite OAuth scanner · PortSwigger Web Academy tools · oauth2_proxy audit

| Capacidad | vamp-oauth-audit | Burp Suite OAuth scanner | oauth2_proxy audit |
|---|---|---|---|
| Comprobación PKCE enforcement (RFC 7636) | ✅ | ✅ | ❌ |
| Análisis de discovery OIDC | ✅ | ✅ | ❌ |
| Detección JWT alg=none + PII en claims | ✅ | ❌ | ❌ |
| Sondeo activo del token endpoint | ✅ | ✅ | ❌ |
| Open redirect en redirect_uri | ✅ | ✅ | ❌ |
| Detección de implicit flow | ✅ | ✅ | ❌ |
| Audience mismatch + nonce replay | ✅ | ❌ | ❌ |
| Self-hosted sin licencia comercial | ✅ | ❌ (comercial) | ✅ |
| JSON + HTML para CI/CD | ✅ | ❌ | ❌ |
| AGPL / código abierto | ✅ | ❌ | ✅ |

- Cobertura completa del ciclo OAuth: desde el discovery OIDC hasta la validación activa del token endpoint, en un único comando sin proxy ni browser.
- Los checks de JWT (alg=none, PII en claims, audience mismatch, TTL excesivo) van más allá de lo que cubren los scanners de proxy genéricos.
- Salida JSON normalizada al esquema VSL, lista para ingerir con `vamp-penreport` o `vamp-orchestrator` sin pasos adicionales.
- Sin dependencias de interfaz gráfica: apto para pipelines CI/CD y entornos headless.

---

### Check Coverage

| Área | Checks incluidos | IDs representativos |
|---|---|---|
| OIDC Discovery | PKCE S256 no anunciado, implicit flow en servidor, ROPC grant habilitado, TLS en endpoints | OAUTH-001 – OAUTH-005 |
| URL de autorización — CSRF | Ausencia del parámetro `state` | OAUTH-010 |
| URL de autorización — PKCE | Ausencia de `code_challenge` / `code_challenge_method` | OAUTH-011 |
| Implicit / Hybrid flow | `response_type=token`, id_token en frontchannel | OAUTH-012, OAUTH-013 |
| Redirect URI | Sin TLS, open redirect, bypass con URL-encoding | OAUTH-015, OAUTH-050, OAUTH-051 |
| Token JWT — firma | alg=none, HMAC simétrico en token público | OAUTH-030, OAUTH-037 |
| Token JWT — claims | Sin `exp`, TTL > 24 h, PII expuesta, audience incorrecta, nonce ausente | OAUTH-031 – OAUTH-036 |
| Token Endpoint | GET aceptado, CORS wildcard, HSTS ausente, debug en respuestas de error | OAUTH-040 – OAUTH-044 |

---

### Uso ético y aviso legal

Esta herramienta está diseñada **exclusivamente para auditorías de seguridad en sistemas propios o con autorización expresa** del propietario del sistema objetivo.

El uso de vamp-oauth-audit en sistemas sin autorización puede constituir un delito informático en la mayoría de jurisdicciones. VampSecure Studios no se responsabiliza del uso indebido de esta herramienta.

**Cumplimiento recomendado:** OWASP API Security Top 10, RFC 6749, RFC 7636 (PKCE), RFC 8252 (Native Apps), OAuth 2.1 (draft-ietf-oauth-v2-1), OpenID Connect Core.

---

### Licencia

AGPL-3.0 License — © VampSecure Studios

---

### Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.2 | README bilingüe (EN/ES) |
| v1.1 | VampSecure Labs Security Research Division — versión inicial pública |

---

*© VampSecure Studios — VampSecure Labs Security Research Division*
