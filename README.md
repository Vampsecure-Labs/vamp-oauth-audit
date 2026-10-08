<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->

  <img src="https://github.com/Vampsecure-Labs/vamp-oauth-audit/actions/workflows/ci.yml/badge.svg" alt="CI"/>
# vamp-oauth-audit

**OAuth 2.0 and OIDC Security Flow Auditor** — VampSecure Labs Security Research Division

Herramienta CLI para auditar configuraciones OAuth 2.0 y OIDC en busca de vulnerabilidades de seguridad.
Analiza endpoints de discovery, URLs de autorización, tokens JWT, token endpoints activos y validación de redirect_uri.

---

## Instalación

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

## Modos de uso

### 1. Auditoría completa por target (discovery OIDC automático)

```bash
vamp-oauth-audit --target auth.ejemplo.com
```

Construye automáticamente `https://auth.ejemplo.com/.well-known/openid-configuration`,
analiza la configuración del servidor y sondea el token endpoint descubierto.

### 2. Análisis de URL de autorización OAuth

```bash
vamp-oauth-audit --auth-url "https://auth.ejemplo.com/oauth/authorize?response_type=code&client_id=mi-app&redirect_uri=https://app.com/callback"
```

Detecta ausencia de PKCE, state, implicit flow, redirect_uri insegura y combinaciones de scopes peligrosas.

### 3. Inspección de tokens JWT

```bash
vamp-oauth-audit \
  --access-token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... \
  --id-token eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... \
  --client-id mi-app-id
```

Decodifica los tokens (sin verificar firma) y detecta alg=none, TTL excesivo, PII en claims y audience incorrecta.

### 4. Auditoría con proxy (Burp Suite / OWASP ZAP)

```bash
vamp-oauth-audit \
  --target auth.ejemplo.com \
  --proxy http://127.0.0.1:8080 \
  --no-ssl-verify
```

Enruta el tráfico a través del proxy configurado para análisis manual paralelo.

### 5. Informe completo con salida HTML y JSON

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

## Tabla de findings detectados

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

## Variables de entorno

| Variable                    | Descripción                          |
|-----------------------------|--------------------------------------|
| `HTTP_PROXY` / `HTTPS_PROXY` | Proxy de red (respetado automáticamente con `--no-ssl-verify`) |

---

## Ejemplo de salida en consola

```
╭──────────────────────────────────────────────────────────────────╮
│ vamp-oauth-audit v1.1 · VampSecure Labs Security Research Division│
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

## Sample Output

```bash
$ vamp-oauth-audit --target auth.example.com \
    --auth-url "https://auth.example.com/authorize?client_id=web-app&response_type=token&redirect_uri=http://192.168.1.10/callback" \
    --access-token eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiZW1haWwiOiJ1c2VyQGV4YW1wbGUuY29tIiwiZXhwIjo5OTk5OTk5OTk5fQ. \
    --json hallazgos.json
```

```
╭──────────────────────────────────────────────────────────────────────────────╮
│  vamp-oauth-audit v1.1 · VampSecure Labs Security Research Division          │
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

## Why vamp-oauth-audit vs. Burp Suite OAuth scanner · PortSwigger Web Academy tools · oauth2_proxy audit

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

## Check Coverage

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

## Uso ético y aviso legal

Esta herramienta está diseñada **exclusivamente para auditorías de seguridad en sistemas propios o con autorización expresa** del propietario del sistema objetivo.

El uso de vamp-oauth-audit en sistemas sin autorización puede constituir un delito informático en la mayoría de jurisdicciones. VampSecure Studios no se responsabiliza del uso indebido de esta herramienta.

**Cumplimiento recomendado:** OWASP API Security Top 10, RFC 6749, RFC 7636 (PKCE), RFC 8252 (Native Apps), OAuth 2.1 (draft-ietf-oauth-v2-1), OpenID Connect Core.

---

## Licencia

AGPL-3.0 License — © VampSecure Studios

---

*© VampSecure Studios — VampSecure Labs Security Research Division*

---

## Versión
v1.1 — VampSecure Labs Security Research Division
