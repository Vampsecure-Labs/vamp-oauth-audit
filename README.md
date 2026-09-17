# vamp-oauth-audit

**OAuth 2.0 and OIDC Security Flow Auditor** — VampSecure Labs Security Research Division

Herramienta CLI para auditar configuraciones OAuth 2.0 y OIDC en busca de vulnerabilidades de seguridad.
Analiza endpoints de discovery, URLs de autorización, tokens JWT, token endpoints activos y validación de redirect_uri.

---

## Instalación

```bash
pip install vamp-oauth-audit
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
│ vamp-oauth-audit v1.0 · VampSecure Labs Security Research Division│
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

## Uso ético y aviso legal

Esta herramienta está diseñada **exclusivamente para auditorías de seguridad en sistemas propios o con autorización expresa** del propietario del sistema objetivo.

El uso de vamp-oauth-audit en sistemas sin autorización puede constituir un delito informático en la mayoría de jurisdicciones. VampSecure Studios no se responsabiliza del uso indebido de esta herramienta.

**Cumplimiento recomendado:** OWASP API Security Top 10, RFC 6749, RFC 7636 (PKCE), RFC 8252 (Native Apps), OAuth 2.1 (draft-ietf-oauth-v2-1), OpenID Connect Core.

---

## Licencia

MIT License — © VampSecure Studios

---

*© VampSecure Studios — VampSecure Labs Security Research Division*
