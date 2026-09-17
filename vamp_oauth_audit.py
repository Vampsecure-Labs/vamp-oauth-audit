# © VampSecure Studios — VampSecure Labs Security Research Division
"""
vamp-oauth-audit v1.0
Auditor de flujos OAuth 2.0 y OIDC.
Detecta vulnerabilidades en configuraciones de autorización, tokens JWT,
endpoints activos y validación de redirect_uri.

Uso: vamp-oauth-audit [opciones]
Autor: VampSecure Studios
"""

import argparse
import asyncio
import base64
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse, urlencode, quote

import aiohttp
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.padding import Padding

# ─────────────────────────────────────────────────────────────────────────────
# Constantes
# ─────────────────────────────────────────────────────────────────────────────

VERSION = "1.0"
BANNER = f"[bold red]vamp-oauth-audit[/bold red] [dim]v{VERSION}[/dim] · [dim]VampSecure Labs Security Research Division[/dim]"

# Colores por severidad para Rich
COLORES_SEVERIDAD: Dict[str, str] = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim white",
}

# Iconos por severidad
ICONOS_SEVERIDAD: Dict[str, str] = {
    "CRITICAL": "💀",
    "HIGH": "🔴",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "ℹ️",
}

console = Console(stderr=False)


# ─────────────────────────────────────────────────────────────────────────────
# Dataclass principal de hallazgos
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Hallazgo:
    """Representa un hallazgo de seguridad detectado durante la auditoría."""
    id: str
    severidad: str        # CRITICAL, HIGH, MEDIUM, LOW, INFO
    fase: str
    descripcion: str
    detalle: str = ""
    remediacion: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Decodificación JWT (solo inspección, sin verificar firma)
# ─────────────────────────────────────────────────────────────────────────────

def decodificar_jwt(token: str) -> Tuple[Dict, Dict]:
    """Decodifica header y payload de un JWT sin verificar la firma."""
    partes = token.split(".")
    if len(partes) < 2:
        raise ValueError("Token JWT inválido: menos de 2 partes")

    def b64_decode(s: str) -> Dict:
        # Normalizar base64url a base64 estándar y agregar padding
        s = s.replace("-", "+").replace("_", "/")
        s += "=" * (4 - len(s) % 4)
        return json.loads(base64.b64decode(s).decode("utf-8", errors="replace"))

    return b64_decode(partes[0]), b64_decode(partes[1])


# ─────────────────────────────────────────────────────────────────────────────
# Fase 1 — OIDC Discovery
# ─────────────────────────────────────────────────────────────────────────────

async def fase_discovery(
    session: aiohttp.ClientSession,
    args: argparse.Namespace,
) -> Tuple[List[Hallazgo], Dict[str, Any]]:
    """
    Fase 1: Interroga el endpoint de descubrimiento OIDC (.well-known/openid-configuration).
    Analiza la configuración anunciada por el servidor en busca de configuraciones inseguras.
    """
    hallazgos: List[Hallazgo] = []
    estado: Dict[str, Any] = {}

    # Determinar URL de discovery
    discovery_url = getattr(args, "discovery_url", None)
    if not discovery_url and getattr(args, "target", None):
        discovery_url = f"https://{args.target}/.well-known/openid-configuration"

    if not discovery_url:
        return hallazgos, estado

    console.print(f"  [dim]→ GET {discovery_url}[/dim]")

    try:
        async with session.get(discovery_url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status != 200:
                hallazgos.append(Hallazgo(
                    id="OAUTH-000",
                    severidad="INFO",
                    fase="Discovery",
                    descripcion="Sin endpoint de descubrimiento OIDC",
                    detalle=f"El endpoint {discovery_url} respondió con HTTP {resp.status}.",
                    remediacion="Si el servidor soporta OIDC, exponer /.well-known/openid-configuration facilita la auditoría y la interoperabilidad.",
                ))
                return hallazgos, estado

            try:
                config = await resp.json(content_type=None)
            except Exception as exc:
                hallazgos.append(Hallazgo(
                    id="OAUTH-000",
                    severidad="INFO",
                    fase="Discovery",
                    descripcion="Sin endpoint de descubrimiento OIDC",
                    detalle=f"Respuesta no parseable como JSON: {exc}",
                    remediacion="Verificar que el endpoint retorna JSON válido con Content-Type application/json.",
                ))
                return hallazgos, estado

    except aiohttp.ClientError as exc:
        hallazgos.append(Hallazgo(
            id="OAUTH-000",
            severidad="INFO",
            fase="Discovery",
            descripcion="Sin endpoint de descubrimiento OIDC",
            detalle=f"Error de red al acceder a {discovery_url}: {exc}",
            remediacion="Verificar que el servidor es alcanzable y el endpoint está configurado.",
        ))
        return hallazgos, estado
    except asyncio.TimeoutError:
        hallazgos.append(Hallazgo(
            id="OAUTH-000",
            severidad="INFO",
            fase="Discovery",
            descripcion="Sin endpoint de descubrimiento OIDC",
            detalle=f"Timeout al conectar con {discovery_url}.",
            remediacion="Verificar conectividad con el servidor.",
        ))
        return hallazgos, estado

    # Almacenar datos relevantes en el estado compartido
    for clave in (
        "authorization_endpoint", "token_endpoint", "userinfo_endpoint",
        "jwks_uri", "issuer", "end_session_endpoint", "introspection_endpoint",
    ):
        if clave in config:
            estado[clave] = config[clave]

    estado["discovery_config"] = config

    # ── Comprobación PKCE S256 ──────────────────────────────────────────────
    metodos_pkce = config.get("code_challenge_methods_supported", [])
    if "S256" not in metodos_pkce:
        hallazgos.append(Hallazgo(
            id="OAUTH-001",
            severidad="HIGH",
            fase="Discovery",
            descripcion="Servidor no anuncia soporte PKCE S256",
            detalle=(
                f"code_challenge_methods_supported = {metodos_pkce!r}. "
                "Sin S256 los clientes públicos no pueden usar PKCE correctamente."
            ),
            remediacion=(
                "Habilitar PKCE con método S256 (RFC 7636). "
                "Rechazar solicitudes de clientes públicos que no incluyan code_challenge."
            ),
        ))

    # ── Implicit flow ───────────────────────────────────────────────────────
    tipos_respuesta = config.get("response_types_supported", [])
    if "token" in tipos_respuesta:
        hallazgos.append(Hallazgo(
            id="OAUTH-002",
            severidad="MEDIUM",
            fase="Discovery",
            descripcion="Implicit flow soportado por el servidor",
            detalle=(
                f"response_types_supported incluye 'token'. "
                "El implicit flow expone access_tokens en la URL (fragment) y es obsoleto en OAuth 2.1."
            ),
            remediacion=(
                "Deshabilitar response_type=token. "
                "Migrar clientes a Authorization Code + PKCE (RFC 9700)."
            ),
        ))

    # ── Clientes sin autenticación ──────────────────────────────────────────
    metodos_auth = config.get("token_endpoint_auth_methods_supported", [])
    if "none" in metodos_auth:
        hallazgos.append(Hallazgo(
            id="OAUTH-003",
            severidad="HIGH",
            fase="Discovery",
            descripcion="Servidor acepta clientes públicos sin autenticación",
            detalle=(
                f"token_endpoint_auth_methods_supported = {metodos_auth!r}. "
                "El método 'none' permite que cualquier cliente obtenga tokens sin credenciales."
            ),
            remediacion=(
                "Restringir 'none' solo a clientes públicos registrados explícitamente. "
                "Exigir PKCE para todos los clientes sin client_secret."
            ),
        ))

    # ── ROPC grant (OWASP API8:2023) ────────────────────────────────────────
    grant_types = config.get("grant_types_supported", [])
    if "password" in grant_types:
        hallazgos.append(Hallazgo(
            id="OAUTH-004",
            severidad="HIGH",
            fase="Discovery",
            descripcion="ROPC grant soportado (OWASP API8:2023)",
            detalle=(
                "grant_types_supported incluye 'password' (Resource Owner Password Credentials). "
                "Este flujo expone las credenciales del usuario al cliente y está deprecado en OAuth 2.1."
            ),
            remediacion=(
                "Deshabilitar el grant type 'password'. "
                "Migrar a Authorization Code + PKCE. "
                "Referencia: OWASP API Security Top 10 2023 — API8: Security Misconfiguration."
            ),
        ))

    # ── Token endpoint sin TLS ──────────────────────────────────────────────
    token_ep = config.get("token_endpoint", "")
    if token_ep.startswith("http://"):
        hallazgos.append(Hallazgo(
            id="OAUTH-005",
            severidad="CRITICAL",
            fase="Discovery",
            descripcion="Token endpoint sin TLS",
            detalle=f"token_endpoint = {token_ep!r} — transmisión de tokens en claro.",
            remediacion=(
                "Configurar TLS en el token endpoint (HTTPS obligatorio por RFC 6749 §3.1). "
                "Redirigir el tráfico HTTP a HTTPS."
            ),
        ))

    return hallazgos, estado


# ─────────────────────────────────────────────────────────────────────────────
# Fase 2 — Análisis de la URL de autorización
# ─────────────────────────────────────────────────────────────────────────────

def fase_auth_url(
    url_str: str,
    estado: Dict[str, Any],
) -> List[Hallazgo]:
    """
    Fase 2: Analiza una URL de autorización OAuth 2.0 en busca de parámetros inseguros,
    ausencia de PKCE, implicit flow, redirect_uri insegura y combinaciones de scopes peligrosas.
    """
    hallazgos: List[Hallazgo] = []

    try:
        parsed = urlparse(url_str)
        params = parse_qs(parsed.query, keep_blank_values=True)
    except Exception as exc:
        return hallazgos

    def param(key: str) -> Optional[str]:
        """Retorna el primer valor del parámetro o None."""
        vals = params.get(key)
        return vals[0] if vals else None

    # ── CSRF: parámetro state ───────────────────────────────────────────────
    if not param("state"):
        hallazgos.append(Hallazgo(
            id="OAUTH-010",
            severidad="CRITICAL",
            fase="Auth URL",
            descripcion="Parámetro state ausente — flujo vulnerable a CSRF",
            detalle=(
                "La ausencia de 'state' permite ataques de tipo CSRF y confusión de sesión. "
                "Un atacante puede inyectar su código de autorización en la sesión de la víctima."
            ),
            remediacion=(
                "Incluir siempre un parámetro 'state' generado con entropía criptográfica (≥128 bits). "
                "Validarlo al recibir el callback. RFC 6749 §10.12."
            ),
        ))

    # ── PKCE ────────────────────────────────────────────────────────────────
    if not param("code_challenge"):
        hallazgos.append(Hallazgo(
            id="OAUTH-011",
            severidad="HIGH",
            fase="Auth URL",
            descripcion="PKCE no utilizado — vulnerable a code interception",
            detalle=(
                "Sin code_challenge, un atacante que intercepte el authorization code "
                "(p.ej. por malicious app o log leakage) puede canjearlo por tokens."
            ),
            remediacion=(
                "Implementar PKCE (RFC 7636) con method=S256. "
                "Generar code_verifier de 43-128 caracteres aleatorios, "
                "calcular code_challenge = BASE64URL(SHA256(code_verifier))."
            ),
        ))

    # ── Implicit flow ───────────────────────────────────────────────────────
    response_type = param("response_type") or ""
    if response_type in ("token", "id_token token"):
        hallazgos.append(Hallazgo(
            id="OAUTH-012",
            severidad="HIGH",
            fase="Auth URL",
            descripcion="Implicit flow detectado (obsoleto en OAuth 2.1)",
            detalle=(
                f"response_type={response_type!r}. "
                "El implicit flow expone el token en el fragment de la URL, "
                "lo que puede filtrarse en logs de servidor, Referer headers o historial del navegador."
            ),
            remediacion=(
                "Migrar a Authorization Code + PKCE. "
                "El implicit flow está eliminado en OAuth 2.1 (draft-ietf-oauth-v2-1)."
            ),
        ))

    # ── id_token en frontchannel (hybrid flow) ──────────────────────────────
    if "id_token" in response_type and "token" not in response_type.replace("id_token", ""):
        # hybrid: response_type contiene id_token directamente
        if response_type not in ("token", "id_token token"):  # evitar doble reporte
            hallazgos.append(Hallazgo(
                id="OAUTH-013",
                severidad="HIGH",
                fase="Auth URL",
                descripcion="id_token en frontchannel — riesgo de token leakage",
                detalle=(
                    f"response_type={response_type!r} expone id_token en el fragment de la URL. "
                    "Esto puede filtrar información personal del usuario (claims PII) "
                    "a través de logs, proxies o extensiones de navegador."
                ),
                remediacion=(
                    "Usar response_type=code y obtener id_token desde el token endpoint (backchannel). "
                    "Evitar hybrid flows donde el id_token viaja en el frontchannel."
                ),
            ))

    # ── redirect_uri ausente ────────────────────────────────────────────────
    redirect_uri = param("redirect_uri") or ""
    if not redirect_uri:
        hallazgos.append(Hallazgo(
            id="OAUTH-014",
            severidad="MEDIUM",
            fase="Auth URL",
            descripcion="redirect_uri no especificada",
            detalle=(
                "Omitir redirect_uri delega la selección al servidor, "
                "que podría usar cualquier URI registrada. "
                "Facilita ataques si el cliente tiene múltiples URIs registradas."
            ),
            remediacion=(
                "Siempre especificar redirect_uri de forma explícita. "
                "El servidor debe validarla contra la lista de URIs registradas (coincidencia exacta)."
            ),
        ))
    else:
        # ── redirect_uri sin TLS (no localhost) ─────────────────────────────
        parsed_redir = urlparse(redirect_uri)
        es_localhost = parsed_redir.hostname in ("localhost", "127.0.0.1", "::1")
        if redirect_uri.startswith("http://") and not es_localhost:
            hallazgos.append(Hallazgo(
                id="OAUTH-015",
                severidad="HIGH",
                fase="Auth URL",
                descripcion="redirect_uri sin TLS",
                detalle=(
                    f"redirect_uri={redirect_uri!r} — el authorization code viajará en claro "
                    "y puede ser interceptado en la red."
                ),
                remediacion=(
                    "Usar HTTPS en todos los redirect_uri de producción. "
                    "La única excepción permitida es 'http://localhost' para apps nativas (RFC 8252)."
                ),
            ))

        # ── redirect_uri a localhost ─────────────────────────────────────────
        if es_localhost:
            hallazgos.append(Hallazgo(
                id="OAUTH-016",
                severidad="MEDIUM",
                fase="Auth URL",
                descripcion="redirect_uri a localhost (¿entorno de desarrollo?)",
                detalle=(
                    f"redirect_uri={redirect_uri!r}. "
                    "Las URIs localhost son válidas para apps nativas (RFC 8252) "
                    "pero no deben usarse en producción web."
                ),
                remediacion=(
                    "Verificar que este flujo es solo para apps nativas/desktop. "
                    "En producción web usar URIs HTTPS registradas."
                ),
            ))

    # ── Scopes de alto privilegio ────────────────────────────────────────────
    scope_str = param("scope") or ""
    scopes = set(scope_str.lower().split())
    combis_peligrosas = [
        ({"offline_access", "write"}, "offline_access + write"),
        ({"admin", "full"}, "admin + full"),
    ]
    for combo, nombre in combis_peligrosas:
        if combo.issubset(scopes):
            hallazgos.append(Hallazgo(
                id="OAUTH-017",
                severidad="MEDIUM",
                fase="Auth URL",
                descripcion="Combinación de scopes de alto privilegio",
                detalle=(
                    f"Se detectó la combinación '{nombre}' en scope={scope_str!r}. "
                    "Acceso offline con escritura o permisos administrativos amplios "
                    "aumenta el impacto de un token comprometido."
                ),
                remediacion=(
                    "Aplicar principio de mínimo privilegio. "
                    "Solicitar solo los scopes estrictamente necesarios para la operación."
                ),
            ))

    # ── Silent authentication ────────────────────────────────────────────────
    if param("prompt") == "none":
        hallazgos.append(Hallazgo(
            id="OAUTH-018",
            severidad="LOW",
            fase="Auth URL",
            descripcion="Silent authentication — posible SSO bypass",
            detalle=(
                "prompt=none indica autenticación silenciosa (sin interacción del usuario). "
                "Si el servidor no valida correctamente la sesión, "
                "un atacante podría obtener tokens sin conocimiento del usuario."
            ),
            remediacion=(
                "Asegurar que el servidor verifica la sesión activa de forma estricta con prompt=none. "
                "Auditar que no existe bypass de MFA ni de step-up authentication."
            ),
        ))

    # ── client_id de entorno de pruebas ─────────────────────────────────────
    client_id = param("client_id") or ""
    patrones_test = ["test", "demo", "sample", "example"]
    if any(p in client_id.lower() for p in patrones_test):
        hallazgos.append(Hallazgo(
            id="OAUTH-019",
            severidad="INFO",
            fase="Auth URL",
            descripcion="client_id con patrón de entorno de pruebas",
            detalle=(
                f"client_id={client_id!r} contiene un patrón de prueba. "
                "Puede indicar que se está usando una aplicación de desarrollo en producción."
            ),
            remediacion=(
                "Usar client_ids de producción distintos de los de desarrollo/test. "
                "Revisar los permisos asignados a este cliente."
            ),
        ))

    # ── Authorization endpoint sin TLS ──────────────────────────────────────
    if url_str.startswith("http://"):
        hallazgos.append(Hallazgo(
            id="OAUTH-020",
            severidad="CRITICAL",
            fase="Auth URL",
            descripcion="Authorization endpoint sin TLS",
            detalle=(
                "La URL de autorización usa HTTP. "
                "El state, code_challenge y redirect_uri viajan en claro, "
                "permitiendo ataques MITM."
            ),
            remediacion=(
                "Usar exclusivamente HTTPS para el authorization endpoint. "
                "RFC 6749 §3.1 exige TLS para todos los endpoints OAuth."
            ),
        ))

    return hallazgos


# ─────────────────────────────────────────────────────────────────────────────
# Fase 3 — Análisis de tokens JWT
# ─────────────────────────────────────────────────────────────────────────────

def fase_tokens(args: argparse.Namespace) -> List[Hallazgo]:
    """
    Fase 3: Decodifica e inspecciona access_token e id_token JWT.
    Detecta algoritmos inseguros, ausencia de expiración, PII en claims,
    scopes de alto privilegio y vulnerabilidades en id_token.
    """
    hallazgos: List[Hallazgo] = []

    # Recopilar tokens a analizar
    tokens_a_analizar: List[Tuple[str, str]] = []
    if getattr(args, "access_token", None):
        tokens_a_analizar.append(("access_token", args.access_token))
    if getattr(args, "id_token", None):
        tokens_a_analizar.append(("id_token", args.id_token))

    if not tokens_a_analizar:
        return hallazgos

    for tipo_token, token in tokens_a_analizar:
        try:
            header, payload = decodificar_jwt(token)
        except (ValueError, Exception) as exc:
            console.print(f"  [yellow]⚠ No se pudo decodificar {tipo_token}: {exc}[/yellow]")
            continue

        alg = header.get("alg", "")

        # ── alg=none ────────────────────────────────────────────────────────
        if str(alg).lower() == "none":
            hallazgos.append(Hallazgo(
                id="OAUTH-030",
                severidad="CRITICAL",
                fase="Tokens",
                descripcion=f"Token con alg=none — firma ignorada por diseño ({tipo_token})",
                detalle=(
                    f"El {tipo_token} declara alg=none. "
                    "Si el servidor acepta este token, la firma no se verifica en absoluto, "
                    "permitiendo falsificación arbitraria."
                ),
                remediacion=(
                    "Rechazar explícitamente tokens con alg=none en la librería de validación. "
                    "Especificar siempre los algoritmos permitidos (allowedAlgorithms). "
                    "CVE-2015-9235 y variantes similares."
                ),
            ))

        # ── Sin claim exp ────────────────────────────────────────────────────
        if "exp" not in payload:
            hallazgos.append(Hallazgo(
                id="OAUTH-031",
                severidad="HIGH",
                fase="Tokens",
                descripcion=f"Token sin claim de expiración (exp) [{tipo_token}]",
                detalle=(
                    f"El {tipo_token} no incluye el claim 'exp'. "
                    "Un token sin expiración es válido indefinidamente si no hay revocación."
                ),
                remediacion=(
                    "Incluir siempre el claim 'exp' con un TTL razonable. "
                    "Implementar revocación de tokens (token introspection o blacklist)."
                ),
            ))
        else:
            # ── TTL > 24 horas ───────────────────────────────────────────────
            exp = payload.get("exp", 0)
            iat = payload.get("iat", 0)
            ttl = exp - iat
            if ttl > 86400:
                horas = ttl // 3600
                hallazgos.append(Hallazgo(
                    id="OAUTH-032",
                    severidad="MEDIUM",
                    fase="Tokens",
                    descripcion=f"TTL del token superior a 24 horas [{tipo_token}]",
                    detalle=(
                        f"El {tipo_token} tiene TTL de {horas}h ({ttl}s). "
                        "Un TTL largo amplía la ventana de ataque si el token es comprometido."
                    ),
                    remediacion=(
                        "Reducir el TTL del access_token a ≤1h. "
                        "Usar refresh_tokens de larga duración con rotación (RFC 6749 §6)."
                    ),
                ))

        # ── PII en claims ────────────────────────────────────────────────────
        claims_pii = {"email", "phone_number", "address", "birthdate", "national_id", "ssn"}
        pii_encontrada = claims_pii.intersection(set(payload.keys()))
        if pii_encontrada:
            hallazgos.append(Hallazgo(
                id="OAUTH-033",
                severidad="MEDIUM",
                fase="Tokens",
                descripcion=f"PII expuesta en claims del token [{tipo_token}]",
                detalle=(
                    f"Claims con PII detectados en {tipo_token}: {sorted(pii_encontrada)}. "
                    "Esta información puede filtrarse en logs, proxies o almacenamiento inseguro."
                ),
                remediacion=(
                    "Minimizar los claims del token. "
                    "Incluir solo el identificador de sujeto (sub) en el access_token. "
                    "Exponer PII solo a través del userinfo endpoint con validación de scope."
                ),
            ))

        # ── Scopes de alto privilegio ────────────────────────────────────────
        scope_val = payload.get("scp") or payload.get("scope") or ""
        if isinstance(scope_val, list):
            scope_str_token = " ".join(scope_val)
        else:
            scope_str_token = str(scope_val)
        scopes_token = set(scope_str_token.lower().split())
        privilegios_altos = {"admin", "write", "delete", "sudo", "root"}
        priv_encontrados = privilegios_altos.intersection(scopes_token)
        if priv_encontrados:
            hallazgos.append(Hallazgo(
                id="OAUTH-034",
                severidad="HIGH",
                fase="Tokens",
                descripcion=f"Token con scopes de alto privilegio [{tipo_token}]",
                detalle=(
                    f"Scopes de alto privilegio en {tipo_token}: {sorted(priv_encontrados)}. "
                    f"Scope completo: {scope_str_token!r}."
                ),
                remediacion=(
                    "Aplicar principio de mínimo privilegio. "
                    "Emitir tokens con solo los scopes necesarios para la operación solicitada."
                ),
            ))

        # ── Checks específicos de id_token ───────────────────────────────────
        if tipo_token == "id_token":
            # nonce ausente
            if "nonce" not in payload:
                hallazgos.append(Hallazgo(
                    id="OAUTH-035",
                    severidad="MEDIUM",
                    fase="Tokens",
                    descripcion="id_token sin nonce — vulnerable a replay",
                    detalle=(
                        "El id_token no incluye el claim 'nonce'. "
                        "Sin nonce, un atacante puede reutilizar un id_token capturado "
                        "en otra sesión (replay attack)."
                    ),
                    remediacion=(
                        "Incluir siempre el claim 'nonce' en el id_token. "
                        "El cliente debe generar un nonce aleatorio, incluirlo en la solicitud "
                        "y verificarlo en el token recibido. OIDC Core §3.1.2."
                    ),
                ))

            # Audience incorrecta
            aud = payload.get("aud")
            client_id_arg = getattr(args, "client_id", None)
            if aud is not None and client_id_arg:
                aud_list = [aud] if isinstance(aud, str) else aud
                if client_id_arg not in aud_list:
                    hallazgos.append(Hallazgo(
                        id="OAUTH-036",
                        severidad="HIGH",
                        fase="Tokens",
                        descripcion="Audience del token no coincide con client_id",
                        detalle=(
                            f"aud={aud!r} en el id_token, pero client_id={client_id_arg!r}. "
                            "Un token con audience incorrecta puede indicar confusión de destinatario "
                            "o que el token fue emitido para otro cliente."
                        ),
                        remediacion=(
                            "Validar siempre que 'aud' contiene el client_id del receptor. "
                            "Rechazar tokens con audience desconocida. OIDC Core §3.1.3.7."
                        ),
                    ))

        # ── HMAC simétrico en access_token ───────────────────────────────────
        if tipo_token == "access_token" and alg in ("HS256", "HS384", "HS512"):
            hallazgos.append(Hallazgo(
                id="OAUTH-037",
                severidad="INFO",
                fase="Tokens",
                descripcion=f"Access token firmado con HMAC simétrico ({alg})",
                detalle=(
                    f"El access_token usa alg={alg}. "
                    "Los algoritmos HMAC requieren que el resource server comparta el secreto, "
                    "lo que complica la rotación y aumenta la superficie de exposición del secreto."
                ),
                remediacion=(
                    "Considerar migrar a RS256 o ES256 (asimétrico). "
                    "Con algoritmos asimétricos, el resource server solo necesita la clave pública."
                ),
            ))

    return hallazgos


# ─────────────────────────────────────────────────────────────────────────────
# Fase 4 — Sondeo activo del token endpoint
# ─────────────────────────────────────────────────────────────────────────────

async def fase_token_endpoint(
    session: aiohttp.ClientSession,
    url: str,
    args: argparse.Namespace,
) -> List[Hallazgo]:
    """
    Fase 4: Sondeo activo del token endpoint para detectar métodos HTTP inseguros,
    CORS mal configurado, ausencia de HSTS, fuga de información en errores y TLS ausente.
    """
    hallazgos: List[Hallazgo] = []

    if not url:
        return hallazgos

    console.print(f"  [dim]→ Sondeo activo: {url}[/dim]")

    # ── GET al token endpoint ────────────────────────────────────────────────
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8), allow_redirects=False) as resp:
            if resp.status == 200:
                hallazgos.append(Hallazgo(
                    id="OAUTH-040",
                    severidad="MEDIUM",
                    fase="Token Endpoint",
                    descripcion="Token endpoint acepta GET (debe ser solo POST)",
                    detalle=(
                        f"GET {url} respondió con HTTP 200. "
                        "RFC 6749 §3.2 exige que el token endpoint use exclusivamente POST."
                    ),
                    remediacion=(
                        "Configurar el servidor para rechazar GET en el token endpoint (405 Method Not Allowed). "
                        "Solo aceptar POST con Content-Type: application/x-www-form-urlencoded."
                    ),
                ))
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass

    # ── OPTIONS (CORS) ───────────────────────────────────────────────────────
    try:
        async with session.options(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                hallazgos.append(Hallazgo(
                    id="OAUTH-041",
                    severidad="MEDIUM",
                    fase="Token Endpoint",
                    descripcion="CORS wildcard en token endpoint",
                    detalle=(
                        f"Access-Control-Allow-Origin: * en {url}. "
                        "Cualquier origen puede hacer solicitudes cross-origin al token endpoint, "
                        "lo que facilita ataques CSRF desde el navegador."
                    ),
                    remediacion=(
                        "Restringir CORS a orígenes explícitamente registrados. "
                        "No usar wildcard en endpoints que manejan tokens."
                    ),
                ))
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass

    # ── HEAD (HSTS) ──────────────────────────────────────────────────────────
    try:
        async with session.head(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
            if "Strict-Transport-Security" not in resp.headers:
                hallazgos.append(Hallazgo(
                    id="OAUTH-042",
                    severidad="LOW",
                    fase="Token Endpoint",
                    descripcion="HSTS no configurado en token endpoint",
                    detalle=(
                        f"La respuesta de {url} no incluye el header Strict-Transport-Security. "
                        "Sin HSTS, un usuario puede ser redirigido a HTTP por un atacante MITM."
                    ),
                    remediacion=(
                        "Configurar: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload. "
                        "Añadir el dominio al preload list de HSTS."
                    ),
                ))
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass

    # ── POST vacío (información de depuración en errores) ────────────────────
    try:
        async with session.post(
            url,
            data={},
            timeout=aiohttp.ClientTimeout(total=8),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        ) as resp:
            try:
                cuerpo = await resp.text(errors="replace")
            except Exception:
                cuerpo = ""

            # Buscar indicios de stack trace o paths de servidor
            patrones_debug = [
                r"Traceback \(most recent call last\)",
                r"at\s+[\w.<>]+\([\w./]+:\d+\)",  # Java/Node stack
                r"/home/|/var/www/|/usr/local/",   # paths Unix
                r"Exception in thread",
                r"NullPointerException",
                r"undefined method",
                r"File \".*\.py\", line \d+",       # Python traceback
                r"SyntaxError|TypeError|ReferenceError",  # JS errors
            ]
            for patron in patrones_debug:
                if re.search(patron, cuerpo, re.IGNORECASE):
                    hallazgos.append(Hallazgo(
                        id="OAUTH-043",
                        severidad="HIGH",
                        fase="Token Endpoint",
                        descripcion="Información de depuración expuesta en error de token endpoint",
                        detalle=(
                            f"La respuesta a POST vacío en {url} contiene trazas de depuración o rutas internas. "
                            "Esto revela detalles de la implementación que facilitan ataques dirigidos."
                        ),
                        remediacion=(
                            "Configurar el servidor para devolver solo mensajes de error genéricos en producción. "
                            "Deshabilitar modo debug. Registrar errores detallados solo en logs internos."
                        ),
                    ))
                    break
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass

    # ── Token endpoint sin TLS (confirmado activamente) ──────────────────────
    if url.startswith("http://"):
        hallazgos.append(Hallazgo(
            id="OAUTH-044",
            severidad="CRITICAL",
            fase="Token Endpoint",
            descripcion="Token endpoint sin TLS (confirmado activamente)",
            detalle=(
                f"El token endpoint {url!r} usa HTTP. "
                "Tokens, client_secrets y credenciales se transmiten en claro."
            ),
            remediacion=(
                "Migrar el token endpoint a HTTPS de forma inmediata. "
                "RFC 6749 §3.2 exige TLS en el token endpoint sin excepción."
            ),
        ))

    return hallazgos


# ─────────────────────────────────────────────────────────────────────────────
# Fase 5 — Validación de redirect_uri
# ─────────────────────────────────────────────────────────────────────────────

async def fase_redirect_uri(
    session: aiohttp.ClientSession,
    auth_endpoint: str,
    client_id: str,
) -> List[Hallazgo]:
    """
    Fase 5: Prueba si el servidor de autorización acepta redirect_uri arbitrarias
    (open redirect) o si la validación puede ser eludida con URL encoding.
    """
    hallazgos: List[Hallazgo] = []

    if not auth_endpoint or not client_id:
        return hallazgos

    console.print(f"  [dim]→ Prueba redirect_uri: {auth_endpoint}[/dim]")

    # ── Open redirect: redirect_uri arbitraria ───────────────────────────────
    uri_evil = "https://evil.vampsecure.test"
    params_evil = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": uri_evil,
        "state": "audit_test_vsl",
    }
    url_test = f"{auth_endpoint}?{urlencode(params_evil)}"

    try:
        async with session.head(
            url_test,
            timeout=aiohttp.ClientTimeout(total=8),
            allow_redirects=False,
        ) as resp:
            location = resp.headers.get("Location", "")
            if resp.status in (301, 302, 303, 307, 308) and "evil.vampsecure.test" in location:
                hallazgos.append(Hallazgo(
                    id="OAUTH-050",
                    severidad="CRITICAL",
                    fase="Redirect URI",
                    descripcion="Open redirect — servidor acepta redirect_uri arbitraria",
                    detalle=(
                        f"El servidor redirigió a {location!r} sin validar la redirect_uri. "
                        "Un atacante puede construir un enlace legítimo que roba el authorization code."
                    ),
                    remediacion=(
                        "Implementar validación estricta de redirect_uri (coincidencia exacta, no prefijo). "
                        "Registrar URIs permitidas por cliente y rechazar cualquier otra. RFC 6749 §10.6."
                    ),
                ))
            elif resp.status in (400, 401, 403):
                # El servidor rechazó correctamente — no es un hallazgo
                pass
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        console.print(f"  [dim]  ↳ Error en prueba open redirect: {exc}[/dim]")

    # ── Bypass con URL encoding ──────────────────────────────────────────────
    uri_evil_encoded = quote("https://evil.vampsecure.test", safe="")
    params_encoded = (
        f"response_type=code&client_id={quote(client_id)}"
        f"&redirect_uri={uri_evil_encoded}&state=audit_enc_vsl"
    )
    url_encoded = f"{auth_endpoint}?{params_encoded}"

    try:
        async with session.head(
            url_encoded,
            timeout=aiohttp.ClientTimeout(total=8),
            allow_redirects=False,
        ) as resp:
            location = resp.headers.get("Location", "")
            if resp.status in (301, 302, 303, 307, 308) and "evil.vampsecure.test" in location:
                hallazgos.append(Hallazgo(
                    id="OAUTH-051",
                    severidad="HIGH",
                    fase="Redirect URI",
                    descripcion="Bypass de validación redirect_uri con URL encoding",
                    detalle=(
                        f"El servidor aceptó redirect_uri con doble URL encoding: {uri_evil_encoded!r}. "
                        "La validación no normaliza la URI antes de compararla, "
                        "permitiendo eludir la lista blanca."
                    ),
                    remediacion=(
                        "Normalizar (decodificar) la redirect_uri antes de validarla. "
                        "Aplicar validación después de cualquier nivel de encoding."
                    ),
                ))
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        console.print(f"  [dim]  ↳ Error en prueba URL encoding: {exc}[/dim]")

    return hallazgos


# ─────────────────────────────────────────────────────────────────────────────
# Calificación global
# ─────────────────────────────────────────────────────────────────────────────

def compute_grade(hallazgos: List[Hallazgo]) -> str:
    """Calcula la calificación global de seguridad basada en los hallazgos."""
    conteo = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for h in hallazgos:
        conteo[h.severidad] = conteo.get(h.severidad, 0) + 1

    if conteo["CRITICAL"] > 0:
        return "F"
    if conteo["HIGH"] >= 3:
        return "D"
    if conteo["HIGH"] >= 1:
        return "C"
    if conteo["MEDIUM"] >= 3:
        return "C"
    if conteo["MEDIUM"] >= 1:
        return "B"
    if conteo["LOW"] >= 1 or conteo["INFO"] >= 1:
        return "A-"
    return "A"


# ─────────────────────────────────────────────────────────────────────────────
# Generación de informe HTML
# ─────────────────────────────────────────────────────────────────────────────

def generar_html(
    hallazgos: List[Hallazgo],
    args: argparse.Namespace,
    estado: Dict[str, Any],
) -> str:
    """
    Genera un informe HTML autocontenido con tema oscuro.
    Incluye resumen ejecutivo, estadísticas por severidad,
    tabla de hallazgos y footer de VampSecure Studios.
    """
    fecha = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    grade = compute_grade(hallazgos)
    target = getattr(args, "target", None) or getattr(args, "discovery_url", None) or "N/A"

    # Estadísticas
    conteo: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for h in hallazgos:
        conteo[h.severidad] = conteo.get(h.severidad, 0) + 1

    colores_html = {
        "CRITICAL": "#ff4444",
        "HIGH": "#ff8c00",
        "MEDIUM": "#ffd700",
        "LOW": "#00bcd4",
        "INFO": "#9e9e9e",
        "A": "#4caf50", "A-": "#8bc34a",
        "B": "#cddc39",
        "C": "#ffc107",
        "D": "#ff9800",
        "F": "#f44336",
    }
    grade_color = colores_html.get(grade, "#9e9e9e")

    # Construir filas de la tabla
    filas_html = []
    for h in hallazgos:
        color = colores_html.get(h.severidad, "#9e9e9e")
        remediacion_escaped = h.remediacion.replace("<", "&lt;").replace(">", "&gt;")
        detalle_escaped = h.detalle.replace("<", "&lt;").replace(">", "&gt;")
        descripcion_escaped = h.descripcion.replace("<", "&lt;").replace(">", "&gt;")
        filas_html.append(f"""
        <tr>
          <td><code>{h.id}</code></td>
          <td><span class="badge" style="background:{color}">{h.severidad}</span></td>
          <td>{h.fase}</td>
          <td>
            <strong>{descripcion_escaped}</strong>
            {f'<br><small class="detalle">{detalle_escaped}</small>' if detalle_escaped else ''}
          </td>
          <td><small>{remediacion_escaped}</small></td>
        </tr>""")

    filas_str = "\n".join(filas_html) if filas_html else (
        '<tr><td colspan="5" style="text-align:center;color:#4caf50">No se detectaron hallazgos</td></tr>'
    )

    # Fases únicas detectadas
    fases_detectadas = sorted(set(h.fase for h in hallazgos))

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>vamp-oauth-audit — Informe de Seguridad</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d0d0d; color: #e0e0e0; padding: 2rem; }}
  h1 {{ color: #ff4444; font-size: 1.8rem; margin-bottom: 0.25rem; }}
  h2 {{ color: #ff8c00; font-size: 1.2rem; margin: 1.5rem 0 0.75rem; border-bottom: 1px solid #333; padding-bottom: 0.4rem; }}
  .meta {{ color: #9e9e9e; font-size: 0.85rem; margin-bottom: 1.5rem; }}
  .grade {{ display: inline-block; font-size: 2.5rem; font-weight: bold; color: {grade_color};
            border: 3px solid {grade_color}; border-radius: 8px; padding: 0.2rem 0.8rem; margin-bottom: 1rem; }}
  .stats {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
  .stat-card {{ background: #1a1a1a; border-radius: 8px; padding: 0.75rem 1.25rem; text-align: center; min-width: 90px; }}
  .stat-card .num {{ font-size: 2rem; font-weight: bold; }}
  .stat-card .lbl {{ font-size: 0.75rem; color: #9e9e9e; text-transform: uppercase; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; color: #000; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
  th {{ background: #1a1a1a; color: #ff8c00; text-align: left; padding: 0.6rem 0.8rem; font-size: 0.85rem; }}
  td {{ padding: 0.6rem 0.8rem; border-bottom: 1px solid #222; font-size: 0.85rem; vertical-align: top; }}
  tr:hover td {{ background: #1a1a1a; }}
  code {{ background: #222; padding: 1px 5px; border-radius: 3px; font-size: 0.8rem; color: #ff4444; }}
  .detalle {{ color: #9e9e9e; }}
  footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #333; color: #555; font-size: 0.75rem; text-align: center; }}
  .issuer {{ background: #1a1a1a; padding: 0.5rem 1rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.85rem; }}
</style>
</head>
<body>
<h1>🔐 vamp-oauth-audit v{VERSION}</h1>
<div class="meta">
  <strong>Target:</strong> {target} &nbsp;|&nbsp;
  <strong>Fecha:</strong> {fecha} &nbsp;|&nbsp;
  <strong>Hallazgos:</strong> {len(hallazgos)}
</div>

<div class="grade">{grade}</div>

{'<div class="issuer"><strong>Issuer:</strong> ' + estado.get("issuer", "N/A") + '</div>' if estado.get("issuer") else ''}

<h2>Resumen por severidad</h2>
<div class="stats">
  <div class="stat-card"><div class="num" style="color:#ff4444">{conteo['CRITICAL']}</div><div class="lbl">Critical</div></div>
  <div class="stat-card"><div class="num" style="color:#ff8c00">{conteo['HIGH']}</div><div class="lbl">High</div></div>
  <div class="stat-card"><div class="num" style="color:#ffd700">{conteo['MEDIUM']}</div><div class="lbl">Medium</div></div>
  <div class="stat-card"><div class="num" style="color:#00bcd4">{conteo['LOW']}</div><div class="lbl">Low</div></div>
  <div class="stat-card"><div class="num" style="color:#9e9e9e">{conteo['INFO']}</div><div class="lbl">Info</div></div>
</div>

<h2>Hallazgos detectados</h2>
<table>
  <thead>
    <tr>
      <th>ID</th>
      <th>Severidad</th>
      <th>Fase</th>
      <th>Descripción / Detalle</th>
      <th>Remediación</th>
    </tr>
  </thead>
  <tbody>
{filas_str}
  </tbody>
</table>

<footer>
  © VampSecure Studios — VampSecure Labs Security Research Division<br>
  Esta herramienta es para uso exclusivo en entornos autorizados. El uso no autorizado puede constituir un delito.
</footer>
</body>
</html>"""

    return html


# ─────────────────────────────────────────────────────────────────────────────
# Punto de entrada principal
# ─────────────────────────────────────────────────────────────────────────────

def build_arg_parser() -> argparse.ArgumentParser:
    """Construye y retorna el parser de argumentos de línea de comandos."""
    p = argparse.ArgumentParser(
        prog="vamp-oauth-audit",
        description=(
            "vamp-oauth-audit v1.0 — Auditor de flujos OAuth 2.0 y OIDC\n"
            "© VampSecure Studios — VampSecure Labs Security Research Division\n\n"
            "ADVERTENCIA: Usar solo en sistemas autorizados. El uso no autorizado es ilegal."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  # Auditoría completa por discovery OIDC:
  vamp-oauth-audit --target auth.ejemplo.com

  # Analizar URL de autorización:
  vamp-oauth-audit --auth-url "https://auth.ejemplo.com/oauth/authorize?response_type=code&client_id=mi-app"

  # Inspeccionar tokens JWT:
  vamp-oauth-audit --access-token eyJhbG... --id-token eyJhbG...

  # Auditoría con proxy (Burp Suite):
  vamp-oauth-audit --target auth.ejemplo.com --proxy http://127.0.0.1:8080

  # Guardar informe completo:
  vamp-oauth-audit --target auth.ejemplo.com --html informe.html --json hallazgos.json
        """,
    )

    # Objetivo
    g_target = p.add_argument_group("Objetivo")
    g_target.add_argument("--target", metavar="HOST",
        help="Hostname o IP del servidor OAuth/OIDC (construye discovery URL automáticamente)")
    g_target.add_argument("--discovery-url", metavar="URL",
        help="URL completa del endpoint OIDC discovery (.well-known/openid-configuration)")
    g_target.add_argument("--auth-url", metavar="URL",
        help="URL de autorización a analizar (puede contener parámetros OAuth)")
    g_target.add_argument("--token-endpoint", metavar="URL",
        help="URL del token endpoint para sondeo activo")

    # Tokens
    g_tokens = p.add_argument_group("Tokens JWT")
    g_tokens.add_argument("--access-token", metavar="JWT",
        help="Access token JWT a inspeccionar")
    g_tokens.add_argument("--id-token", metavar="JWT",
        help="ID token JWT a inspeccionar")
    g_tokens.add_argument("--client-id", metavar="ID",
        help="Client ID (para validar audience del id_token y prueba de redirect_uri)")

    # Opciones de red
    g_red = p.add_argument_group("Red")
    g_red.add_argument("--proxy", metavar="URL",
        help="Proxy HTTP/HTTPS (ej: http://127.0.0.1:8080 para Burp Suite)")
    g_red.add_argument("--timeout", type=int, default=10, metavar="SEG",
        help="Timeout de red en segundos (por defecto: 10)")
    g_red.add_argument("--no-ssl-verify", action="store_true",
        help="Deshabilitar verificación de certificados SSL (uso con proxy de auditoría)")

    # Salida
    g_salida = p.add_argument_group("Salida")
    g_salida.add_argument("--html", metavar="FICHERO",
        help="Guardar informe HTML en el fichero especificado")
    g_salida.add_argument("--json", metavar="FICHERO",
        help="Guardar hallazgos en formato JSON")
    g_salida.add_argument("--min-severity", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="INFO", help="Filtrar hallazgos por severidad mínima (por defecto: INFO)")
    g_salida.add_argument("--quiet", action="store_true",
        help="Modo silencioso: solo mostrar tabla final y errores")
    g_salida.add_argument("--version", action="version", version=f"vamp-oauth-audit {VERSION}")

    return p


def filtrar_hallazgos(hallazgos: List[Hallazgo], min_severidad: str) -> List[Hallazgo]:
    """Filtra la lista de hallazgos por severidad mínima."""
    orden = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    idx_min = orden.index(min_severidad)
    return [h for h in hallazgos if orden.index(h.severidad) <= idx_min]


def mostrar_tabla_rich(hallazgos: List[Hallazgo], grade: str) -> None:
    """Renderiza la tabla de hallazgos en consola con Rich."""
    tabla = Table(
        title=f"Hallazgos — vamp-oauth-audit v{VERSION}",
        box=box.ROUNDED,
        border_style="dim",
        show_lines=True,
    )
    tabla.add_column("ID", style="bold red", no_wrap=True, width=12)
    tabla.add_column("Sev.", width=10)
    tabla.add_column("Fase", width=14)
    tabla.add_column("Descripción", min_width=35)
    tabla.add_column("Remediación", min_width=30)

    for h in hallazgos:
        color = COLORES_SEVERIDAD.get(h.severidad, "white")
        icono = ICONOS_SEVERIDAD.get(h.severidad, " ")
        tabla.add_row(
            h.id,
            Text(f"{icono} {h.severidad}", style=color),
            h.fase,
            h.descripcion,
            h.remediacion[:120] + ("…" if len(h.remediacion) > 120 else ""),
        )

    console.print(tabla)

    # Grade badge
    colores_grade = {
        "A": "bold green", "A-": "green",
        "B": "yellow", "C": "bold yellow",
        "D": "bold red", "F": "bold red on white",
    }
    estilo_grade = colores_grade.get(grade, "white")
    console.print(Padding(
        Panel(
            Text(f"Calificación global: {grade}", style=estilo_grade, justify="center"),
            border_style=estilo_grade,
            expand=False,
        ),
        (1, 0, 0, 0),
    ))


async def ejecutar_auditoria(args: argparse.Namespace) -> List[Hallazgo]:
    """
    Orquesta la ejecución de todas las fases de auditoría disponibles
    según los parámetros proporcionados.
    """
    todos_los_hallazgos: List[Hallazgo] = []
    estado: Dict[str, Any] = {}

    # Configurar conector aiohttp (proxy, SSL)
    connector_kwargs: Dict[str, Any] = {}
    if getattr(args, "no_ssl_verify", False) or getattr(args, "proxy", None):
        connector_kwargs["ssl"] = False

    proxy = getattr(args, "proxy", None)

    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(**connector_kwargs),
        trust_env=True,
        headers={"User-Agent": f"vamp-oauth-audit/{VERSION} (VampSecure Labs)"},
    ) as session:

        # ── Fase 1: Discovery ────────────────────────────────────────────────
        if getattr(args, "target", None) or getattr(args, "discovery_url", None):
            if not getattr(args, "quiet", False):
                console.print("\n[bold]Fase 1 — OIDC Discovery[/bold]")
            h_disc, estado = await fase_discovery(session, args)
            todos_los_hallazgos.extend(h_disc)

        # Fusionar token_endpoint del estado con el arg explícito
        token_endpoint_efectivo = (
            getattr(args, "token_endpoint", None)
            or estado.get("token_endpoint", "")
        )

        # ── Fase 2: Análisis URL de autorización ────────────────────────────
        auth_url = getattr(args, "auth_url", None)
        if auth_url:
            if not getattr(args, "quiet", False):
                console.print("\n[bold]Fase 2 — Análisis URL de autorización[/bold]")
            h_auth = fase_auth_url(auth_url, estado)
            todos_los_hallazgos.extend(h_auth)

        # ── Fase 3: Tokens JWT ───────────────────────────────────────────────
        if getattr(args, "access_token", None) or getattr(args, "id_token", None):
            if not getattr(args, "quiet", False):
                console.print("\n[bold]Fase 3 — Análisis de tokens JWT[/bold]")
            h_tok = fase_tokens(args)
            todos_los_hallazgos.extend(h_tok)

        # ── Fase 4: Sondeo token endpoint ────────────────────────────────────
        if token_endpoint_efectivo:
            if not getattr(args, "quiet", False):
                console.print("\n[bold]Fase 4 — Sondeo activo token endpoint[/bold]")
            h_ep = await fase_token_endpoint(session, token_endpoint_efectivo, args)
            todos_los_hallazgos.extend(h_ep)

        # ── Fase 5: Validación redirect_uri ─────────────────────────────────
        auth_endpoint = estado.get("authorization_endpoint", "")
        client_id = getattr(args, "client_id", None) or ""

        # Si hay auth_url, extraer authorization_endpoint y client_id si no están disponibles
        if not auth_endpoint and auth_url:
            parsed_auth = urlparse(auth_url)
            auth_endpoint = f"{parsed_auth.scheme}://{parsed_auth.netloc}{parsed_auth.path}"
            if not client_id:
                qp = parse_qs(parsed_auth.query)
                client_id = (qp.get("client_id") or [""])[0]

        if auth_endpoint and client_id:
            if not getattr(args, "quiet", False):
                console.print("\n[bold]Fase 5 — Validación redirect_uri[/bold]")
            h_redir = await fase_redirect_uri(session, auth_endpoint, client_id)
            todos_los_hallazgos.extend(h_redir)

    return todos_los_hallazgos


def main() -> None:
    """Punto de entrada principal de vamp-oauth-audit."""
    parser = build_arg_parser()
    args = parser.parse_args()

    # Comprobar que hay al menos un parámetro de entrada
    tiene_input = any([
        getattr(args, "target", None),
        getattr(args, "discovery_url", None),
        getattr(args, "auth_url", None),
        getattr(args, "access_token", None),
        getattr(args, "id_token", None),
        getattr(args, "token_endpoint", None),
    ])

    if not tiene_input:
        console.print(BANNER)
        console.print(
            "\n[yellow]⚠ No se proporcionó ninguna entrada.[/yellow]\n"
            "Usa [bold]--target[/bold], [bold]--auth-url[/bold], "
            "[bold]--access-token[/bold] o [bold]--id-token[/bold].\n"
            "Ejecuta con [bold]--help[/bold] para ver todas las opciones."
        )
        sys.exit(1)

    if not getattr(args, "quiet", False):
        console.print(Padding(Panel(BANNER, border_style="dim red", expand=False), (1, 0, 1, 0)))

    # Ejecutar auditoría asíncrona
    try:
        hallazgos = asyncio.run(ejecutar_auditoria(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]Auditoría interrumpida por el usuario.[/yellow]")
        sys.exit(130)

    # Filtrar por severidad mínima
    min_sev = getattr(args, "min_severity", "INFO")
    hallazgos_filtrados = filtrar_hallazgos(hallazgos, min_sev)

    # Mostrar tabla Rich
    console.print()
    if hallazgos_filtrados:
        mostrar_tabla_rich(hallazgos_filtrados, compute_grade(hallazgos_filtrados))
    else:
        console.print("[bold green]✓ No se detectaron hallazgos con la severidad mínima seleccionada.[/bold green]")

    # Guardar JSON
    json_path = getattr(args, "json", None)
    if json_path:
        datos_json = {
            "herramienta": "vamp-oauth-audit",
            "version": VERSION,
            "fecha": datetime.now(timezone.utc).isoformat(),
            "target": getattr(args, "target", None) or getattr(args, "discovery_url", None),
            "grade": compute_grade(hallazgos_filtrados),
            "total": len(hallazgos_filtrados),
            "hallazgos": [
                {
                    "id": h.id,
                    "severidad": h.severidad,
                    "fase": h.fase,
                    "descripcion": h.descripcion,
                    "detalle": h.detalle,
                    "remediacion": h.remediacion,
                }
                for h in hallazgos_filtrados
            ],
        }
        try:
            with open(json_path, "w", encoding="utf-8") as fh:
                json.dump(datos_json, fh, ensure_ascii=False, indent=2)
            console.print(f"[green]✓ JSON guardado en:[/green] {json_path}")
        except OSError as exc:
            console.print(f"[red]✗ Error al guardar JSON: {exc}[/red]")

    # Guardar HTML
    html_path = getattr(args, "html", None)
    if html_path:
        # Para el HTML se usa el estado de la última ejecución
        # Como estado no es accesible aquí directamente, generamos con estado vacío
        # (los datos relevantes están en los hallazgos)
        estado_html: Dict[str, Any] = {}
        contenido_html = generar_html(hallazgos_filtrados, args, estado_html)
        try:
            with open(html_path, "w", encoding="utf-8") as fh:
                fh.write(contenido_html)
            console.print(f"[green]✓ Informe HTML guardado en:[/green] {html_path}")
        except OSError as exc:
            console.print(f"[red]✗ Error al guardar HTML: {exc}[/red]")

    # Resumen final
    conteo_final: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for h in hallazgos_filtrados:
        conteo_final[h.severidad] = conteo_final.get(h.severidad, 0) + 1

    if not getattr(args, "quiet", False):
        console.print(
            f"\n[dim]Total: {len(hallazgos_filtrados)} hallazgos — "
            f"CRITICAL={conteo_final['CRITICAL']} "
            f"HIGH={conteo_final['HIGH']} "
            f"MEDIUM={conteo_final['MEDIUM']} "
            f"LOW={conteo_final['LOW']} "
            f"INFO={conteo_final['INFO']}[/dim]"
        )

    # Código de salida basado en severidad
    if conteo_final["CRITICAL"] > 0:
        sys.exit(2)
    if conteo_final["HIGH"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
