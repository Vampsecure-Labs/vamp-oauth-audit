# © VampSecure Studios — VampSecure Labs Security Research Division
"""
conftest.py — Fixtures compartidos para los tests de vamp-oauth-audit
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures de configuración OIDC
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def discovery_config_seguro():
    """Configuración OIDC con buenas prácticas de seguridad."""
    return {
        "issuer": "https://auth.vampsecure.test",
        "authorization_endpoint": "https://auth.vampsecure.test/oauth/authorize",
        "token_endpoint": "https://auth.vampsecure.test/oauth/token",
        "userinfo_endpoint": "https://auth.vampsecure.test/userinfo",
        "jwks_uri": "https://auth.vampsecure.test/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "end_session_endpoint": "https://auth.vampsecure.test/logout",
    }


@pytest.fixture
def discovery_config_inseguro():
    """Configuración OIDC con múltiples problemas de seguridad."""
    return {
        "issuer": "https://auth.vampsecure.test",
        "authorization_endpoint": "https://auth.vampsecure.test/oauth/authorize",
        # Token endpoint sin TLS
        "token_endpoint": "http://auth.vampsecure.test/oauth/token",
        "jwks_uri": "https://auth.vampsecure.test/.well-known/jwks.json",
        # Sin S256: código de desafío no soportado
        "code_challenge_methods_supported": ["plain"],
        # Implicit flow habilitado
        "response_types_supported": ["code", "token"],
        # Acepta clientes sin autenticación
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        # ROPC grant habilitado
        "grant_types_supported": ["authorization_code", "password", "refresh_token"],
    }


@pytest.fixture
def jwks_rsa():
    """JWKS con una clave RSA pública de ejemplo (módulo reducido para test)."""
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "kid": "test-key-2024",
                "alg": "RS256",
                # n y e mínimos (clave ficticia para tests)
                "n": "pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGyw-It_sg",
                "e": "AQAB",
            }
        ]
    }


@pytest.fixture
def url_auth_segura():
    """URL de autorización OAuth con todos los parámetros de seguridad correctos."""
    return (
        "https://auth.vampsecure.test/oauth/authorize"
        "?client_id=mi-app"
        "&response_type=code"
        "&redirect_uri=https%3A%2F%2Fapp.test%2Fcallback"
        "&state=Xk8mP3aQ2nGr7sY1"
        "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        "&code_challenge_method=S256"
        "&scope=openid+profile"
    )


@pytest.fixture
def url_auth_sin_state():
    """URL de autorización OAuth sin parámetro state (vulnerable a CSRF)."""
    return (
        "https://auth.vampsecure.test/oauth/authorize"
        "?client_id=mi-app"
        "&response_type=code"
        "&redirect_uri=https%3A%2F%2Fapp.test%2Fcallback"
        "&scope=openid+profile"
    )


@pytest.fixture
def url_auth_implicit():
    """URL de autorización OAuth con response_type=token (implicit flow)."""
    return (
        "https://auth.vampsecure.test/oauth/authorize"
        "?client_id=mi-spa"
        "&response_type=token"
        "&redirect_uri=https%3A%2F%2Fspa.test%2Fcallback"
        "&state=Xk8mP3aQ2nGr7sY1"
        "&scope=openid"
    )
