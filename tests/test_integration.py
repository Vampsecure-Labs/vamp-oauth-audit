# © VampSecure Studios — VampSecure Labs Security Research Division
"""
test_integration.py — Tests de integración para vamp-oauth-audit
=================================================================
Utiliza mocks de aiohttp para simular servidores OIDC/OAuth sin infraestructura real.
Verifica el parsing de discovery, JWKS y detección de configuraciones inseguras.
"""

import pytest
import argparse
from unittest.mock import AsyncMock, MagicMock

from vamp_oauth_audit import fase_discovery


# ─────────────────────────────────────────────────────────────────────────────
# Helpers para simular respuestas aiohttp
# ─────────────────────────────────────────────────────────────────────────────

def _crear_args(discovery_url: str) -> argparse.Namespace:
    """Crea un Namespace de args simulando la CLI con --discovery-url."""
    args = argparse.Namespace()
    args.discovery_url = discovery_url
    args.target = None
    return args


def _mock_session_con_json(cuerpo: dict, status: int = 200):
    """Crea un mock de aiohttp.ClientSession que devuelve JSON fijo."""
    resp = MagicMock()
    resp.status = status
    resp.json = AsyncMock(return_value=cuerpo)
    resp.__aenter__ = AsyncMock(return_value=resp)
    resp.__aexit__ = AsyncMock(return_value=False)

    session = MagicMock()
    session.get = MagicMock(return_value=resp)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    return session


# ─────────────────────────────────────────────────────────────────────────────
# Test 1: Discovery sin S256 → finding OAUTH-001 HIGH
# ─────────────────────────────────────────────────────────────────────────────

class TestIntegrationDiscovery:
    """Verifica el análisis del endpoint de discovery OIDC."""

    @pytest.mark.asyncio
    async def test_pkce_s256_ausente_genera_oauth_001_high(self, discovery_config_inseguro):
        """Discovery sin S256 en code_challenge_methods debe generar OAUTH-001 HIGH."""
        session_mock = _mock_session_con_json(discovery_config_inseguro)
        args = _crear_args("https://auth.vampsecure.test/.well-known/openid-configuration")

        hallazgos, estado = await fase_discovery(session_mock, args)

        altos = [h for h in hallazgos if h.severidad == "HIGH"]
        assert any(h.id == "OAUTH-001" for h in altos)

    @pytest.mark.asyncio
    async def test_implicit_flow_soportado_genera_hallazgo(self, discovery_config_inseguro):
        """Discovery con response_type=token soportado debe generar hallazgo."""
        session_mock = _mock_session_con_json(discovery_config_inseguro)
        args = _crear_args("https://auth.vampsecure.test/.well-known/openid-configuration")

        hallazgos, estado = await fase_discovery(session_mock, args)

        # Debe haber hallazgo por implicit flow (OAUTH-002)
        ids_hallados = {h.id for h in hallazgos}
        assert "OAUTH-002" in ids_hallados

    @pytest.mark.asyncio
    async def test_token_endpoint_http_genera_critical(self, discovery_config_inseguro):
        """Token endpoint sin TLS (http://) debe generar hallazgo CRITICAL."""
        session_mock = _mock_session_con_json(discovery_config_inseguro)
        args = _crear_args("https://auth.vampsecure.test/.well-known/openid-configuration")

        hallazgos, estado = await fase_discovery(session_mock, args)

        criticos = [h for h in hallazgos if h.severidad == "CRITICAL"]
        assert any(h.id == "OAUTH-005" for h in criticos)

    @pytest.mark.asyncio
    async def test_ropc_grant_genera_oauth_004_high(self, discovery_config_inseguro):
        """grant_type=password (ROPC) debe generar hallazgo OAUTH-004 HIGH."""
        session_mock = _mock_session_con_json(discovery_config_inseguro)
        args = _crear_args("https://auth.vampsecure.test/.well-known/openid-configuration")

        hallazgos, estado = await fase_discovery(session_mock, args)

        altos = [h for h in hallazgos if h.severidad == "HIGH"]
        assert any(h.id == "OAUTH-004" for h in altos)

    @pytest.mark.asyncio
    async def test_discovery_seguro_sin_hallazgos_criticos(self, discovery_config_seguro):
        """Una configuración OIDC correcta no debe generar hallazgos CRITICAL."""
        session_mock = _mock_session_con_json(discovery_config_seguro)
        args = _crear_args("https://auth.vampsecure.test/.well-known/openid-configuration")

        hallazgos, estado = await fase_discovery(session_mock, args)

        criticos = [h for h in hallazgos if h.severidad == "CRITICAL"]
        assert len(criticos) == 0

    @pytest.mark.asyncio
    async def test_estado_contiene_endpoints_del_discovery(self, discovery_config_seguro):
        """El estado resultante debe contener los endpoints del discovery."""
        session_mock = _mock_session_con_json(discovery_config_seguro)
        args = _crear_args("https://auth.vampsecure.test/.well-known/openid-configuration")

        _, estado = await fase_discovery(session_mock, args)

        assert "authorization_endpoint" in estado
        assert "token_endpoint" in estado
        assert "jwks_uri" in estado
