"""Tests for VendorProbeDetector — vendor-specific and generic auth endpoint probing."""
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _mock_aiohttp_session(responses):
    """Build a mock aiohttp session returning responses by URL path.

    responses: dict mapping path -> (status, headers_dict, body_text)
    Default for unknown paths: (404, {}, "")
    """
    mock_session = AsyncMock()

    def make_get(url, **kwargs):
        from urllib.parse import urlparse
        path = urlparse(url).path
        status, headers, body = responses.get(path, (404, {}, ""))

        mock_resp = AsyncMock()
        mock_resp.status = status
        mock_resp.headers = headers
        mock_resp.text = AsyncMock(return_value=body)
        mock_resp.cookies = {}

        ctx = AsyncMock()
        ctx.__aenter__ = AsyncMock(return_value=mock_resp)
        ctx.__aexit__ = AsyncMock(return_value=False)
        return ctx

    mock_session.get = MagicMock(side_effect=make_get)

    session_ctx = AsyncMock()
    session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
    session_ctx.__aexit__ = AsyncMock(return_value=False)
    return session_ctx


class TestVendorProbeDetectorVendorSpecific:
    """Vendor-specific auth endpoint probing."""

    @pytest.mark.asyncio
    async def test_dahua_cgi_login_401_digest(self):
        """Dahua: /cgi-bin/login.cgi returns 401 Digest → high confidence."""
        from src.layers.layer3_cve_searcher.auth_checker.vendor_probe_detector import VendorProbeDetector
        from src.core.config import AuthCheckConfig

        responses = {
            "/cgi-bin/login.cgi": (
                401,
                {"WWW-Authenticate": 'Digest realm="Login to cam", nonce="123"'},
                "",
            ),
        }

        detector = VendorProbeDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http", "dahua")

        assert result.has_login is True
        assert result.auth_type == "digest"
        assert result.confidence == "high"
        assert result.detection_method == "vendor_probe"

    @pytest.mark.asyncio
    async def test_hikvision_isapi_401_basic(self):
        """Hikvision: /ISAPI/Security/userCheck returns 401 Basic → high confidence."""
        from src.layers.layer3_cve_searcher.auth_checker.vendor_probe_detector import VendorProbeDetector
        from src.core.config import AuthCheckConfig

        responses = {
            "/ISAPI/Security/userCheck": (
                401,
                {"WWW-Authenticate": 'Basic realm="Hikvision"'},
                "",
            ),
        }

        detector = VendorProbeDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http", "hikvision")

        assert result.has_login is True
        assert result.auth_type == "basic"
        assert result.confidence == "high"

    @pytest.mark.asyncio
    async def test_axis_cgi_401_digest(self):
        """Axis: /axis-cgi/usergroup.cgi returns 401 Digest → high confidence."""
        from src.layers.layer3_cve_searcher.auth_checker.vendor_probe_detector import VendorProbeDetector
        from src.core.config import AuthCheckConfig

        responses = {
            "/axis-cgi/usergroup.cgi": (
                401,
                {"WWW-Authenticate": 'Digest realm="AXIS_ABC", nonce="xyz", algorithm=MD5, qop="auth"'},
                "",
            ),
        }

        detector = VendorProbeDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 443, "https", "axis")

        assert result.has_login is True
        assert result.auth_type == "digest"
        assert result.confidence == "high"

    @pytest.mark.asyncio
    async def test_ubiquiti_api_auth_401(self):
        """Ubiquiti: /api/auth/login returns 401 → high confidence."""
        from src.layers.layer3_cve_searcher.auth_checker.vendor_probe_detector import VendorProbeDetector
        from src.core.config import AuthCheckConfig

        responses = {
            "/api/auth/login": (401, {}, ""),
        }

        detector = VendorProbeDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 443, "https", "ubiquiti")

        assert result.has_login is True
        assert result.confidence == "high"

    @pytest.mark.asyncio
    async def test_ubiquiti_api_auth_200_json_error(self):
        """Ubiquiti: /api/auth/login returns 200 with JSON error → high confidence."""
        from src.layers.layer3_cve_searcher.auth_checker.vendor_probe_detector import VendorProbeDetector
        from src.core.config import AuthCheckConfig

        responses = {
            "/api/auth/login": (200, {}, '{"error": "Invalid credentials", "msg": "Login required"}'),
        }

        detector = VendorProbeDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 443, "https", "ubiquiti")

        assert result.has_login is True
        assert result.auth_type == "api"
        assert result.confidence == "high"

    @pytest.mark.asyncio
    async def test_foscam_cgi_proxy_xml(self):
        """Foscam: /cgi-bin/CGIProxy.fcgi?cmd=logIn returns 200 with XML result → high confidence."""
        from src.layers.layer3_cve_searcher.auth_checker.vendor_probe_detector import VendorProbeDetector
        from src.core.config import AuthCheckConfig

        responses = {
            "/cgi-bin/CGIProxy.fcgi": (200, {}, '<CGI_Result><result>-1</result></CGI_Result>'),
        }

        detector = VendorProbeDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http", "foscam")

        assert result.has_login is True
        assert result.auth_type == "api"
        assert result.confidence == "high"

    @pytest.mark.asyncio
    async def test_vendor_specific_no_match_falls_through(self):
        """Vendor endpoints all 404 → falls through to generic probes."""
        from src.layers.layer3_cve_searcher.auth_checker.vendor_probe_detector import VendorProbeDetector
        from src.core.config import AuthCheckConfig

        responses = {}  # everything returns 404

        detector = VendorProbeDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http", "dahua")

        assert result.has_login is False


class TestVendorProbeDetectorGeneric:
    """Generic auth endpoint probing for unknown vendors."""

    @pytest.mark.asyncio
    async def test_generic_cgi_login_401(self):
        """Unknown vendor: /cgi-bin/login.cgi returns 401 → high confidence."""
        from src.layers.layer3_cve_searcher.auth_checker.vendor_probe_detector import VendorProbeDetector
        from src.core.config import AuthCheckConfig

        responses = {
            "/cgi-bin/login.cgi": (
                401,
                {"WWW-Authenticate": 'Digest realm="camera"'},
                "",
            ),
        }

        detector = VendorProbeDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http", None)

        assert result.has_login is True
        assert result.auth_type == "digest"
        assert result.confidence == "high"

    @pytest.mark.asyncio
    async def test_generic_api_login_401(self):
        """Unknown vendor: /api/login returns 401 → high confidence."""
        from src.layers.layer3_cve_searcher.auth_checker.vendor_probe_detector import VendorProbeDetector
        from src.core.config import AuthCheckConfig

        responses = {
            "/api/login": (401, {"WWW-Authenticate": "Basic"}, ""),
        }

        detector = VendorProbeDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http", None)

        assert result.has_login is True
        assert result.confidence == "high"

    @pytest.mark.asyncio
    async def test_no_generic_match_no_heuristic(self):
        """No generic endpoints match and no SPA heuristics → has_login=False."""
        from src.layers.layer3_cve_searcher.auth_checker.vendor_probe_detector import VendorProbeDetector
        from src.core.config import AuthCheckConfig

        responses = {
            "/": (200, {}, "<html><head><title>Camera Stream</title></head><body>Live</body></html>"),
        }

        detector = VendorProbeDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http", None)

        assert result.has_login is False


class TestVendorProbeDetectorHeuristics:
    """Title + SPA framework heuristic detection (low confidence)."""

    @pytest.mark.asyncio
    async def test_dahua_spa_extjs_title(self):
        """Dahua SPA: title 'WEB SERVICE' + ext-all.js → low confidence."""
        from src.layers.layer3_cve_searcher.auth_checker.vendor_probe_detector import VendorProbeDetector
        from src.core.config import AuthCheckConfig

        html = (
            '<!DOCTYPE HTML><html><head><title>WEB SERVICE</title>'
            '<script src="ext/ext-all.js"></script>'
            '<script>Ext.onReady(function(){})</script>'
            '</head><body></body></html>'
        )
        responses = {"/": (200, {}, html)}

        detector = VendorProbeDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http", "dahua")

        assert result.has_login is True
        assert result.auth_type == "spa_login"
        assert result.confidence == "low"
        assert result.detection_method == "heuristic"

    @pytest.mark.asyncio
    async def test_vigor_smartgwt_login_page(self):
        """Vigor: title 'Vigor Login Page' + .nocache.js → low confidence."""
        from src.layers.layer3_cve_searcher.auth_checker.vendor_probe_detector import VendorProbeDetector
        from src.core.config import AuthCheckConfig

        html = (
            '<html><head><title>Vigor Login Page</title>'
            '<script src="assets/md5.js"></script>'
            '<script src="assets/rsa/rsa.js"></script>'
            '<script src="V2960/V2960.nocache.js"></script>'
            '</head><body></body></html>'
        )
        responses = {"/": (200, {}, html)}

        detector = VendorProbeDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http", "panasonic")

        assert result.has_login is True
        assert result.auth_type == "spa_login"
        assert result.confidence == "low"

    @pytest.mark.asyncio
    async def test_crypto_login_md5_rsa(self):
        """Page with md5.js + rsa.js + login title → low confidence."""
        from src.layers.layer3_cve_searcher.auth_checker.vendor_probe_detector import VendorProbeDetector
        from src.core.config import AuthCheckConfig

        html = (
            '<html><head><title>Login</title>'
            '<script src="md5.js"></script>'
            '<script src="rsa.js"></script>'
            '</head><body></body></html>'
        )
        responses = {"/": (200, {}, html)}

        detector = VendorProbeDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http", None)

        assert result.has_login is True
        assert result.confidence == "low"

    @pytest.mark.asyncio
    async def test_spa_framework_without_login_title_no_match(self):
        """SPA framework present but no login-related title → no conclusion."""
        from src.layers.layer3_cve_searcher.auth_checker.vendor_probe_detector import VendorProbeDetector
        from src.core.config import AuthCheckConfig

        html = (
            '<html><head><title>Camera Stream Viewer</title>'
            '<script src="ext/ext-all.js"></script>'
            '</head><body></body></html>'
        )
        responses = {"/": (200, {}, html)}

        detector = VendorProbeDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http", None)

        assert result.has_login is False

    @pytest.mark.asyncio
    async def test_title_nvr_standalone(self):
        """Title containing standalone 'NVR' + SPA → low confidence."""
        from src.layers.layer3_cve_searcher.auth_checker.vendor_probe_detector import VendorProbeDetector
        from src.core.config import AuthCheckConfig

        html = (
            '<html><head><title>NVR</title>'
            '<script src="ext/ext-all.js"></script>'
            '</head><body></body></html>'
        )
        responses = {"/": (200, {}, html)}

        detector = VendorProbeDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http", None)

        assert result.has_login is True
        assert result.confidence == "low"


class TestVendorProbeDetectorEdgeCases:
    """Error handling and edge cases."""

    @pytest.mark.asyncio
    async def test_connection_error_returns_no_login(self):
        """Connection failure returns has_login=False."""
        from src.layers.layer3_cve_searcher.auth_checker.vendor_probe_detector import VendorProbeDetector
        from src.core.config import AuthCheckConfig

        detector = VendorProbeDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", side_effect=Exception("connection failed")):
            result = await detector.detect("1.1.1.1", 80, "http", "dahua")

        assert result.has_login is False

    @pytest.mark.asyncio
    async def test_vendor_probe_hit_skips_generic_and_heuristic(self):
        """When vendor probe finds 401, generic probes and heuristics are skipped."""
        from src.layers.layer3_cve_searcher.auth_checker.vendor_probe_detector import VendorProbeDetector
        from src.core.config import AuthCheckConfig

        call_log = []
        original_responses = {
            "/cgi-bin/login.cgi": (
                401,
                {"WWW-Authenticate": "Digest"},
                "",
            ),
        }

        def tracking_get(url, **kwargs):
            from urllib.parse import urlparse
            path = urlparse(url).path
            call_log.append(path)
            status, headers, body = original_responses.get(path, (404, {}, ""))

            mock_resp = AsyncMock()
            mock_resp.status = status
            mock_resp.headers = headers
            mock_resp.text = AsyncMock(return_value=body)
            mock_resp.cookies = {}

            ctx = AsyncMock()
            ctx.__aenter__ = AsyncMock(return_value=mock_resp)
            ctx.__aexit__ = AsyncMock(return_value=False)
            return ctx

        mock_session = AsyncMock()
        mock_session.get = MagicMock(side_effect=tracking_get)
        session_ctx = AsyncMock()
        session_ctx.__aenter__ = AsyncMock(return_value=mock_session)
        session_ctx.__aexit__ = AsyncMock(return_value=False)

        detector = VendorProbeDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=session_ctx):
            result = await detector.detect("1.1.1.1", 80, "http", "dahua")

        assert result.has_login is True
        assert "/cgi-bin/login.cgi" in call_log
        assert "/" not in call_log  # heuristic fetch skipped

    @pytest.mark.asyncio
    async def test_https_scheme(self):
        """Protocol 'https' uses https:// scheme."""
        from src.layers.layer3_cve_searcher.auth_checker.vendor_probe_detector import VendorProbeDetector
        from src.core.config import AuthCheckConfig

        responses = {
            "/ISAPI/Security/userCheck": (
                401,
                {"WWW-Authenticate": "Digest"},
                "",
            ),
        }

        detector = VendorProbeDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 443, "https", "hikvision")

        assert result.has_login is True
        assert result.login_url.startswith("https://")
