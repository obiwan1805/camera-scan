# VendorProbeDetector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add VendorProbeDetector to Layer 3 auth detection, probing vendor-specific and generic auth endpoints plus title/SPA heuristics to fix the 84.6% miss rate on SPA-based camera UIs.

**Architecture:** New `VendorProbeDetector` class runs in parallel with existing `FormDetector` and `MSFDetector` via `asyncio.gather`. It probes vendor-specific auth endpoints (using vendor from Layer 2 fingerprint), generic camera auth endpoints, and applies title+SPA heuristics as fallback. AuthChecker merges results by confidence priority.

**Tech Stack:** Python 3, aiohttp, re, asyncio, pydantic, pytest

## Global Constraints

- All new fields on `AuthInfo` must be `Optional` with default `None` for backward compatibility
- VendorProbeDetector uses `config.banner_timeout` for HTTP request timeouts (default 5s)
- `MAX_RAW_RESPONSE = 512` bytes truncation applies to all raw responses
- No new dependencies — only stdlib + aiohttp (already in project)
- Vendor probe map is a hardcoded dict, not external YAML

---

### Task 1: Extend AuthInfo with confidence and detection_method fields

**Files:**
- Modify: `src/storage/schemas.py:49-65`
- Test: `tests/test_auth_checker.py` (TestAuthInfo class)

**Interfaces:**
- Consumes: nothing new
- Produces: `AuthInfo` model with new optional fields: `confidence: Optional[str] = None`, `detection_method: Optional[str] = None`

- [ ] **Step 1: Write failing test for new AuthInfo fields**

In `tests/test_auth_checker.py`, add a test to `TestAuthInfo`:

```python
def test_auth_info_vendor_probe_fields(self):
    from src.storage.schemas import AuthInfo
    info = AuthInfo(
        port=80, protocol="http", has_login=True, auth_type="digest",
        confidence="high", detection_method="vendor_probe",
        login_url="http://1.1.1.1/cgi-bin/login.cgi",
    )
    assert info.confidence == "high"
    assert info.detection_method == "vendor_probe"

def test_auth_info_new_fields_default_none(self):
    from src.storage.schemas import AuthInfo
    info = AuthInfo(port=22, protocol="ssh", has_login=True, auth_type="password")
    assert info.confidence is None
    assert info.detection_method is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_auth_checker.py::TestAuthInfo::test_auth_info_vendor_probe_fields -v`
Expected: FAIL — `AuthInfo.__init__() got an unexpected keyword argument 'confidence'`

- [ ] **Step 3: Add new fields to AuthInfo**

In `src/storage/schemas.py`, add two fields at the end of `AuthInfo` (after `cookies`):

```python
class AuthInfo(BaseModel):
    """Authentication detection result for a single port."""
    port: int
    protocol: str
    has_login: bool
    auth_type: str
    raw_response: str = ""
    msf_module: Optional[str] = None
    form_action: Optional[str] = None
    form_method: Optional[str] = None
    username_field: Optional[str] = None
    password_field: Optional[str] = None
    hidden_fields: Optional[dict] = None
    csrf_token_field: Optional[str] = None
    csrf_token_value: Optional[str] = None
    login_url: Optional[str] = None
    cookies: Optional[dict] = None
    confidence: Optional[str] = None
    detection_method: Optional[str] = None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_auth_checker.py::TestAuthInfo -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add src/storage/schemas.py tests/test_auth_checker.py
git commit -m "feat(auth): add confidence and detection_method fields to AuthInfo"
```

---

### Task 2: Create VendorProbeDetector

**Files:**
- Create: `src/layers/layer3_cve_searcher/auth_checker/vendor_probe_detector.py`
- Create: `tests/test_vendor_probe_detector.py`

**Interfaces:**
- Consumes: `AuthCheckConfig` (uses `banner_timeout`), `AuthInfo` from Task 1 (uses `confidence`, `detection_method`)
- Produces: `VendorProbeDetector` class with `async def detect(self, ip: str, port: int, protocol: str, vendor: Optional[str]) -> AuthInfo`

- [ ] **Step 1: Write failing tests for VendorProbeDetector**

Create `tests/test_vendor_probe_detector.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_vendor_probe_detector.py -v`
Expected: FAIL — `vendor_probe_detector` module does not exist

- [ ] **Step 3: Implement VendorProbeDetector**

Create `src/layers/layer3_cve_searcher/auth_checker/vendor_probe_detector.py`:

```python
"""Vendor-specific and generic auth endpoint probing + SPA heuristics."""
import json
import re
from typing import Optional, List, Tuple, Dict
import aiohttp
from src.core.config import AuthCheckConfig
from src.storage.schemas import AuthInfo
from src.utils.logging import setup_logger

MAX_RAW_RESPONSE = 512

VENDOR_PROBE_MAP: Dict[str, List[str]] = {
    "dahua": ["/cgi-bin/login.cgi"],
    "hikvision": ["/ISAPI/Security/userCheck", "/ISAPI/Security/sessionLogin/capabilities"],
    "axis": ["/axis-cgi/usergroup.cgi", "/axis-cgi/param.cgi"],
    "panasonic": ["/cgi-bin/login.cgi"],
    "ubiquiti": ["/api/auth/login"],
    "vivotek": ["/cgi-bin/admin/getparam.cgi"],
    "foscam": ["/cgi-bin/CGIProxy.fcgi?cmd=logIn"],
    "sony": ["/command/inquiry.cgi"],
    "mobotix": ["/control/userimage.html"],
}

GENERIC_PROBE_PATHS: List[str] = [
    "/cgi-bin/login.cgi",
    "/ISAPI/Security/userCheck",
    "/api/login",
    "/api/auth",
    "/cgi-bin/viewer/login.cgi",
    "/login.htm",
    "/login.php",
    "/admin/login.html",
]

LOGIN_TITLE_PATTERNS = [
    re.compile(r"\blogin\b", re.IGNORECASE),
    re.compile(r"^WEB SERVICE$", re.IGNORECASE),
    re.compile(r"^AXIS$", re.IGNORECASE),
    re.compile(r"\b(?:NVR|DVR|IPC)\b"),
    re.compile(r"\bUniFi\b", re.IGNORECASE),
]

SPA_FRAMEWORK_PATTERNS = [
    re.compile(r"Ext\.onReady|ext-all\.js", re.IGNORECASE),
    re.compile(r"SmartGWT|\.nocache\.js", re.IGNORECASE),
    re.compile(r"require\.js.*jsCore|jsCore.*require\.js", re.IGNORECASE | re.DOTALL),
]

CRYPTO_LOGIN_PATTERN = re.compile(r"md5\.js", re.IGNORECASE)
CRYPTO_RSA_PATTERN = re.compile(r"rsa\.js", re.IGNORECASE)

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class VendorProbeDetector:
    def __init__(self, config: AuthCheckConfig):
        self._config = config
        self._logger = setup_logger("VendorProbeDetector")

    async def detect(
        self, ip: str, port: int, protocol: str, vendor: Optional[str],
    ) -> AuthInfo:
        scheme = "https" if protocol == "https" else "http"
        default = AuthInfo(
            port=port, protocol=protocol, has_login=False, auth_type="unknown",
        )

        try:
            timeout = aiohttp.ClientTimeout(total=self._config.banner_timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # 1. Vendor-specific probes
                if vendor and vendor.lower() in VENDOR_PROBE_MAP:
                    paths = VENDOR_PROBE_MAP[vendor.lower()]
                    result = await self._probe_endpoints(
                        session, ip, port, scheme, protocol, paths,
                    )
                    if result:
                        return result

                # 2. Generic probes
                result = await self._probe_endpoints(
                    session, ip, port, scheme, protocol, GENERIC_PROBE_PATHS,
                )
                if result:
                    return result

                # 3. Heuristic: title + SPA framework
                result = await self._check_heuristics(
                    session, ip, port, scheme, protocol,
                )
                if result:
                    return result

        except Exception as e:
            self._logger.debug(f"VendorProbe failed for {ip}:{port}: {e}")

        return default

    async def _probe_endpoints(
        self,
        session: aiohttp.ClientSession,
        ip: str,
        port: int,
        scheme: str,
        protocol: str,
        paths: List[str],
    ) -> Optional[AuthInfo]:
        for path in paths:
            url = f"{scheme}://{ip}:{port}{path}"
            try:
                async with session.get(url, ssl=False, allow_redirects=False) as resp:
                    if resp.status == 401:
                        auth_header = resp.headers.get("WWW-Authenticate", "")
                        auth_type = self._parse_auth_type(auth_header)
                        return AuthInfo(
                            port=port,
                            protocol=protocol,
                            has_login=True,
                            auth_type=auth_type,
                            raw_response=f"HTTP 401 at {path}"[:MAX_RAW_RESPONSE],
                            login_url=url,
                            confidence="high",
                            detection_method="vendor_probe",
                        )

                    if resp.status == 200:
                        body = await resp.text(errors="replace")
                        api_result = self._check_api_response(
                            body, url, port, protocol,
                        )
                        if api_result:
                            return api_result

            except Exception:
                continue
        return None

    def _check_api_response(
        self, body: str, url: str, port: int, protocol: str,
    ) -> Optional[AuthInfo]:
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                keys_lower = {k.lower() for k in data.keys()}
                if keys_lower & {"error", "msg", "message", "result"}:
                    return AuthInfo(
                        port=port,
                        protocol=protocol,
                        has_login=True,
                        auth_type="api",
                        raw_response=body[:MAX_RAW_RESPONSE],
                        login_url=url,
                        confidence="high",
                        detection_method="vendor_probe",
                    )
        except (json.JSONDecodeError, ValueError):
            pass

        if "<result>" in body.lower():
            return AuthInfo(
                port=port,
                protocol=protocol,
                has_login=True,
                auth_type="api",
                raw_response=body[:MAX_RAW_RESPONSE],
                login_url=url,
                confidence="high",
                detection_method="vendor_probe",
            )

        return None

    async def _check_heuristics(
        self,
        session: aiohttp.ClientSession,
        ip: str,
        port: int,
        scheme: str,
        protocol: str,
    ) -> Optional[AuthInfo]:
        url = f"{scheme}://{ip}:{port}/"
        try:
            async with session.get(url, ssl=False, allow_redirects=True) as resp:
                html = await resp.text(errors="replace")
        except Exception:
            return None

        title = self._extract_title(html)
        has_login_title = any(p.search(title) for p in LOGIN_TITLE_PATTERNS) if title else False
        has_spa = any(p.search(html) for p in SPA_FRAMEWORK_PATTERNS)
        has_crypto = bool(CRYPTO_LOGIN_PATTERN.search(html) and CRYPTO_RSA_PATTERN.search(html))

        if has_login_title and (has_spa or has_crypto):
            return AuthInfo(
                port=port,
                protocol=protocol,
                has_login=True,
                auth_type="spa_login",
                raw_response=f"Heuristic: title={title!r}"[:MAX_RAW_RESPONSE],
                login_url=url,
                confidence="low",
                detection_method="heuristic",
            )

        return None

    def _extract_title(self, html: str) -> Optional[str]:
        match = TITLE_RE.search(html)
        if match:
            return match.group(1).strip()
        return None

    def _parse_auth_type(self, header: str) -> str:
        h = header.lower()
        if "digest" in h:
            return "digest"
        if "basic" in h:
            return "basic"
        return "unknown"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_vendor_probe_detector.py -v`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add src/layers/layer3_cve_searcher/auth_checker/vendor_probe_detector.py tests/test_vendor_probe_detector.py
git commit -m "feat(auth): add VendorProbeDetector with vendor-specific, generic, and heuristic detection"
```

---

### Task 3: Update AuthChecker to integrate VendorProbeDetector and update exports

**Files:**
- Modify: `src/layers/layer3_cve_searcher/auth_checker/auth_checker.py`
- Modify: `src/layers/layer3_cve_searcher/auth_checker/__init__.py`
- Modify: `tests/test_auth_checker.py`

**Interfaces:**
- Consumes: `VendorProbeDetector` from Task 2 (`VendorProbeDetector(config: AuthCheckConfig)`, `async detect(ip, port, protocol, vendor) -> AuthInfo`), `CameraFingerprint.fingerprint.vendor` from `src/storage/schemas.py`
- Produces: Updated `AuthChecker` that runs 3 detectors in parallel with confidence-based merge priority

- [ ] **Step 1: Write failing tests for new merge behavior**

Add to `tests/test_auth_checker.py`, new class `TestAuthCheckerVendorProbeMerge`:

```python
class TestAuthCheckerVendorProbeMerge:
    """AuthChecker merge logic with VendorProbeDetector."""

    @pytest.mark.asyncio
    async def test_form_beats_vendor_probe_high(self):
        """FormDetector result preferred over VendorProbe high confidence."""
        from src.layers.layer3_cve_searcher.auth_checker import AuthChecker
        from src.core.config import AuthCheckConfig
        from src.storage.schemas import CameraFingerprint, Fingerprint, AuthInfo

        checker = AuthChecker(AuthCheckConfig(), msf_client=None)

        form_result = AuthInfo(
            port=80, protocol="http", has_login=True, auth_type="form",
            form_action="/login", password_field="pass",
            detection_method="form",
        )
        vendor_result = AuthInfo(
            port=80, protocol="http", has_login=True, auth_type="digest",
            confidence="high", detection_method="vendor_probe",
        )
        msf_no = AuthInfo(port=80, protocol="http", has_login=False, auth_type="unknown")

        checker._form.detect = AsyncMock(return_value=form_result)
        checker._vendor_probe.detect = AsyncMock(return_value=vendor_result)
        checker._msf.detect = AsyncMock(return_value=msf_no)

        item = CameraFingerprint(
            ip="1.1.1.1", port=80,
            fingerprint=Fingerprint(vendor="dahua"),
        )
        results = await checker.check(item)

        assert len(results) == 1
        assert results[0].auth_type == "form"

    @pytest.mark.asyncio
    async def test_vendor_probe_high_beats_msf(self):
        """VendorProbe high confidence beats MSFDetector."""
        from src.layers.layer3_cve_searcher.auth_checker import AuthChecker
        from src.core.config import AuthCheckConfig
        from src.storage.schemas import CameraFingerprint, Fingerprint, AuthInfo

        checker = AuthChecker(AuthCheckConfig(), msf_client=None)

        form_no = AuthInfo(port=80, protocol="http", has_login=False, auth_type="unknown")
        vendor_result = AuthInfo(
            port=80, protocol="http", has_login=True, auth_type="digest",
            confidence="high", detection_method="vendor_probe",
        )
        msf_result = AuthInfo(
            port=80, protocol="http", has_login=True, auth_type="basic",
            msf_module="auxiliary/scanner/http/http_login",
        )

        checker._form.detect = AsyncMock(return_value=form_no)
        checker._vendor_probe.detect = AsyncMock(return_value=vendor_result)
        checker._msf.detect = AsyncMock(return_value=msf_result)

        item = CameraFingerprint(
            ip="1.1.1.1", port=80,
            fingerprint=Fingerprint(vendor="dahua"),
        )
        results = await checker.check(item)

        assert len(results) == 1
        assert results[0].auth_type == "digest"
        assert results[0].confidence == "high"

    @pytest.mark.asyncio
    async def test_msf_beats_vendor_probe_low(self):
        """MSFDetector beats VendorProbe low confidence."""
        from src.layers.layer3_cve_searcher.auth_checker import AuthChecker
        from src.core.config import AuthCheckConfig
        from src.storage.schemas import CameraFingerprint, Fingerprint, AuthInfo

        checker = AuthChecker(AuthCheckConfig(), msf_client=None)

        form_no = AuthInfo(port=80, protocol="http", has_login=False, auth_type="unknown")
        vendor_result = AuthInfo(
            port=80, protocol="http", has_login=True, auth_type="spa_login",
            confidence="low", detection_method="heuristic",
        )
        msf_result = AuthInfo(
            port=80, protocol="http", has_login=True, auth_type="basic",
            msf_module="auxiliary/scanner/http/http_login",
        )

        checker._form.detect = AsyncMock(return_value=form_no)
        checker._vendor_probe.detect = AsyncMock(return_value=vendor_result)
        checker._msf.detect = AsyncMock(return_value=msf_result)

        item = CameraFingerprint(
            ip="1.1.1.1", port=80,
            fingerprint=Fingerprint(vendor="dahua"),
        )
        results = await checker.check(item)

        assert len(results) == 1
        assert results[0].auth_type == "basic"

    @pytest.mark.asyncio
    async def test_vendor_probe_low_used_as_last_resort(self):
        """VendorProbe low confidence used when form and msf find nothing."""
        from src.layers.layer3_cve_searcher.auth_checker import AuthChecker
        from src.core.config import AuthCheckConfig
        from src.storage.schemas import CameraFingerprint, Fingerprint, AuthInfo

        checker = AuthChecker(AuthCheckConfig(), msf_client=None)

        no_login = AuthInfo(port=80, protocol="http", has_login=False, auth_type="unknown")
        vendor_result = AuthInfo(
            port=80, protocol="http", has_login=True, auth_type="spa_login",
            confidence="low", detection_method="heuristic",
        )

        checker._form.detect = AsyncMock(return_value=no_login)
        checker._vendor_probe.detect = AsyncMock(return_value=vendor_result)
        checker._msf.detect = AsyncMock(return_value=no_login)

        item = CameraFingerprint(
            ip="1.1.1.1", port=80,
            fingerprint=Fingerprint(vendor="dahua"),
        )
        results = await checker.check(item)

        assert len(results) == 1
        assert results[0].auth_type == "spa_login"
        assert results[0].confidence == "low"

    @pytest.mark.asyncio
    async def test_all_three_fail_returns_no_login(self):
        """All detectors find nothing → has_login=False."""
        from src.layers.layer3_cve_searcher.auth_checker import AuthChecker
        from src.core.config import AuthCheckConfig
        from src.storage.schemas import CameraFingerprint, Fingerprint, AuthInfo

        checker = AuthChecker(AuthCheckConfig(), msf_client=None)

        no_login = AuthInfo(port=80, protocol="http", has_login=False, auth_type="unknown")

        checker._form.detect = AsyncMock(return_value=no_login)
        checker._vendor_probe.detect = AsyncMock(return_value=no_login)
        checker._msf.detect = AsyncMock(return_value=no_login)

        item = CameraFingerprint(
            ip="1.1.1.1", port=80,
            fingerprint=Fingerprint(vendor="dahua"),
        )
        results = await checker.check(item)

        assert len(results) == 1
        assert results[0].has_login is False

    @pytest.mark.asyncio
    async def test_vendor_probe_exception_ignored(self):
        """VendorProbe exception doesn't break auth checking."""
        from src.layers.layer3_cve_searcher.auth_checker import AuthChecker
        from src.core.config import AuthCheckConfig
        from src.storage.schemas import CameraFingerprint, Fingerprint, AuthInfo

        checker = AuthChecker(AuthCheckConfig(), msf_client=None)

        form_result = AuthInfo(
            port=80, protocol="http", has_login=True, auth_type="form",
            form_action="/login",
        )

        checker._form.detect = AsyncMock(return_value=form_result)
        checker._vendor_probe.detect = AsyncMock(side_effect=Exception("probe exploded"))
        checker._msf.detect = AsyncMock(return_value=AuthInfo(
            port=80, protocol="http", has_login=False, auth_type="unknown",
        ))

        item = CameraFingerprint(
            ip="1.1.1.1", port=80,
            fingerprint=Fingerprint(vendor="dahua"),
        )
        results = await checker.check(item)

        assert len(results) == 1
        assert results[0].has_login is True

    @pytest.mark.asyncio
    async def test_vendor_passed_to_vendor_probe(self):
        """Vendor from CameraFingerprint.fingerprint.vendor is passed to VendorProbeDetector."""
        from src.layers.layer3_cve_searcher.auth_checker import AuthChecker
        from src.core.config import AuthCheckConfig
        from src.storage.schemas import CameraFingerprint, Fingerprint, AuthInfo

        checker = AuthChecker(AuthCheckConfig(), msf_client=None)

        no_login = AuthInfo(port=80, protocol="http", has_login=False, auth_type="unknown")
        checker._form.detect = AsyncMock(return_value=no_login)
        checker._vendor_probe.detect = AsyncMock(return_value=no_login)
        checker._msf.detect = AsyncMock(return_value=no_login)

        item = CameraFingerprint(
            ip="1.1.1.1", port=80,
            fingerprint=Fingerprint(vendor="axis"),
        )
        await checker.check(item)

        checker._vendor_probe.detect.assert_called_once_with(
            "1.1.1.1", 80, "http", "axis",
        )

    @pytest.mark.asyncio
    async def test_vendor_none_when_no_fingerprint_vendor(self):
        """Vendor=None passed when fingerprint has no vendor."""
        from src.layers.layer3_cve_searcher.auth_checker import AuthChecker
        from src.core.config import AuthCheckConfig
        from src.storage.schemas import CameraFingerprint, Fingerprint, AuthInfo

        checker = AuthChecker(AuthCheckConfig(), msf_client=None)

        no_login = AuthInfo(port=80, protocol="http", has_login=False, auth_type="unknown")
        checker._form.detect = AsyncMock(return_value=no_login)
        checker._vendor_probe.detect = AsyncMock(return_value=no_login)
        checker._msf.detect = AsyncMock(return_value=no_login)

        item = CameraFingerprint(
            ip="1.1.1.1", port=80,
            fingerprint=Fingerprint(),
        )
        await checker.check(item)

        checker._vendor_probe.detect.assert_called_once_with(
            "1.1.1.1", 80, "http", None,
        )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_auth_checker.py::TestAuthCheckerVendorProbeMerge -v`
Expected: FAIL — `AuthChecker` has no `_vendor_probe` attribute

- [ ] **Step 3: Update AuthChecker**

Replace `src/layers/layer3_cve_searcher/auth_checker/auth_checker.py`:

```python
"""Authentication checker orchestrator — dispatches to banner, MSF, form, or vendor probe detector."""
import asyncio
from typing import List, Optional
from src.core.config import AuthCheckConfig
from src.storage.schemas import AuthInfo, CameraFingerprint
from src.utils.logging import setup_logger
from .protocol_map import get_protocol, is_web_protocol
from .banner_detector import BannerDetector
from .msf_detector import MSFDetector
from .form_detector import FormDetector
from .vendor_probe_detector import VendorProbeDetector


class AuthChecker:
    def __init__(self, config: AuthCheckConfig, msf_client):
        self._config = config
        self._banner = BannerDetector(config)
        self._msf = MSFDetector(config, msf_client)
        self._form = FormDetector(config)
        self._vendor_probe = VendorProbeDetector(config)
        self._semaphore = asyncio.Semaphore(config.max_auth_concurrency)
        self._logger = setup_logger("AuthChecker")

    async def check(self, item: CameraFingerprint) -> List[AuthInfo]:
        if not self._config.enabled:
            return []

        async with self._semaphore:
            return await self._check_inner(item)

    async def _check_inner(self, item: CameraFingerprint) -> List[AuthInfo]:
        ip = item.ip
        port = item.port
        protocol = get_protocol(port)
        vendor = item.fingerprint.vendor

        if is_web_protocol(protocol):
            result = await self._check_web(ip, port, protocol, vendor)
            return [result]

        result = await self._banner.detect(ip, port, protocol)

        if protocol == "unknown" and not result.has_login:
            raw = result.raw_response.lower()
            if "http/" in raw or "<html" in raw:
                web_result = await self._check_web(ip, port, "http", vendor)
                return [web_result]

        return [result]

    async def _check_web(
        self, ip: str, port: int, protocol: str, vendor: Optional[str],
    ) -> AuthInfo:
        msf_result, form_result, vendor_result = await asyncio.gather(
            self._msf.detect(ip, port, protocol),
            self._form.detect(ip, port, protocol),
            self._vendor_probe.detect(ip, port, protocol, vendor),
            return_exceptions=True,
        )

        if isinstance(form_result, Exception):
            self._logger.debug(f"FormDetector error for {ip}:{port}: {form_result}")
            form_result = None
        if isinstance(msf_result, Exception):
            self._logger.debug(f"MSFDetector error for {ip}:{port}: {msf_result}")
            msf_result = None
        if isinstance(vendor_result, Exception):
            self._logger.debug(f"VendorProbe error for {ip}:{port}: {vendor_result}")
            vendor_result = None

        if form_result and form_result.has_login:
            return form_result
        if vendor_result and vendor_result.has_login and vendor_result.confidence == "high":
            return vendor_result
        if msf_result and msf_result.has_login:
            return msf_result
        if vendor_result and vendor_result.has_login and vendor_result.confidence == "low":
            return vendor_result
        return AuthInfo(
            port=port, protocol=protocol, has_login=False, auth_type="unknown",
        )
```

- [ ] **Step 4: Update `__init__.py` exports**

Replace `src/layers/layer3_cve_searcher/auth_checker/__init__.py`:

```python
"""Layer 3: Authentication Checker sub-module."""
from .auth_checker import AuthChecker
from .form_detector import FormDetector
from .vendor_probe_detector import VendorProbeDetector

__all__ = ["AuthChecker", "FormDetector", "VendorProbeDetector"]
```

- [ ] **Step 5: Run ALL tests**

Run: `python -m pytest tests/test_auth_checker.py tests/test_form_detector.py tests/test_vendor_probe_detector.py -v`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add src/layers/layer3_cve_searcher/auth_checker/auth_checker.py \
        src/layers/layer3_cve_searcher/auth_checker/__init__.py \
        tests/test_auth_checker.py
git commit -m "feat(auth): integrate VendorProbeDetector into AuthChecker with confidence-based merge"
```

---

### Task 4: Full test suite verification

**Files:**
- No new files
- Test: all existing tests

**Interfaces:**
- Consumes: all changes from Tasks 1-3
- Produces: confirmation that all tests pass and no regressions

- [ ] **Step 1: Run complete test suite**

Run: `python -m pytest tests/ -v`
Expected: ALL PASS — no regressions

- [ ] **Step 2: Verify backward compatibility of AuthInfo**

Run: `python -c "from src.storage.schemas import AuthInfo; a = AuthInfo(port=22, protocol='ssh', has_login=True, auth_type='password'); print(a.model_dump_json())"`
Expected: JSON output with `confidence` and `detection_method` as `null`, all existing fields unchanged

- [ ] **Step 3: Verify VendorProbeDetector import from package**

Run: `python -c "from src.layers.layer3_cve_searcher.auth_checker import AuthChecker, FormDetector, VendorProbeDetector; print('OK')"`
Expected: `OK`

- [ ] **Step 4: No commit needed — verification only**
