"""Tests for FormDetector — HTML/JS login analysis."""
import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _mock_aiohttp_session(responses):
    """Helper: build a mock aiohttp session that returns responses by URL path.

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


class TestFormDetectorFormAnalysis:
    """Form Analyzer: detect <form> with password inputs."""

    @pytest.mark.asyncio
    async def test_password_input_type_first(self):
        """Detect <input type="password" name="pw"> — type attribute first."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        html = '<html><form action="/login" method="POST"><input type="text" name="user"><input type="password" name="pw"></form></html>'
        responses = {"/": (200, {}, html)}

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is True
        assert result.auth_type == "form"
        assert result.form_action == "/login"
        assert result.form_method == "POST"
        assert result.password_field == "pw"
        assert result.username_field == "user"

    @pytest.mark.asyncio
    async def test_password_input_type_last(self):
        """Detect <input name="pwd" class="x" type="password"> — type at end."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        html = '<html><form action="/auth" method="post"><input name="username"><input name="pwd" class="x" type="password"></form></html>'
        responses = {"/": (200, {}, html)}

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is True
        assert result.password_field == "pwd"
        assert result.username_field == "username"

    @pytest.mark.asyncio
    async def test_password_input_case_insensitive(self):
        """Detect <INPUT TYPE="Password"> — case variations."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        html = '<html><FORM ACTION="/login"><INPUT TYPE="Password" NAME="pass"><INPUT TYPE="text" NAME="user"></FORM></html>'
        responses = {"/": (200, {}, html)}

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is True
        assert result.password_field == "pass"

    @pytest.mark.asyncio
    async def test_password_input_with_spaces_around_equals(self):
        """Detect <input type = "password"> — spaces around =."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        html = '<html><form action="/login"><input type = "password" name = "pw"></form></html>'
        responses = {"/": (200, {}, html)}

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is True
        assert result.password_field == "pw"

    @pytest.mark.asyncio
    async def test_hidden_fields_and_csrf(self):
        """Extract hidden fields and CSRF token."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        html = '''<html><form action="/login" method="POST">
            <input type="hidden" name="_csrf_token" value="tok123">
            <input type="hidden" name="redirect" value="/home">
            <input type="text" name="user">
            <input type="password" name="pass">
        </form></html>'''
        responses = {"/": (200, {}, html)}

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is True
        assert result.hidden_fields == {"_csrf_token": "tok123", "redirect": "/home"}
        assert result.csrf_token_field == "_csrf_token"
        assert result.csrf_token_value == "tok123"

    @pytest.mark.asyncio
    async def test_name_heuristic_pass_prefix(self):
        """Detect input with name="passwd" even without type="password"."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        html = '<html><form action="/login"><input name="user"><input name="passwd"></form></html>'
        responses = {"/": (200, {}, html)}

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is True
        assert result.password_field == "passwd"

    @pytest.mark.asyncio
    async def test_no_form_no_detection(self):
        """Page with no form or password input returns has_login=False."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        html = '<html><h1>Camera Stream</h1><p>Live feed</p></html>'
        responses = {"/": (200, {}, html)}

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is False
        assert result.form_action is None


class TestFormDetectorPathDiscovery:
    """Path Discovery: crawl / to find login pages."""

    @pytest.mark.asyncio
    async def test_meta_refresh_redirect(self):
        """Discover login path via <meta http-equiv="refresh">."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        root_html = '<html><head><meta http-equiv="refresh" content="0;url=/webui/login.asp"></head></html>'
        login_html = '<html><form action="/webui/auth" method="POST"><input type="text" name="user"><input type="password" name="pass"></form></html>'
        responses = {
            "/": (200, {}, root_html),
            "/webui/login.asp": (200, {}, login_html),
        }

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is True
        assert result.form_action == "/webui/auth"
        assert result.login_url == "http://1.1.1.1:80/webui/login.asp"

    @pytest.mark.asyncio
    async def test_js_redirect(self):
        """Discover login path via window.location in inline script."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        root_html = '<html><script>window.location = "/auth/login"</script></html>'
        login_html = '<html><form action="/auth/do_login"><input type="password" name="pw"></form></html>'
        responses = {
            "/": (200, {}, root_html),
            "/auth/login": (200, {}, login_html),
        }

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is True
        assert result.form_action == "/auth/do_login"

    @pytest.mark.asyncio
    async def test_link_discovery(self):
        """Discover login path via <a href="/login">."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        root_html = '<html><body><a href="/custom/login">Sign In</a></body></html>'
        login_html = '<html><form action="/custom/auth"><input type="password" name="pw"></form></html>'
        responses = {
            "/": (200, {}, root_html),
            "/custom/login": (200, {}, login_html),
        }

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is True
        assert result.form_action == "/custom/auth"


class TestFormDetectorJSIndicators:
    """JS Login Indicator Analyzer: detect JS-rendered login forms."""

    @pytest.mark.asyncio
    async def test_js_create_password_input(self):
        """Detect createElement creating a password input."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        html = '''<html><script>
            var inp = document.createElement("input");
            inp.type = "password";
            inp.name = "pass";
            document.getElementById("form").appendChild(inp);
        </script><div id="form"></div></html>'''
        responses = {"/": (200, {}, html)}

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is True
        assert result.auth_type == "js_rendered"

    @pytest.mark.asyncio
    async def test_js_get_element_password(self):
        """Detect getElementById("password") in JS."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        html = '''<html><script>
            var pw = document.getElementById("password");
            var user = document.getElementById("username");
            fetch("/api/login", {method: "POST", body: JSON.stringify({u: user.value, p: pw.value})});
        </script></html>'''
        responses = {"/": (200, {}, html)}

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is True
        assert result.auth_type == "js_rendered"

    @pytest.mark.asyncio
    async def test_js_fetch_auth_endpoint(self):
        """Detect fetch() or XMLHttpRequest to auth-related URL."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        html = '''<html><script>
            function doLogin() {
                $.post("/api/auth", {username: u, password: p});
            }
        </script></html>'''
        responses = {"/": (200, {}, html)}

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is True
        assert result.auth_type == "js_rendered"

    @pytest.mark.asyncio
    async def test_no_js_indicators(self):
        """Page with JS but no login indicators returns has_login=False."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        html = '''<html><script>
            var canvas = document.getElementById("stream");
            var ctx = canvas.getContext("2d");
        </script></html>'''
        responses = {"/": (200, {}, html)}

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is False


class TestFormDetectorHTTPAuth:
    """HTTP Auth Analyzer: detect 401 responses."""

    @pytest.mark.asyncio
    async def test_http_401_basic(self):
        """HTTP 401 with Basic WWW-Authenticate."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        responses = {"/": (401, {"WWW-Authenticate": "Basic realm=\"camera\""}, "")}

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is True
        assert result.auth_type == "basic"

    @pytest.mark.asyncio
    async def test_http_401_digest(self):
        """HTTP 401 with Digest WWW-Authenticate."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        responses = {"/": (401, {"WWW-Authenticate": 'Digest realm="cam", nonce="abc"'}, "")}

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is True
        assert result.auth_type == "digest"


class TestFormDetectorEdgeCases:
    """Edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_connection_error_returns_no_login(self):
        """Connection failure returns has_login=False."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", side_effect=Exception("connection failed")):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is False

    @pytest.mark.asyncio
    async def test_form_preferred_over_js_indicators(self):
        """When both form and JS indicators are found, form result wins."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        html = '''<html>
            <form action="/login" method="POST">
                <input type="text" name="user">
                <input type="password" name="pass">
            </form>
            <script>
                document.getElementById("password");
                fetch("/api/auth");
            </script>
        </html>'''
        responses = {"/": (200, {}, html)}

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is True
        assert result.auth_type == "form"
        assert result.form_action == "/login"
        assert result.password_field == "pass"

    @pytest.mark.asyncio
    async def test_login_url_populated(self):
        """login_url is set to the full URL where login was found."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        html = '<html><form action="/auth"><input type="password" name="pw"></form></html>'
        responses = {
            "/": (200, {}, "<html>no login</html>"),
            "/login": (200, {}, html),
        }

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is True
        assert result.login_url == "http://1.1.1.1:80/login"

    @pytest.mark.asyncio
    async def test_https_scheme(self):
        """Protocol 'https' uses https:// scheme."""
        from src.layers.layer3_cve_searcher.auth_checker.form_detector import FormDetector
        from src.core.config import AuthCheckConfig

        html = '<html><form action="/login"><input type="password" name="pw"></form></html>'
        responses = {"/": (200, {}, html)}

        detector = FormDetector(AuthCheckConfig())
        with patch("aiohttp.ClientSession", return_value=_mock_aiohttp_session(responses)):
            result = await detector.detect("1.1.1.1", 443, "https")

        assert result.login_url == "https://1.1.1.1:443/"
