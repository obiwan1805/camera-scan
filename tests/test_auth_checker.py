"""Tests for Layer 3 Authentication Checker."""
import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestAuthInfo:
    def test_auth_info_defaults(self):
        from src.storage.schemas import AuthInfo
        info = AuthInfo(port=22, protocol="ssh", has_login=True, auth_type="password")
        assert info.port == 22
        assert info.protocol == "ssh"
        assert info.has_login is True
        assert info.auth_type == "password"
        assert info.raw_response == ""
        assert info.msf_module is None

    def test_auth_info_full(self):
        from src.storage.schemas import AuthInfo
        info = AuthInfo(
            port=80,
            protocol="http",
            has_login=True,
            auth_type="basic",
            raw_response="HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic",
            msf_module="auxiliary/scanner/http/http_login",
        )
        assert info.auth_type == "basic"
        assert "401" in info.raw_response
        assert info.msf_module == "auxiliary/scanner/http/http_login"

    def test_camera_fingerprint_has_auth_info(self):
        from src.storage.schemas import CameraFingerprint, Fingerprint, AuthInfo
        item = CameraFingerprint(
            ip="1.1.1.1", port=80,
            fingerprint=Fingerprint(vendor="hikvision"),
            auth_info=[AuthInfo(port=80, protocol="http", has_login=True, auth_type="basic")],
        )
        assert len(item.auth_info) == 1
        assert item.auth_info[0].has_login is True

    def test_camera_fingerprint_auth_info_default_empty(self):
        from src.storage.schemas import CameraFingerprint, Fingerprint
        item = CameraFingerprint(ip="1.1.1.1", port=80, fingerprint=Fingerprint())
        assert item.auth_info == []


class TestAuthCheckConfig:
    def test_defaults(self):
        from src.core.config import AuthCheckConfig
        config = AuthCheckConfig()
        assert config.enabled is True
        assert config.banner_timeout == 5
        assert config.msf_detect_timeout == 15
        assert config.max_auth_concurrency == 50

    def test_layer3_config_has_auth(self):
        from src.core.config import Layer3Config
        config = Layer3Config()
        assert config.auth.enabled is True
        assert config.auth.banner_timeout == 5

    def test_from_yaml_parses_auth(self):
        from src.core.config import Config
        config = Config.from_yaml("config/default.yaml")
        assert config.layer3.auth.enabled is True
        assert config.layer3.auth.banner_timeout == 5
        assert config.layer3.auth.msf_detect_timeout == 15
        assert config.layer3.auth.max_auth_concurrency == 50


class TestProtocolMap:
    def test_known_ssh(self):
        from src.layers.layer3_cve_searcher.auth_checker.protocol_map import get_protocol
        assert get_protocol(22) == "ssh"
        assert get_protocol(2222) == "ssh"

    def test_known_telnet(self):
        from src.layers.layer3_cve_searcher.auth_checker.protocol_map import get_protocol
        assert get_protocol(23) == "telnet"

    def test_known_ftp(self):
        from src.layers.layer3_cve_searcher.auth_checker.protocol_map import get_protocol
        assert get_protocol(21) == "ftp"

    def test_known_rtsp(self):
        from src.layers.layer3_cve_searcher.auth_checker.protocol_map import get_protocol
        assert get_protocol(554) == "rtsp"
        assert get_protocol(8554) == "rtsp"

    def test_known_http(self):
        from src.layers.layer3_cve_searcher.auth_checker.protocol_map import get_protocol
        assert get_protocol(80) == "http"
        assert get_protocol(8080) == "http"
        assert get_protocol(8000) == "http"
        assert get_protocol(8888) == "http"

    def test_known_https(self):
        from src.layers.layer3_cve_searcher.auth_checker.protocol_map import get_protocol
        assert get_protocol(443) == "https"
        assert get_protocol(8443) == "https"

    def test_unknown_port(self):
        from src.layers.layer3_cve_searcher.auth_checker.protocol_map import get_protocol
        assert get_protocol(9999) == "unknown"
        assert get_protocol(12345) == "unknown"

    def test_is_web_protocol(self):
        from src.layers.layer3_cve_searcher.auth_checker.protocol_map import is_web_protocol
        assert is_web_protocol("http") is True
        assert is_web_protocol("https") is True
        assert is_web_protocol("ssh") is False
        assert is_web_protocol("unknown") is False


class TestBannerDetector:
    @pytest.fixture
    def detector(self):
        from src.layers.layer3_cve_searcher.auth_checker.banner_detector import BannerDetector
        from src.core.config import AuthCheckConfig
        return BannerDetector(AuthCheckConfig())

    @pytest.mark.asyncio
    async def test_detect_ssh_banner(self, detector):
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)):
            result = await detector.detect("1.1.1.1", 22, "ssh")

        assert result.has_login is True
        assert result.protocol == "ssh"
        assert result.auth_type == "password"
        assert "SSH-2.0" in result.raw_response

    @pytest.mark.asyncio
    async def test_detect_telnet_login(self, detector):
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"\xff\xfd\x01\xff\xfd\x1flogin: ")
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)):
            result = await detector.detect("1.1.1.1", 23, "telnet")

        assert result.has_login is True
        assert result.protocol == "telnet"
        assert result.auth_type == "password"

    @pytest.mark.asyncio
    async def test_detect_rtsp_401(self, detector):
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(
            return_value=b"RTSP/1.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"LIVE555\"\r\n\r\n"
        )
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)):
            result = await detector.detect("1.1.1.1", 554, "rtsp")

        assert result.has_login is True
        assert result.protocol == "rtsp"
        assert result.auth_type == "digest"

    @pytest.mark.asyncio
    async def test_detect_rtsp_200_no_auth(self, detector):
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(
            return_value=b"RTSP/1.0 200 OK\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n"
        )
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)):
            result = await detector.detect("1.1.1.1", 554, "rtsp")

        assert result.has_login is False

    @pytest.mark.asyncio
    async def test_detect_ftp_password_required(self, detector):
        mock_reader = AsyncMock()
        mock_reader.readline = AsyncMock(side_effect=[
            b"220 Welcome to FTP\r\n",
            b"331 Password required\r\n",
        ])
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)):
            result = await detector.detect("1.1.1.1", 21, "ftp")

        assert result.has_login is True
        assert result.auth_type == "password"

    @pytest.mark.asyncio
    async def test_detect_ftp_anonymous_ok(self, detector):
        mock_reader = AsyncMock()
        mock_reader.readline = AsyncMock(side_effect=[
            b"220 Welcome to FTP\r\n",
            b"230 Anonymous login ok\r\n",
        ])
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)):
            result = await detector.detect("1.1.1.1", 21, "ftp")

        assert result.has_login is True
        assert result.auth_type == "anonymous"

    @pytest.mark.asyncio
    async def test_detect_unknown_no_banner(self, detector):
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)):
            result = await detector.detect("1.1.1.1", 9999, "unknown")

        assert result.has_login is False
        assert result.protocol == "unknown"

    @pytest.mark.asyncio
    async def test_detect_connection_refused(self, detector):
        with patch("asyncio.open_connection", new_callable=AsyncMock, side_effect=ConnectionRefusedError):
            result = await detector.detect("1.1.1.1", 22, "ssh")

        assert result.has_login is False

    @pytest.mark.asyncio
    async def test_raw_response_truncated(self, detector):
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH " + b"A" * 600)
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)):
            result = await detector.detect("1.1.1.1", 22, "ssh")

        assert len(result.raw_response) <= 512


class TestMSFDetector:
    @pytest.fixture
    def detector(self):
        from src.layers.layer3_cve_searcher.auth_checker.msf_detector import MSFDetector
        from src.core.config import AuthCheckConfig
        msf_client = AsyncMock()
        return MSFDetector(AuthCheckConfig(), msf_client)

    @pytest.mark.asyncio
    async def test_detect_http_basic_auth(self, detector):
        """MSF http_login detects Basic auth on 401 response."""
        detector._msf_client._call = AsyncMock(side_effect=[
            {"id": "1"},
            None,
            {"data": b"[*] 1.1.1.1:80 - HTTP 401 - requires authentication\n[*] WWW-Authenticate: Basic realm=\"camera\"\n", "busy": False},
            None,
        ])
        detector._msf_client._val = MagicMock(side_effect=lambda r, k: r.get(k) if r else None)

        result = await detector.detect("1.1.1.1", 80, "http")
        assert result.has_login is True
        assert result.auth_type in ("basic", "digest", "unknown")

    @pytest.mark.asyncio
    async def test_detect_http_form_login(self, detector):
        """Form heuristic detects password input in HTML."""
        import aiohttp
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='<html><form><input type="password" name="pw"></form></html>')

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_response),
            __aexit__=AsyncMock(return_value=False),
        ))

        mock_session_instance = AsyncMock()
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_instance.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session_instance):
            result = await detector._detect_form_login("1.1.1.1", 80, "http")

        assert result is not None
        assert result.has_login is True
        assert result.auth_type == "form"

    @pytest.mark.asyncio
    async def test_detect_http_no_form(self, detector):
        """No password input means no form login detected."""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='<html><h1>Camera Stream</h1></html>')

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_response),
            __aexit__=AsyncMock(return_value=False),
        ))

        mock_session_instance = AsyncMock()
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_instance.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session_instance):
            result = await detector._detect_form_login("1.1.1.1", 80, "http")

        assert result is None

    @pytest.mark.asyncio
    async def test_detect_msf_client_none(self):
        """MSFDetector with no MSF client falls back to form-only detection."""
        from src.layers.layer3_cve_searcher.auth_checker.msf_detector import MSFDetector
        from src.core.config import AuthCheckConfig
        detector = MSFDetector(AuthCheckConfig(), msf_client=None)

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='<html><h1>No login</h1></html>')

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_response),
            __aexit__=AsyncMock(return_value=False),
        ))

        mock_session_instance = AsyncMock()
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_instance.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session_instance):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is False

    @pytest.mark.asyncio
    async def test_detect_connection_error(self, detector):
        """Connection error results in has_login=False."""
        detector._msf_client = None

        with patch("aiohttp.ClientSession", side_effect=Exception("connection failed")):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is False


class TestAuthChecker:
    @pytest.fixture
    def checker(self):
        from src.layers.layer3_cve_searcher.auth_checker import AuthChecker
        from src.core.config import AuthCheckConfig
        return AuthChecker(AuthCheckConfig(), msf_client=None)

    @pytest.mark.asyncio
    async def test_check_ssh_port(self, checker):
        """SSH port routes to BannerDetector."""
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH_8.9\r\n")
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)):
            from src.storage.schemas import CameraFingerprint, Fingerprint
            item = CameraFingerprint(ip="1.1.1.1", port=22, fingerprint=Fingerprint())
            results = await checker.check(item)

        assert len(results) == 1
        assert results[0].protocol == "ssh"
        assert results[0].has_login is True

    @pytest.mark.asyncio
    async def test_check_unknown_port_no_banner(self, checker):
        """Unknown port with timeout returns has_login=False."""
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", new_callable=AsyncMock, return_value=(mock_reader, mock_writer)):
            from src.storage.schemas import CameraFingerprint, Fingerprint
            item = CameraFingerprint(ip="1.1.1.1", port=9999, fingerprint=Fingerprint())
            results = await checker.check(item)

        assert len(results) == 1
        assert results[0].has_login is False

    @pytest.mark.asyncio
    async def test_check_http_port_uses_msf_detector(self, checker):
        """HTTP port routes to MSFDetector (form fallback when msf_client=None)."""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='<form><input type="password"></form>')

        mock_session_instance = AsyncMock()
        mock_session_instance.get = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_response),
            __aexit__=AsyncMock(return_value=False),
        ))
        mock_session_instance.__aenter__ = AsyncMock(return_value=mock_session_instance)
        mock_session_instance.__aexit__ = AsyncMock(return_value=False)

        with patch("aiohttp.ClientSession", return_value=mock_session_instance):
            from src.storage.schemas import CameraFingerprint, Fingerprint
            item = CameraFingerprint(ip="1.1.1.1", port=80, fingerprint=Fingerprint())
            results = await checker.check(item)

        assert len(results) == 1
        assert results[0].has_login is True
        assert results[0].auth_type == "form"

    @pytest.mark.asyncio
    async def test_check_disabled(self):
        """When disabled, check returns empty list."""
        from src.layers.layer3_cve_searcher.auth_checker import AuthChecker
        from src.core.config import AuthCheckConfig
        checker = AuthChecker(AuthCheckConfig(enabled=False), msf_client=None)

        from src.storage.schemas import CameraFingerprint, Fingerprint
        item = CameraFingerprint(ip="1.1.1.1", port=22, fingerprint=Fingerprint())
        results = await checker.check(item)
        assert results == []


class TestCVESearcherAuthIntegration:
    @pytest.mark.asyncio
    async def test_process_includes_auth_info(self):
        """process() populates auth_info when auth checker is enabled."""
        from src.layers.layer3_cve_searcher.cve_searcher import CVESearcher
        from src.core.config import Layer3Config, NVDConfig, MSFConfig, AuthCheckConfig
        from src.storage.schemas import CameraFingerprint, Fingerprint, AuthInfo

        config = Layer3Config(nvd=NVDConfig(), msf=MSFConfig(), auth=AuthCheckConfig())
        searcher = CVESearcher(config)
        searcher._nvd_client = AsyncMock()
        searcher._msf_client = AsyncMock()

        mock_auth_checker = AsyncMock()
        mock_auth_checker.check = AsyncMock(return_value=[
            AuthInfo(port=80, protocol="http", has_login=True, auth_type="form"),
        ])
        searcher._auth_checker = mock_auth_checker

        item = CameraFingerprint(
            ip="1.1.1.1", port=80, weight=0.0,
            fingerprint=Fingerprint(),
        )

        result = await searcher.process(item)
        assert result is not None
        assert len(result.auth_info) == 1
        assert result.auth_info[0].has_login is True
        assert result.auth_info[0].auth_type == "form"

    @pytest.mark.asyncio
    async def test_process_auth_disabled(self):
        """process() leaves auth_info empty when disabled."""
        from src.layers.layer3_cve_searcher.cve_searcher import CVESearcher
        from src.core.config import Layer3Config, NVDConfig, MSFConfig, AuthCheckConfig
        from src.storage.schemas import CameraFingerprint, Fingerprint

        config = Layer3Config(nvd=NVDConfig(), msf=MSFConfig(), auth=AuthCheckConfig(enabled=False))
        searcher = CVESearcher(config)
        searcher._nvd_client = AsyncMock()
        searcher._msf_client = AsyncMock()

        item = CameraFingerprint(
            ip="1.1.1.1", port=80, weight=0.0,
            fingerprint=Fingerprint(),
        )

        result = await searcher.process(item)
        assert result is not None
        assert result.auth_info == []

    @pytest.mark.asyncio
    async def test_process_auth_failure_does_not_break_cve(self):
        """Auth checker failure doesn't prevent CVE search from completing."""
        from src.layers.layer3_cve_searcher.cve_searcher import CVESearcher
        from src.core.config import Layer3Config, NVDConfig, MSFConfig, AuthCheckConfig
        from src.storage.schemas import CameraFingerprint, Fingerprint

        config = Layer3Config(nvd=NVDConfig(), msf=MSFConfig(), auth=AuthCheckConfig())
        searcher = CVESearcher(config)
        searcher._nvd_client = AsyncMock()
        searcher._msf_client = AsyncMock()

        mock_auth_checker = AsyncMock()
        mock_auth_checker.check = AsyncMock(side_effect=Exception("auth check exploded"))
        searcher._auth_checker = mock_auth_checker

        item = CameraFingerprint(
            ip="1.1.1.1", port=80, weight=0.0,
            fingerprint=Fingerprint(),
        )

        result = await searcher.process(item)
        assert result is not None
        assert result.auth_info == []

    @pytest.mark.asyncio
    async def test_auth_progress_counters(self):
        """Auth counters are incremented after processing."""
        from src.layers.layer3_cve_searcher.cve_searcher import CVESearcher
        from src.core.config import Layer3Config, NVDConfig, MSFConfig, AuthCheckConfig
        from src.storage.schemas import CameraFingerprint, Fingerprint, AuthInfo

        config = Layer3Config(nvd=NVDConfig(), msf=MSFConfig(), auth=AuthCheckConfig())
        searcher = CVESearcher(config)
        searcher._nvd_client = AsyncMock()
        searcher._msf_client = AsyncMock()

        mock_auth_checker = AsyncMock()
        mock_auth_checker.check = AsyncMock(return_value=[
            AuthInfo(port=22, protocol="ssh", has_login=True, auth_type="password"),
        ])
        searcher._auth_checker = mock_auth_checker

        item = CameraFingerprint(
            ip="1.1.1.1", port=22, weight=0.0,
            fingerprint=Fingerprint(),
        )

        await searcher.process(item)
        assert searcher._auth_checked == 1
        assert searcher._auth_found == 1
