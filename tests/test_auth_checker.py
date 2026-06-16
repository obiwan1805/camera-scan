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
