"""Tests for Layer 3 Authentication Checker."""
import sys
from pathlib import Path
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
