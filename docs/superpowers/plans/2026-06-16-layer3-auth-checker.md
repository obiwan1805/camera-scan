# Layer 3 Authentication Checker — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add authentication detection to Layer 3 — identify whether scanned targets have login mechanisms on their open ports, running in parallel with CVE search.

**Architecture:** New `auth_checker/` sub-module inside `layer3_cve_searcher/`. `AuthChecker` orchestrates two detectors: `BannerDetector` (async TCP for SSH/Telnet/RTSP/FTP/unknown) and `MSFDetector` (Metasploit auxiliary modules for HTTP/HTTPS + form heuristic). Integrated into `CVESearcher._process_item()` via `asyncio.gather()`.

**Tech Stack:** Python 3, asyncio, aiohttp, msgpack (existing MSFRPCClient), pydantic (existing schemas), pytest + pytest-asyncio

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `src/layers/layer3_cve_searcher/auth_checker/__init__.py` | Export `AuthChecker` |
| Create | `src/layers/layer3_cve_searcher/auth_checker/protocol_map.py` | Port → protocol mapping |
| Create | `src/layers/layer3_cve_searcher/auth_checker/banner_detector.py` | TCP banner grabbing for known protocols + unknown |
| Create | `src/layers/layer3_cve_searcher/auth_checker/msf_detector.py` | MSF auxiliary + HTTP form heuristic |
| Create | `src/layers/layer3_cve_searcher/auth_checker/auth_checker.py` | Orchestrator dispatching to detectors |
| Create | `tests/test_auth_checker.py` | All tests for auth checker |
| Modify | `src/storage/schemas.py:61-68` | Add `AuthInfo` model, add `auth_info` field to `CameraFingerprint` |
| Modify | `src/core/config.py:54-59` | Add `AuthCheckConfig` dataclass, add `auth` field to `Layer3Config` |
| Modify | `src/core/config.py:106-123` | Update `Config.from_yaml()` to parse `layer3.auth` |
| Modify | `config/default.yaml:34-50` | Add `auth` section under `layer3` |
| Modify | `src/layers/layer3_cve_searcher/cve_searcher.py:100-145` | Parallel auth check in `_process_item()` |
| Modify | `src/cli.py:663-668` | Add `--skip-auth` flag to `run-layer3` |

---

### Task 1: AuthInfo Data Model

**Files:**
- Modify: `src/storage/schemas.py:49-68`
- Test: `tests/test_auth_checker.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/test_auth_checker.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_auth_checker.py::TestAuthInfo -v`
Expected: FAIL with `ImportError` — `AuthInfo` does not exist yet.

- [ ] **Step 3: Add AuthInfo model and update CameraFingerprint**

In `src/storage/schemas.py`, add `AuthInfo` class before `CVEEntry` (after line 47) and add `auth_info` field to `CameraFingerprint`:

```python
class AuthInfo(BaseModel):
    """Authentication detection result for a single port."""
    port: int
    protocol: str
    has_login: bool
    auth_type: str
    raw_response: str = ""
    msf_module: Optional[str] = None
```

In `CameraFingerprint`, add after `weight`:

```python
    auth_info: List["AuthInfo"] = []
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_auth_checker.py::TestAuthInfo -v`
Expected: All 4 tests PASS.

- [ ] **Step 5: Run existing tests to check no regressions**

Run: `pytest tests/test_layer3.py -v`
Expected: All 42 tests PASS — `auth_info` defaults to `[]` so existing code is unaffected.

- [ ] **Step 6: Commit**

```bash
git add src/storage/schemas.py tests/test_auth_checker.py
git commit -m "feat(layer3): add AuthInfo data model for authentication detection"
```

---

### Task 2: AuthCheckConfig

**Files:**
- Modify: `src/core/config.py:54-59`
- Modify: `src/core/config.py:106-123`
- Modify: `config/default.yaml:34-50`
- Test: `tests/test_auth_checker.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_auth_checker.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_auth_checker.py::TestAuthCheckConfig -v`
Expected: FAIL with `ImportError` — `AuthCheckConfig` does not exist.

- [ ] **Step 3: Add AuthCheckConfig dataclass**

In `src/core/config.py`, add after `MSFConfig` (after line 50):

```python
@dataclass
class AuthCheckConfig:
    enabled: bool = True
    banner_timeout: int = 5
    msf_detect_timeout: int = 15
    max_auth_concurrency: int = 50
```

In `Layer3Config`, add field after `module_concurrency`:

```python
    auth: AuthCheckConfig = field(default_factory=AuthCheckConfig)
```

- [ ] **Step 4: Update Config.from_yaml() to parse auth section**

In `Config.from_yaml()`, update the `Layer3Config` construction (around line 106-123). Add after `module_concurrency=...`:

```python
                auth=AuthCheckConfig(
                    enabled=data.get("layer3", {}).get("auth", {}).get("enabled", True),
                    banner_timeout=data.get("layer3", {}).get("auth", {}).get("banner_timeout", 5),
                    msf_detect_timeout=data.get("layer3", {}).get("auth", {}).get("msf_detect_timeout", 15),
                    max_auth_concurrency=data.get("layer3", {}).get("auth", {}).get("max_auth_concurrency", 50),
                ),
```

- [ ] **Step 5: Add auth section to default.yaml**

Add to `config/default.yaml` under `layer3:`, after `module_concurrency: 32`:

```yaml
  auth:
    enabled: true
    banner_timeout: 5
    msf_detect_timeout: 15
    max_auth_concurrency: 50
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_auth_checker.py::TestAuthCheckConfig tests/test_layer3.py::TestLayer3Config -v`
Expected: All tests PASS.

- [ ] **Step 7: Commit**

```bash
git add src/core/config.py config/default.yaml tests/test_auth_checker.py
git commit -m "feat(layer3): add AuthCheckConfig for authentication detection settings"
```

---

### Task 3: Protocol Map

**Files:**
- Create: `src/layers/layer3_cve_searcher/auth_checker/__init__.py`
- Create: `src/layers/layer3_cve_searcher/auth_checker/protocol_map.py`
- Test: `tests/test_auth_checker.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_auth_checker.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_auth_checker.py::TestProtocolMap -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Create protocol_map.py and __init__.py**

Create `src/layers/layer3_cve_searcher/auth_checker/__init__.py`:

```python
"""Layer 3: Authentication Checker sub-module."""
```

Create `src/layers/layer3_cve_searcher/auth_checker/protocol_map.py`:

```python
"""Port-to-protocol mapping for authentication detection."""

KNOWN_PROTOCOLS = {
    22: "ssh",
    2222: "ssh",
    23: "telnet",
    21: "ftp",
    554: "rtsp",
    8554: "rtsp",
    80: "http",
    8080: "http",
    8000: "http",
    8888: "http",
    443: "https",
    8443: "https",
}

WEB_PROTOCOLS = {"http", "https"}


def get_protocol(port: int) -> str:
    return KNOWN_PROTOCOLS.get(port, "unknown")


def is_web_protocol(protocol: str) -> bool:
    return protocol in WEB_PROTOCOLS
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_auth_checker.py::TestProtocolMap -v`
Expected: All 8 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/layers/layer3_cve_searcher/auth_checker/ tests/test_auth_checker.py
git commit -m "feat(layer3): add protocol map for auth checker port classification"
```

---

### Task 4: BannerDetector

**Files:**
- Create: `src/layers/layer3_cve_searcher/auth_checker/banner_detector.py`
- Test: `tests/test_auth_checker.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_auth_checker.py`:

```python
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


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

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
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

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
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

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
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

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
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

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
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

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
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

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            result = await detector.detect("1.1.1.1", 9999, "unknown")

        assert result.has_login is False
        assert result.protocol == "unknown"

    @pytest.mark.asyncio
    async def test_detect_connection_refused(self, detector):
        with patch("asyncio.open_connection", side_effect=ConnectionRefusedError):
            result = await detector.detect("1.1.1.1", 22, "ssh")

        assert result.has_login is False

    @pytest.mark.asyncio
    async def test_raw_response_truncated(self, detector):
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH " + b"A" * 600)
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            result = await detector.detect("1.1.1.1", 22, "ssh")

        assert len(result.raw_response) <= 512
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_auth_checker.py::TestBannerDetector -v`
Expected: FAIL with `ModuleNotFoundError` — `banner_detector` does not exist.

- [ ] **Step 3: Implement BannerDetector**

Create `src/layers/layer3_cve_searcher/auth_checker/banner_detector.py`:

```python
"""TCP banner grabbing for authentication detection on known protocols."""
import asyncio
from src.core.config import AuthCheckConfig
from src.storage.schemas import AuthInfo
from src.utils.logging import setup_logger

MAX_RAW_RESPONSE = 512


class BannerDetector:
    def __init__(self, config: AuthCheckConfig):
        self._timeout = config.banner_timeout
        self._logger = setup_logger("BannerDetector")

    async def detect(self, ip: str, port: int, protocol: str) -> AuthInfo:
        try:
            if protocol == "ssh":
                return await self._detect_ssh(ip, port)
            elif protocol == "telnet":
                return await self._detect_telnet(ip, port)
            elif protocol == "rtsp":
                return await self._detect_rtsp(ip, port)
            elif protocol == "ftp":
                return await self._detect_ftp(ip, port)
            else:
                return await self._detect_unknown(ip, port)
        except (ConnectionRefusedError, ConnectionResetError, OSError, asyncio.TimeoutError):
            return AuthInfo(port=port, protocol=protocol, has_login=False, auth_type="unknown")

    async def _detect_ssh(self, ip: str, port: int) -> AuthInfo:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=self._timeout
        )
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=self._timeout)
            banner = data.decode(errors="replace")
            has_login = "SSH-" in banner
            return AuthInfo(
                port=port, protocol="ssh", has_login=has_login,
                auth_type="password" if has_login else "unknown",
                raw_response=banner[:MAX_RAW_RESPONSE],
            )
        finally:
            writer.close()
            await writer.wait_closed()

    async def _detect_telnet(self, ip: str, port: int) -> AuthInfo:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=self._timeout
        )
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=self._timeout)
            text = data.decode(errors="replace").lower()
            has_login = any(kw in text for kw in ["login:", "username:", "password:"])
            return AuthInfo(
                port=port, protocol="telnet", has_login=has_login,
                auth_type="password" if has_login else "unknown",
                raw_response=data.decode(errors="replace")[:MAX_RAW_RESPONSE],
            )
        finally:
            writer.close()
            await writer.wait_closed()

    async def _detect_rtsp(self, ip: str, port: int) -> AuthInfo:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=self._timeout
        )
        try:
            request = f"OPTIONS rtsp://{ip}:{port} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(2048), timeout=self._timeout)
            text = data.decode(errors="replace")
            has_login = "401" in text
            auth_type = "unknown"
            if has_login:
                text_lower = text.lower()
                if "digest" in text_lower:
                    auth_type = "digest"
                elif "basic" in text_lower:
                    auth_type = "basic"
                else:
                    auth_type = "unknown"
            return AuthInfo(
                port=port, protocol="rtsp", has_login=has_login,
                auth_type=auth_type,
                raw_response=text[:MAX_RAW_RESPONSE],
            )
        finally:
            writer.close()
            await writer.wait_closed()

    async def _detect_ftp(self, ip: str, port: int) -> AuthInfo:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=self._timeout
        )
        try:
            welcome = await asyncio.wait_for(reader.readline(), timeout=self._timeout)
            welcome_text = welcome.decode(errors="replace")
            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            response = await asyncio.wait_for(reader.readline(), timeout=self._timeout)
            response_text = response.decode(errors="replace")
            code = response_text[:3]
            if code == "331":
                auth_type = "password"
            elif code == "230":
                auth_type = "anonymous"
            else:
                return AuthInfo(
                    port=port, protocol="ftp", has_login=False, auth_type="unknown",
                    raw_response=(welcome_text + response_text)[:MAX_RAW_RESPONSE],
                )
            return AuthInfo(
                port=port, protocol="ftp", has_login=True,
                auth_type=auth_type,
                raw_response=(welcome_text + response_text)[:MAX_RAW_RESPONSE],
            )
        finally:
            writer.close()
            await writer.wait_closed()

    async def _detect_unknown(self, ip: str, port: int) -> AuthInfo:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=self._timeout
        )
        try:
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=self._timeout)
            except asyncio.TimeoutError:
                return AuthInfo(port=port, protocol="unknown", has_login=False, auth_type="unknown")
            text = data.decode(errors="replace")
            text_lower = text.lower()
            if "SSH-" in text:
                return AuthInfo(
                    port=port, protocol="ssh", has_login=True,
                    auth_type="password", raw_response=text[:MAX_RAW_RESPONSE],
                )
            if any(kw in text_lower for kw in ["login:", "username:", "password:"]):
                return AuthInfo(
                    port=port, protocol="telnet", has_login=True,
                    auth_type="password", raw_response=text[:MAX_RAW_RESPONSE],
                )
            if "RTSP/" in text:
                has_login = "401" in text
                return AuthInfo(
                    port=port, protocol="rtsp", has_login=has_login,
                    auth_type="unknown", raw_response=text[:MAX_RAW_RESPONSE],
                )
            if text.startswith("220"):
                return AuthInfo(
                    port=port, protocol="ftp", has_login=True,
                    auth_type="unknown", raw_response=text[:MAX_RAW_RESPONSE],
                )
            return AuthInfo(
                port=port, protocol="unknown", has_login=False,
                auth_type="unknown", raw_response=text[:MAX_RAW_RESPONSE],
            )
        finally:
            writer.close()
            await writer.wait_closed()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_auth_checker.py::TestBannerDetector -v`
Expected: All 9 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/layers/layer3_cve_searcher/auth_checker/banner_detector.py tests/test_auth_checker.py
git commit -m "feat(layer3): add BannerDetector for TCP banner-based auth detection"
```

---

### Task 5: MSFDetector

**Files:**
- Create: `src/layers/layer3_cve_searcher/auth_checker/msf_detector.py`
- Test: `tests/test_auth_checker.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_auth_checker.py`:

```python
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
        detector._msf_client._val = MagicMock(side_effect=lambda r, k: r.get(k))

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

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await detector._detect_form_login("1.1.1.1", 80, "http")

        assert result is not None
        assert result.has_login is True
        assert result.auth_type == "form"

    @pytest.mark.asyncio
    async def test_detect_http_no_form(self, detector):
        """No password input → no form login detected."""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='<html><h1>Camera Stream</h1></html>')

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_response),
            __aexit__=AsyncMock(return_value=False),
        ))

        with patch("aiohttp.ClientSession", return_value=mock_session):
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

        with patch("aiohttp.ClientSession", return_value=mock_session):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is False

    @pytest.mark.asyncio
    async def test_detect_connection_error(self, detector):
        """Connection error → has_login=False."""
        detector._msf_client = None

        with patch("aiohttp.ClientSession", side_effect=Exception("connection failed")):
            result = await detector.detect("1.1.1.1", 80, "http")

        assert result.has_login is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_auth_checker.py::TestMSFDetector -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Implement MSFDetector**

Create `src/layers/layer3_cve_searcher/auth_checker/msf_detector.py`:

```python
"""MSF auxiliary scanner + HTTP form heuristic for web auth detection."""
import asyncio
import re
from typing import Optional
import aiohttp
from src.core.config import AuthCheckConfig
from src.storage.schemas import AuthInfo
from src.utils.logging import setup_logger

MAX_RAW_RESPONSE = 512

LOGIN_PATHS = ["/", "/login", "/login.html", "/admin", "/cgi-bin/login"]
LOGIN_TITLE_KEYWORDS = re.compile(r"login|sign\s*in|authentication|log\s*in", re.IGNORECASE)
PASSWORD_INPUT = re.compile(r'<input[^>]*type=["\']?password', re.IGNORECASE)


class MSFDetector:
    def __init__(self, config: AuthCheckConfig, msf_client):
        self._config = config
        self._msf_client = msf_client
        self._logger = setup_logger("MSFDetector")

    async def detect(self, ip: str, port: int, protocol: str) -> AuthInfo:
        scheme = "https" if protocol == "https" else "http"
        msf_result = None
        form_result = None

        try:
            tasks = []
            if self._msf_client:
                tasks.append(self._detect_msf_http(ip, port))
            tasks.append(self._detect_form_login(ip, port, scheme))
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, AuthInfo) and r.has_login:
                    return r
                if isinstance(r, AuthInfo):
                    if msf_result is None:
                        msf_result = r
                    else:
                        form_result = r
        except Exception as e:
            self._logger.warning(f"Auth detection failed for {ip}:{port}: {e}")

        return AuthInfo(
            port=port, protocol=protocol, has_login=False, auth_type="unknown",
        )

    async def _detect_msf_http(self, ip: str, port: int) -> AuthInfo:
        console_id = None
        try:
            resp = await self._msf_client._call("console.create")
            console_id = self._msf_client._val(resp, "id")
            if isinstance(console_id, bytes):
                console_id = console_id.decode()

            cmd = (
                f"use auxiliary/scanner/http/http_login\n"
                f"set RHOSTS {ip}\n"
                f"set RPORT {port}\n"
                f"set STOP_ON_SUCCESS false\n"
                f"set BLANK_PASSWORDS false\n"
                f"set VERBOSE true\n"
                f"run\n"
            )
            await self._msf_client._call("console.write", str(console_id), cmd)

            output = ""
            elapsed = 0
            interval = 2
            timeout = self._config.msf_detect_timeout

            while elapsed < timeout:
                await asyncio.sleep(interval)
                elapsed += interval
                resp = await self._msf_client._call("console.read", str(console_id))
                chunk = self._msf_client._val(resp, "data") or b""
                if isinstance(chunk, bytes):
                    chunk = chunk.decode(errors="replace")
                output += chunk
                busy = self._msf_client._val(resp, "busy")
                if not busy and elapsed >= interval * 2:
                    break

            auth_type = "unknown"
            has_login = False
            output_lower = output.lower()
            if "401" in output or "www-authenticate" in output_lower:
                has_login = True
                if "basic" in output_lower:
                    auth_type = "basic"
                elif "digest" in output_lower:
                    auth_type = "digest"

            return AuthInfo(
                port=port, protocol="http", has_login=has_login,
                auth_type=auth_type,
                raw_response=output[:MAX_RAW_RESPONSE],
                msf_module="auxiliary/scanner/http/http_login",
            )
        except Exception as e:
            self._logger.warning(f"MSF http_login failed for {ip}:{port}: {e}")
            return AuthInfo(port=port, protocol="http", has_login=False, auth_type="unknown")
        finally:
            if console_id is not None:
                try:
                    await self._msf_client._call("console.destroy", str(console_id))
                except Exception:
                    pass

    async def _detect_form_login(self, ip: str, port: int, scheme: str) -> Optional[AuthInfo]:
        try:
            timeout = aiohttp.ClientTimeout(total=self._config.banner_timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for path in LOGIN_PATHS:
                    url = f"{scheme}://{ip}:{port}{path}"
                    try:
                        async with session.get(url, ssl=False, allow_redirects=True) as resp:
                            if resp.status == 401:
                                auth_header = resp.headers.get("WWW-Authenticate", "")
                                auth_type = "basic" if "basic" in auth_header.lower() else (
                                    "digest" if "digest" in auth_header.lower() else "unknown"
                                )
                                return AuthInfo(
                                    port=port, protocol=scheme, has_login=True,
                                    auth_type=auth_type,
                                    raw_response=f"HTTP 401 at {path}"[:MAX_RAW_RESPONSE],
                                )
                            html = await resp.text(errors="replace")
                            if PASSWORD_INPUT.search(html):
                                return AuthInfo(
                                    port=port, protocol=scheme, has_login=True,
                                    auth_type="form",
                                    raw_response=f"Password input found at {path}"[:MAX_RAW_RESPONSE],
                                )
                    except Exception:
                        continue
        except Exception as e:
            self._logger.debug(f"Form detection failed for {ip}:{port}: {e}")
        return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_auth_checker.py::TestMSFDetector -v`
Expected: All 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/layers/layer3_cve_searcher/auth_checker/msf_detector.py tests/test_auth_checker.py
git commit -m "feat(layer3): add MSFDetector for web auth detection via MSF + form heuristic"
```

---

### Task 6: AuthChecker Orchestrator

**Files:**
- Create: `src/layers/layer3_cve_searcher/auth_checker/auth_checker.py`
- Modify: `src/layers/layer3_cve_searcher/auth_checker/__init__.py`
- Test: `tests/test_auth_checker.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_auth_checker.py`:

```python
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

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            from src.storage.schemas import CameraFingerprint, Fingerprint
            item = CameraFingerprint(ip="1.1.1.1", port=22, fingerprint=Fingerprint())
            results = await checker.check(item)

        assert len(results) == 1
        assert results[0].protocol == "ssh"
        assert results[0].has_login is True

    @pytest.mark.asyncio
    async def test_check_unknown_port_no_banner(self, checker):
        """Unknown port with timeout → has_login=False."""
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(side_effect=asyncio.TimeoutError)
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
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

        mock_session = AsyncMock()
        mock_session.get = MagicMock(return_value=AsyncMock(
            __aenter__=AsyncMock(return_value=mock_response),
            __aexit__=AsyncMock(return_value=False),
        ))

        with patch("aiohttp.ClientSession", return_value=mock_session):
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_auth_checker.py::TestAuthChecker -v`
Expected: FAIL with `ImportError` — `AuthChecker` not exported.

- [ ] **Step 3: Implement AuthChecker**

Create `src/layers/layer3_cve_searcher/auth_checker/auth_checker.py`:

```python
"""Authentication checker orchestrator — dispatches to banner or MSF detector."""
import asyncio
from typing import List
from src.core.config import AuthCheckConfig
from src.storage.schemas import AuthInfo, CameraFingerprint
from src.utils.logging import setup_logger
from .protocol_map import get_protocol, is_web_protocol
from .banner_detector import BannerDetector
from .msf_detector import MSFDetector


class AuthChecker:
    def __init__(self, config: AuthCheckConfig, msf_client):
        self._config = config
        self._banner = BannerDetector(config)
        self._msf = MSFDetector(config, msf_client)
        self._logger = setup_logger("AuthChecker")

    async def check(self, item: CameraFingerprint) -> List[AuthInfo]:
        if not self._config.enabled:
            return []

        ip = item.ip
        port = item.port
        protocol = get_protocol(port)

        if is_web_protocol(protocol):
            result = await self._msf.detect(ip, port, protocol)
            return [result]

        result = await self._banner.detect(ip, port, protocol)

        if protocol == "unknown" and not result.has_login:
            raw = result.raw_response.lower()
            if "http/" in raw or "<html" in raw:
                web_result = await self._msf.detect(ip, port, "http")
                return [web_result]

        return [result]
```

- [ ] **Step 4: Update __init__.py to export AuthChecker**

Replace `src/layers/layer3_cve_searcher/auth_checker/__init__.py`:

```python
"""Layer 3: Authentication Checker sub-module."""
from .auth_checker import AuthChecker

__all__ = ["AuthChecker"]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_auth_checker.py::TestAuthChecker -v`
Expected: All 4 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add src/layers/layer3_cve_searcher/auth_checker/ tests/test_auth_checker.py
git commit -m "feat(layer3): add AuthChecker orchestrator dispatching to banner/MSF detectors"
```

---

### Task 7: Integrate AuthChecker into CVESearcher

**Files:**
- Modify: `src/layers/layer3_cve_searcher/cve_searcher.py:1-199`
- Test: `tests/test_auth_checker.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_auth_checker.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_auth_checker.py::TestCVESearcherAuthIntegration -v`
Expected: FAIL — `CVESearcher` does not have `_auth_checker` attribute yet.

- [ ] **Step 3: Modify CVESearcher to integrate AuthChecker**

Edit `src/layers/layer3_cve_searcher/cve_searcher.py`. Changes:

**Imports** — add at line 7 (after existing imports):

```python
from .auth_checker import AuthChecker
```

**`__init__`** — add after `self._msf_client` initialization (after line 45):

```python
        self._auth_checker: Optional[AuthChecker] = None
        if config.auth.enabled:
            self._auth_checker = AuthChecker(config.auth, msf_client=None)

        self._auth_checked = 0
        self._auth_found = 0
```

**`start()`** — add after msf client connect (after line 71), to update auth checker's MSF client:

```python
        if self._auth_checker and self._msf_client:
            self._auth_checker._msf._msf_client = self._msf_client
```

**`process()`** — replace the entire method (lines 126-145) with:

```python
    async def process(self, item: CameraFingerprint) -> Optional[CameraFingerprint]:
        """Process a CameraFingerprint: CVE search + auth check in parallel."""
        strategy_type = self._router.classify(item)

        async def _cve_search():
            if strategy_type == "skip":
                self._logger.info(f"[SKIP] {item.ip}:{item.port} — no vendor")
                return item
            try:
                if strategy_type == "high":
                    return await self._high_strategy.execute(
                        item, self._nvd_client, self._msf_client, self.storage
                    )
                else:
                    return await self._low_strategy.execute(
                        item, self._nvd_client, self._msf_client, self.storage
                    )
            except Exception as e:
                self._logger.error(f"Strategy error for {item.ip}:{item.port}: {e}")
                return item

        async def _auth_check():
            if not self._auth_checker:
                return []
            try:
                return await self._auth_checker.check(item)
            except Exception as e:
                self._logger.warning(f"Auth check failed for {item.ip}:{item.port}: {e}")
                return []

        cve_result, auth_result = await asyncio.gather(_cve_search(), _auth_check())

        result = cve_result if cve_result is not None else item
        result.auth_info = auth_result

        if auth_result:
            self._auth_checked += 1
            if any(a.has_login for a in auth_result):
                self._auth_found += 1

        return result
```

**`_status_reporter()`** — update the log line (around line 152) to include auth counters:

```python
            self._logger.info(
                f"[Progress] Processed: {self._processed} | "
                f"CVE found: {self._cve_found} | "
                f"Auth checked: {self._auth_checked} | "
                f"Auth found: {self._auth_found} | "
                f"Skipped: {self._skipped} | "
                f"Failed: {self._failed} | "
                f"Active: {self._processing_count} | "
                f"Rate: {rate:.1f}/s"
            )
```

- [ ] **Step 4: Run new tests to verify they pass**

Run: `pytest tests/test_auth_checker.py::TestCVESearcherAuthIntegration -v`
Expected: All 4 tests PASS.

- [ ] **Step 5: Run all existing tests to verify no regressions**

Run: `pytest tests/test_layer3.py tests/test_auth_checker.py -v`
Expected: All tests PASS (existing 42 + new auth tests).

- [ ] **Step 6: Commit**

```bash
git add src/layers/layer3_cve_searcher/cve_searcher.py tests/test_auth_checker.py
git commit -m "feat(layer3): integrate AuthChecker into CVESearcher with parallel execution"
```

---

### Task 8: CLI --skip-auth Flag

**Files:**
- Modify: `src/cli.py:663-668`
- Test: `tests/test_auth_checker.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_auth_checker.py`:

```python
class TestCLISkipAuth:
    def test_run_layer3_has_skip_auth_flag(self):
        """run-layer3 subparser accepts --skip-auth."""
        import argparse
        from src.cli import main
        import sys

        sys.argv = ["src.cli", "run-layer3", "--skip-auth"]
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        p_run = subparsers.add_parser("run-layer3")
        p_run.add_argument("--skip-auth", action="store_true")
        p_run.add_argument("--db")
        p_run.add_argument("--limit", type=int)
        p_run.add_argument("--vendor")
        p_run.add_argument("--concurrency", type=int, default=10)

        args = parser.parse_args(["run-layer3", "--skip-auth"])
        assert args.skip_auth is True

    def test_run_layer3_default_auth_enabled(self):
        """run-layer3 without --skip-auth has skip_auth=False."""
        import argparse

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        p_run = subparsers.add_parser("run-layer3")
        p_run.add_argument("--skip-auth", action="store_true")
        p_run.add_argument("--db")
        p_run.add_argument("--limit", type=int)
        p_run.add_argument("--vendor")
        p_run.add_argument("--concurrency", type=int, default=10)

        args = parser.parse_args(["run-layer3"])
        assert args.skip_auth is False
```

- [ ] **Step 2: Run test to verify baseline**

Run: `pytest tests/test_auth_checker.py::TestCLISkipAuth -v`
Expected: PASS (these tests use local parsers, not the actual CLI parser — they validate the pattern we'll add).

- [ ] **Step 3: Add --skip-auth flag to CLI**

In `src/cli.py`, find the `run-layer3` parser (around line 663-668). Add after `p_run.add_argument("--concurrency", ...)`:

```python
    p_run.add_argument("--skip-auth", action="store_true", help="Skip authentication detection")
```

In `cmd_run_layer3()` (around line 489), add after initializing `cve_searcher`:

```python
    if args.skip_auth:
        cve_searcher._auth_checker = None
```

- [ ] **Step 4: Run all tests**

Run: `pytest tests/test_auth_checker.py tests/test_layer3.py -v`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/cli.py tests/test_auth_checker.py
git commit -m "feat(layer3): add --skip-auth flag to run-layer3 CLI command"
```

---

### Task 9: Final Integration Test

**Files:**
- Test: `tests/test_auth_checker.py`

- [ ] **Step 1: Write full integration test**

Append to `tests/test_auth_checker.py`:

```python
class TestAuthCheckerIntegration:
    @pytest.mark.asyncio
    async def test_full_pipeline_cve_and_auth(self):
        """Full integration: CVE search + auth check run in parallel, results merged."""
        from src.layers.layer3_cve_searcher.cve_searcher import CVESearcher
        from src.core.config import Layer3Config, NVDConfig, MSFConfig, AuthCheckConfig
        from src.storage.schemas import CameraFingerprint, Fingerprint, CVEEntry, AuthInfo

        config = Layer3Config(
            nvd=NVDConfig(), msf=MSFConfig(),
            auth=AuthCheckConfig(),
        )
        searcher = CVESearcher(config)

        searcher._nvd_client = AsyncMock()
        searcher._nvd_client.search = AsyncMock(return_value=[
            CVEEntry(cve_id="CVE-2021-36260", severity="CRITICAL", source="nvd"),
        ])
        searcher._msf_client = AsyncMock()
        searcher._msf_client.find_module_for_cve = MagicMock(return_value=None)

        storage = AsyncMock()
        searcher.storage = storage

        mock_auth_checker = AsyncMock()
        mock_auth_checker.check = AsyncMock(return_value=[
            AuthInfo(port=80, protocol="http", has_login=True, auth_type="basic",
                     raw_response="HTTP 401"),
        ])
        searcher._auth_checker = mock_auth_checker

        item = CameraFingerprint(
            ip="192.168.1.1", port=80, weight=1.0,
            fingerprint=Fingerprint(vendor="hikvision", model="DS-2CD2142", version="V5.4.5"),
        )

        result = await searcher.process(item)

        assert result is not None
        assert "CVE-2021-36260" in result.fingerprint.cves
        assert len(result.auth_info) == 1
        assert result.auth_info[0].has_login is True
        assert result.auth_info[0].auth_type == "basic"
        assert searcher._auth_checked == 1
        assert searcher._auth_found == 1

    @pytest.mark.asyncio
    async def test_full_pipeline_no_auth_no_cve(self):
        """Target with no vendor and no auth → empty cves + empty auth_info."""
        from src.layers.layer3_cve_searcher.cve_searcher import CVESearcher
        from src.core.config import Layer3Config, NVDConfig, MSFConfig, AuthCheckConfig
        from src.storage.schemas import CameraFingerprint, Fingerprint

        config = Layer3Config(
            nvd=NVDConfig(), msf=MSFConfig(),
            auth=AuthCheckConfig(),
        )
        searcher = CVESearcher(config)
        searcher._nvd_client = AsyncMock()
        searcher._msf_client = AsyncMock()

        mock_auth_checker = AsyncMock()
        mock_auth_checker.check = AsyncMock(return_value=[])
        searcher._auth_checker = mock_auth_checker

        item = CameraFingerprint(
            ip="192.168.1.1", port=9999, weight=0.0,
            fingerprint=Fingerprint(),
        )

        result = await searcher.process(item)
        assert result is not None
        assert result.fingerprint.cves == []
        assert result.auth_info == []
```

- [ ] **Step 2: Run the full test suite**

Run: `pytest tests/test_auth_checker.py tests/test_layer3.py -v`
Expected: All tests PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/test_auth_checker.py
git commit -m "test(layer3): add integration tests for auth checker + CVE search pipeline"
```

---

### Task 10: Verify All Tests Pass

- [ ] **Step 1: Run complete test suite**

Run: `pytest tests/ -v`
Expected: All tests PASS, zero failures.

- [ ] **Step 2: Verify no import errors**

Run: `python3 -c "from src.layers.layer3_cve_searcher.auth_checker import AuthChecker; print('OK')"`
Expected: `OK`

Run: `python3 -c "from src.storage.schemas import AuthInfo; print('OK')"`
Expected: `OK`

Run: `python3 -c "from src.core.config import AuthCheckConfig; print('OK')"`
Expected: `OK`
