# Layer 3 Authentication Checker — Design Spec v1.0

## Overview

Authentication detection sub-layer within Layer 3 (CVE Searcher). Identifies whether scanned targets have login mechanisms on their open ports — without attempting authentication. Results feed a future brute-force layer.

Runs **in parallel** with CVE search on the same target. Shares MSFRPCClient and concurrency infrastructure.

## Data Model

### AuthInfo (new model in `schemas.py`)

```python
class AuthInfo(BaseModel):
    port: int
    protocol: str          # "ssh", "telnet", "rtsp", "ftp", "http", "https", "unknown"
    has_login: bool
    auth_type: str         # "password", "publickey", "basic", "digest", "form", "bearer", "unknown"
    raw_response: str = "" # banner string, HTTP header, or MSF output (max 512 chars, truncated by detector)
    msf_module: Optional[str] = None
```

### CameraFingerprint (modified)

Add field:
```python
auth_info: List[AuthInfo] = []
```

Each target can have multiple `AuthInfo` entries — one per port/protocol pair.

## Architecture

### Module Structure

```
src/layers/layer3_cve_searcher/auth_checker/
├── __init__.py
├── auth_checker.py      # Orchestrator — dispatches to correct detector
├── banner_detector.py   # TCP banner grabbing for known protocols
├── msf_detector.py      # MSF auxiliary scanner for web + unknown ports
└── protocol_map.py      # Port → known protocol mapping
```

### AuthChecker (orchestrator)

`auth_checker.py` — main class that:

1. Receives a `CameraFingerprint` (ip + port)
2. Looks up `protocol_map` to determine protocol from port number
3. Routes to the appropriate detector:
   - Known protocol (SSH, Telnet, RTSP, FTP) → `BannerDetector`
   - HTTP/HTTPS → `MSFDetector` (uses `auxiliary/scanner/http` modules)
   - Unknown port → `BannerDetector` first (TCP connect + read banner), if unrecognized → `MSFDetector` fallback
4. Returns `List[AuthInfo]`

Constructor takes `MSFRPCClient` (shared from CVESearcher) and `AuthCheckConfig`.

### BannerDetector

Async TCP banner grabbing via `asyncio.open_connection`. Per-protocol detection:

| Protocol | Method | Detection |
|----------|--------|-----------|
| SSH | Connect, read banner | Banner contains `SSH-` → `has_login=True`. Parse for auth methods if available. `auth_type="password"` default |
| Telnet | Connect, read greeting | Response contains `login:`, `username:`, or `password:` → `has_login=True`, `auth_type="password"` |
| RTSP | Send `OPTIONS rtsp://{ip}:{port} RTSP/1.0\r\nCSeq: 1\r\n\r\n` | `401 Unauthorized` → `has_login=True`. Parse `WWW-Authenticate` header for `auth_type` (basic/digest) |
| FTP | Connect, read `220` banner, send `USER anonymous\r\n` | `331` response (password required) → `has_login=True`, `auth_type="password"`. `230` (anonymous ok) → `has_login=True`, `auth_type="anonymous"` |
| Unknown | Connect, read banner (5s timeout) | Try matching all patterns above. No match → `has_login=False` |

Each connection has a configurable timeout (default 5 seconds). All I/O via `asyncio.open_connection`.

`raw_response` stores the first 512 bytes of banner/response for debugging.

### MSFDetector

Uses the existing `MSFRPCClient` to run Metasploit auxiliary modules.

**Web login detection (HTTP/HTTPS):**

Primary module: `auxiliary/scanner/http/http_login`
- Set `STOP_ON_SUCCESS=false`, `BLANK_PASSWORDS=false`, `USERPASS_FILE=""` — detection only, no brute-force
- Detects HTTP Basic/Digest authentication (401 response with `WWW-Authenticate`)

Secondary module: `auxiliary/scanner/http/title`
- Fetches page title, searches for login-related keywords: "login", "sign in", "authentication", "password", "log in"
- Supplements Basic/Digest detection with title-based heuristic

**Form-based login detection (HTTP/HTTPS):**

MSF modules primarily detect Basic/Digest auth. For HTML form-based login pages, `MSFDetector` also performs a lightweight HTTP GET on the target and checks:
- HTML contains `<input type="password">` or `<input type="password"`
- HTML contains form elements with action URLs containing login-related keywords
- This is a simple heuristic fetch, not a full crawl — single request to the root path and common login paths (`/login`, `/admin`, `/cgi-bin/login`)
- If any match → `has_login=True`, `auth_type="form"`

**For unknown ports (MSF fallback):**

When `BannerDetector` returns `has_login=False` for an unknown port:
- If banner contained recognizable HTTP-like content (e.g., `HTTP/1.`, `<html`), treat as HTTP and run web detection modules
- Otherwise, skip — no further MSF detection for truly unrecognizable services. The banner grab already covers the common cases; running generic MSF modules on unknown services has poor signal-to-noise ratio

**Execution pattern:**
- Create MSF console via `console.create`
- Write module commands (`use`, `set RHOSTS`, `set RPORT`, `run`)
- Poll `console.read` until completion or timeout
- Parse output for authentication indicators
- Destroy console in `finally` block

Same pattern as existing `MSFRPCClient.check()` method.

### Protocol Map

Default port-to-protocol mapping:

```python
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
```

Ports not in the map → `"unknown"` → banner grab first, MSF fallback second.

## Integration into CVESearcher

### Parallel Execution

In `CVESearcher._process_item()`, auth check runs concurrently with CVE search:

```python
async def _process_item(self, item: CameraFingerprint) -> None:
    cve_task = asyncio.create_task(self._run_cve_search(item))
    auth_task = asyncio.create_task(self._run_auth_check(item))

    cve_result, auth_result = await asyncio.gather(
        cve_task, auth_task, return_exceptions=True
    )

    result = cve_result if isinstance(cve_result, CameraFingerprint) else item
    if isinstance(auth_result, list):
        result.auth_info = auth_result
    # ... save to storage
```

### Shared Resources

- `MSFRPCClient`: shared instance, already serialized via `_lock`
- `_target_semaphore`: shared with CVE search (controls total concurrent targets)
- `_auth_semaphore`: new semaphore specifically for auth check concurrency (default 50)

### CVESearcher Modifications

1. Add `_auth_checker: Optional[AuthChecker]` field
2. In `start()`: initialize `AuthChecker` with shared `MSFRPCClient` and config
3. In `_process_item()`: refactor to run CVE search and auth check in parallel
4. In `stop()`: no additional cleanup needed (AuthChecker has no persistent state)
5. Add progress counters: `_auth_checked`, `_auth_found`

## Configuration

### AuthCheckConfig (new dataclass in `config.py`)

```python
@dataclass
class AuthCheckConfig:
    enabled: bool = True
    banner_timeout: int = 5        # seconds per TCP banner grab
    msf_detect_timeout: int = 15   # seconds per MSF detection
    max_auth_concurrency: int = 50 # auth-specific semaphore
```

### Layer3Config (modified)

Add field:
```python
auth: AuthCheckConfig = field(default_factory=AuthCheckConfig)
```

### YAML config (config/default.yaml)

```yaml
layer3:
  auth:
    enabled: true
    banner_timeout: 5
    msf_detect_timeout: 15
    max_auth_concurrency: 50
```

## Storage

`auth_info` is serialized as part of `CameraFingerprint` and stored in the existing `fingerprints` table (SQLite JSON field). No new tables needed — the `List[AuthInfo]` is embedded in the fingerprint JSON.

This keeps the schema change minimal and aligns with how `evidence_items` and `cves` are already stored.

## Progress Tracking

New counters in `CVESearcher`:

| Counter | Description |
|---------|-------------|
| `_auth_checked` | Targets where auth check completed |
| `_auth_found` | Targets with at least one `has_login=True` |

Added to `_status_reporter()` output and Discord bot progress embed.

## CLI Integration

Add `--skip-auth` flag to `run-layer3` command to disable auth checking.
Add auth results to output display in existing CLI commands.

## Error Handling

- Banner grab timeout → `has_login=False`, log warning
- MSF module failure → skip MSF detection for that target, log error
- Connection refused → `has_login=False` (port may have closed since scan)
- Auth checker failure does NOT affect CVE search (independent tasks via `gather(return_exceptions=True)`)

## Scope Boundaries

**In scope:**
- Detect whether a login mechanism exists on each port
- Identify protocol and auth type
- Store results in `CameraFingerprint.auth_info`

**Out of scope (future brute-force layer):**
- Attempting any credentials
- Default credential testing
- Password brute-forcing
- Session/cookie management
