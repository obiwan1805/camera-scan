# FormDetector — Improved Auth Detection for Layer 3

**Date:** 2026-06-18
**Status:** Approved

## Problem

Current HTTP auth detection in Layer 3 has low reliability:

1. `MSFDetector._detect_form_login()` uses a single regex (`<input type="password">`) — misses many login form variants
2. No detection of JavaScript-rendered login forms
3. No extraction of form details (action URL, field names, CSRF tokens) needed for downstream brute force
4. Fixed 5-path list misses camera-vendor login pages on non-standard paths
5. MSF `http_login` module is unreliable (depends on msfrpcd, console polling, timeouts)

## Solution

Create a new `FormDetector` class, separate from `MSFDetector`, dedicated to HTML/JS-based login detection with form detail extraction.

## Architecture

```
AuthChecker.check(item)
    |
    +-- get_protocol(port)
    |
    +-- is_web_protocol?
    |     YES --> asyncio.gather(
    |               MSFDetector.detect()      # HTTP 401/Basic/Digest (unchanged)
    |               FormDetector.detect()     # HTML/JS analysis (NEW)
    |             )
    |             --> merge: prefer FormDetector if it has form details
    |
    |     NO --> BannerDetector.detect()      # unchanged
    |
    +-- Fallback unknown protocol (unchanged)
```

### MSFDetector changes

- Remove `_detect_form_login()` entirely
- Keep only `_detect_msf_http()` — single-purpose HTTP 401/Basic/Digest detection via MSF module

### FormDetector — 3 stages

#### Stage 1: Path Discovery

1. GET `/` (root page)
2. Parse response for redirects and links to login pages:
   - `<meta http-equiv="refresh" content="0;url=/login.asp">`
   - `<a href="/webui/login">`
   - `<script>window.location = "/auth"</script>`
   - HTTP 301/302 `Location` header
3. Merge discovered paths with expanded static list, deduplicate
4. Max 1 redirect hop to avoid loops (e.g., `/` → `/login.asp` is followed, but `/login.asp` → `/other` is not)

Expanded static login path list:

```python
LOGIN_PATHS = [
    "/", "/login", "/login.html", "/login.asp", "/login.cgi",
    "/admin", "/admin/login",
    "/cgi-bin/login", "/cgi-bin/login.cgi",
    "/webui/", "/webui/login",
    "/doc/page/login.asp",
]
```

#### Stage 2: HTML/JS Analysis

For each path, GET response then run 3 analyzers:

**a) Form Analyzer** — parse HTML for `<form>` elements:

- Signals for detecting password inputs (must handle `type="password"` at any position within the `<input>` tag, with flexible whitespace and case-insensitive matching):
  - `<input type="password" name="pass">` — type first
  - `<input name="pass" type="password">` — type after other attributes
  - `<input class="x" id="y" type="password">` — type at end
  - `<input type = "password">` — spaces around `=`
  - `<input TYPE="Password">` — case variations
  - `<input name="pass*">`, `<input name="pwd*">` — name-based heuristic (fallback when type is not password but name suggests it)
  - `<input placeholder="*password*">` — placeholder-based heuristic
- Implementation: use an HTML parser (e.g., `html.parser` or regex with `[^>]*` wildcard) that scans all attributes of each `<input>` tag, not just a fixed-position match
- Extract: `action`, `method`, all `<input>` fields (name, type, value)
- Detect hidden fields and CSRF tokens (`<input type="hidden">`, field name containing "csrf"/"token"/"_verify")

**b) JS Login Indicator Analyzer** — parse inline `<script>` blocks:

- DOM manipulation patterns: `createElement("input")` near `type.*password`, `getElementById("password")`, `querySelector('[type=password]')`
- String literals: `"password"`, `"username"`, `"login"`, `"auth"`, `"/api/login"`, `"/api/auth"`
- AJAX calls: `XMLHttpRequest`, `fetch(`, `$.ajax`, `$.post` combined with auth-related URLs
- Result: `has_login=True`, `auth_type="js_rendered"`, form fields left empty (form not present in static HTML)

**c) HTTP Auth Analyzer** — check response headers:

- HTTP 401 + `WWW-Authenticate` header → extract auth type (Basic/Digest)
- Backup for when MSF is unavailable

#### Stage 3: Result Assembly

- If multiple paths have login forms → select path with most detail (prefer forms with explicit action URL)
- If only JS indicators detected → return `has_login=True` with `auth_type="js_rendered"`, form fields empty

## Schema Changes

### AuthInfo — new optional fields

All new fields are `Optional` with default `None` for backward compatibility:

```python
class AuthInfo(BaseModel):
    # existing fields (unchanged)
    port: int
    protocol: str
    has_login: bool
    auth_type: str              # new values: "form", "js_rendered"
    raw_response: str = ""
    msf_module: Optional[str] = None

    # new fields
    form_action: Optional[str] = None
    form_method: Optional[str] = None
    username_field: Optional[str] = None
    password_field: Optional[str] = None
    hidden_fields: Optional[dict] = None
    csrf_token_field: Optional[str] = None
    csrf_token_value: Optional[str] = None
    login_url: Optional[str] = None
    cookies: Optional[dict] = None
```

## Merge Logic in AuthChecker

```python
async def _check_web(self, ip, port, protocol):
    msf_result, form_result = await asyncio.gather(
        self._msf.detect(ip, port, protocol),
        self._form.detect(ip, port, protocol),
        return_exceptions=True
    )

    if isinstance(msf_result, Exception): msf_result = None
    if isinstance(form_result, Exception): form_result = None

    # Priority:
    # 1. FormDetector has form details → use FormDetector
    # 2. Only MSF detected → use MSF
    # 3. Neither detected → has_login=False
    if form_result and form_result.has_login:
        return form_result
    if msf_result and msf_result.has_login:
        return msf_result
    return AuthInfo(port=port, protocol=protocol, has_login=False, auth_type="unknown")
```

## File Structure

```
auth_checker/
├── __init__.py          # add FormDetector export
├── auth_checker.py      # add _check_web(), inject FormDetector
├── banner_detector.py   # unchanged
├── msf_detector.py      # remove _detect_form_login(), keep only _detect_msf_http()
├── form_detector.py     # NEW — HTML/JS login analysis + form detail extraction
└── protocol_map.py      # unchanged
```

## Configuration

Uses existing `AuthCheckConfig` fields — no new config needed:

- `banner_timeout` (default 5s) — reused for HTTP request timeout in FormDetector
- `max_auth_concurrency` — already applies at AuthChecker level

## Testing Strategy

- Unit tests for each analyzer (Form, JS Indicator, HTTP Auth) with crafted HTML fixtures
- Unit tests for path discovery (redirect parsing, link extraction)
- Unit tests for merge logic in AuthChecker
- Integration tests with MSFDetector + FormDetector running in parallel
- Update existing MSFDetector tests to reflect removal of `_detect_form_login()`
