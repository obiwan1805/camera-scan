# VendorProbeDetector Design Spec — Improve Layer 3 Auth Detection

**Date:** 2026-06-22
**Status:** Draft
**Problem:** 84.6% miss rate (1020/1205 cameras) on auth detection. FormDetector fails on SPA-based camera UIs that render login forms via JavaScript frameworks (ExtJS, SmartGWT) instead of static HTML `<form>` tags.

## Root Cause Analysis (from live debugging)

Three root causes identified by probing real cameras in the database:

### 1. Dahua SPA — 762 misses (75%)

HTML body is `<body></body>` (empty). UI loaded entirely by ExtJS (`Ext.onReady`). No `<input type="password">`, no `<form>` tag. But `/cgi-bin/login.cgi` returns **HTTP 401 + Digest WWW-Authenticate**. FormDetector's `LOGIN_PATHS` list does not include this endpoint.

### 2. Vigor/Panasonic SmartGWT — 63 misses

Title is "Vigor Login Page" but form rendered by SmartGWT JavaScript. HTML contains `md5.js`, `rsa.js` imports (crypto-based login) but no password inputs in raw HTML.

### 3. Axis JS redirect — 21 misses

Root `/` returns `<script>window.location.pathname='camera/index.html'</script>`. FormDetector discovers the path but `/camera/index.html` is also a SPA. Real auth endpoint is `/axis-cgi/usergroup.cgi` (returns 401 Digest).

## Solution: VendorProbeDetector

New detector class that runs in parallel with FormDetector and MSFDetector. Three detection layers:

1. **Vendor-specific auth endpoint probing** — use `vendor` from Layer 2 fingerprint to probe known auth endpoints
2. **Generic auth endpoint probing** — fallback list of common camera auth endpoints for unknown vendors
3. **Title + SPA heuristic detection** — detect login pages via HTML title and JS framework signatures

## Architecture

### Detection Flow (updated)

```
AuthChecker._check_web(ip, port, protocol, vendor)
  ├── asyncio.gather(
  │     MSFDetector.detect(ip, port, protocol)
  │     FormDetector.detect(ip, port, protocol)
  │     VendorProbeDetector.detect(ip, port, protocol, vendor)    ← NEW
  │   )
  └── Merge by priority:
        1. FormDetector (has_login + form details)         ← highest
        2. VendorProbe high confidence (401 response)      ← high
        3. MSFDetector (MSF http_login)                    ← medium
        4. VendorProbe low confidence (title + SPA)        ← low
        5. no_login                                        ← default
```

### Vendor Probe Map

Hardcoded dict in `vendor_probe_detector.py`. Each vendor maps to a list of `(path, expected_signal)` tuples.

| Vendor | Probe Endpoints | Success Signal |
|--------|----------------|----------------|
| dahua | `/cgi-bin/login.cgi` | HTTP 401 + Digest |
| hikvision | `/ISAPI/Security/userCheck`, `/ISAPI/Security/sessionLogin/capabilities` | HTTP 401 + Digest/Basic |
| axis | `/axis-cgi/usergroup.cgi`, `/axis-cgi/param.cgi` | HTTP 401 + Digest |
| panasonic | `/cgi-bin/login.cgi` | HTTP 401 |
| ubiquiti | `/api/auth/login` | HTTP 401, or HTTP 200 with JSON body containing `"error"` or `"msg"` key |
| vivotek | `/cgi-bin/admin/getparam.cgi` | HTTP 401 + Digest/Basic |
| foscam | `/cgi-bin/CGIProxy.fcgi?cmd=logIn` | HTTP 200 + XML body containing `<result>` tag with non-zero code |
| sony | `/command/inquiry.cgi` | HTTP 401 |
| mobotix | `/control/userimage.html` | HTTP 401 + Basic |

### Generic Fallback Endpoints

Probed for all cameras when vendor-specific probes don't find login:

```
/cgi-bin/login.cgi
/ISAPI/Security/userCheck
/api/login
/api/auth
/cgi-bin/viewer/login.cgi
/login.htm
/login.php
/admin/login.html
```

### Title-Based Detection (low confidence)

Regex patterns on `<title>` content:

| Title Pattern | Auth Type |
|---------------|-----------|
| `Login Page`, `Login` (exact or as part) | `spa_login` |
| `WEB SERVICE` | `spa_login` |
| `AXIS` | `spa_login` |
| `NVR`, `DVR`, `IPC` (standalone word) | `spa_login` |
| `UniFi` | `spa_login` |

### JS Library Detection (combined with title for low confidence)

| Signal in HTML | Framework |
|----------------|-----------|
| `Ext.onReady`, `ext-all.js` | ExtJS (Dahua) |
| `SmartGWT`, `.nocache.js` | GWT (Vigor/Panasonic) |
| `require.js` + `jsCore` | Dahua custom loader |
| `md5.js` + `rsa.js` present together | Crypto login |

Logic: SPA framework detected + login-related title → `has_login=True`, `confidence="low"`. SPA framework alone without title hint → no conclusion.

### VendorProbeDetector Internal Flow

```
detect(ip, port, protocol, vendor):
    1. If vendor is known:
       - Probe vendor-specific endpoints (sequential, early-exit on first 401)
       - If found → return AuthInfo(confidence="high")
    2. Probe generic endpoints (sequential, early-exit on first 401)
       - If found → return AuthInfo(confidence="high")
    3. Fetch root page (/), analyze:
       - Extract <title>
       - Scan for SPA framework markers
       - If title matches + SPA framework → return AuthInfo(confidence="low")
    4. Return AuthInfo(has_login=False)
```

Step 3 reuses the root page HTML. VendorProbeDetector fetches `/` once internally for heuristic analysis. This is separate from FormDetector's fetch of `/` — they run in parallel and the duplication is acceptable (one extra HTTP request vs complex shared-state coordination).

## Data Model Changes

Two new optional fields on `AuthInfo`:

```python
class AuthInfo(BaseModel):
    # ... existing fields ...
    confidence: Optional[str] = None       # "high", "low", or None
    detection_method: Optional[str] = None  # "form", "vendor_probe", "msf", "heuristic"
```

Both fields are Optional with default None. No backward compatibility impact.

## AuthChecker Changes

1. Constructor: add `self._vendor_probe = VendorProbeDetector(config)`
2. `_check_inner()`: extract `vendor = item.fingerprint.vendor` and pass to `_check_web()`
3. `_check_web()`: run 3 detectors in parallel via `asyncio.gather`, merge by priority

Merge logic:

```python
if form_result and form_result.has_login:
    return form_result
if vendor_result and vendor_result.has_login and vendor_result.confidence == "high":
    return vendor_result
if msf_result and msf_result.has_login:
    return msf_result
if vendor_result and vendor_result.has_login and vendor_result.confidence == "low":
    return vendor_result
return AuthInfo(port=port, protocol=protocol, has_login=False, auth_type="unknown")
```

## Performance

| Aspect | Impact |
|--------|--------|
| Extra requests per camera | Vendor-specific: 1-3. Generic: max 8. Probes early-exit on first match |
| Wall-clock time | Near zero — runs in parallel with FormDetector (which already does 12+ requests sequentially) |
| Timeout per probe | Uses existing `banner_timeout` (5s default) per request |
| Vendor-specific hit → skip generic | Yes. No wasted requests when vendor probe succeeds |

## Files

| File | Action |
|------|--------|
| `src/layers/layer3_cve_searcher/auth_checker/vendor_probe_detector.py` | Create |
| `src/layers/layer3_cve_searcher/auth_checker/auth_checker.py` | Modify |
| `src/storage/schemas.py` | Modify |
| `src/layers/layer3_cve_searcher/auth_checker/__init__.py` | Modify |
| `tests/test_vendor_probe_detector.py` | Create |
| `tests/test_auth_checker.py` | Modify |

## Testing

Unit tests with mocked aiohttp responses:
- Vendor-specific probe detection per vendor (Dahua 401, Axis 401, etc.)
- Generic probe fallback when vendor=None
- Title + SPA heuristic detection
- Confidence level assignment (high vs low)
- Early-exit behavior (stops probing after first hit)
- Timeout/error graceful fallback
- AuthChecker merge priority (form > vendor_high > msf > vendor_low > no_login)
- Vendor passed correctly from CameraFingerprint to VendorProbeDetector

## Estimated Impact

Based on live data analysis:
- Dahua 762 misses: `/cgi-bin/login.cgi` returns 401 → vendor probe catches all (high confidence)
- Panasonic 63 misses: title "Vigor Login Page" + SmartGWT → heuristic catches (low confidence); also `/cgi-bin/login.cgi` may return 401 (high confidence)
- Axis 21 misses: `/axis-cgi/usergroup.cgi` returns 401 → vendor probe catches all (high confidence)
- Expected miss rate improvement: from 84.6% to estimated <20%
