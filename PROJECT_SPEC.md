# Technical Specification: IP Camera Scanner - 3-Layer Pipe & Filter Architecture
**Version:** 2.0
**Pattern:** Pipe & Filter
**Focus:** Layer 1 & Layer 2 (Layer 3 placeholder)

---

## 1. System Architecture

```
[CIDR Input]
    ↓
┌─────────────────┐
│  Layer 1: Port  │──[Queue1: (ip,port), maxsize=1000]──▶
│     Scanner     │  ← InMemoryQueue with backpressure
└─────────────────┘
                          ↓
                  ┌─────────────────┐
                  │  Layer 2: FP    │──[Queue2: fingerprint, maxsize=1000]──▶
                  │     Scanner     │  ← InMemoryQueue with backpressure
                  └─────────────────┘
                                    ↓
                            ┌─────────────────┐
                            │  Layer 3: CVE   │──[Queue3: cves, maxsize=1000]──▶
                            │    Searcher     │  ← InMemoryQueue with backpressure
                            └─────────────────┘
```

---

## 2. Layer 1: Port Scanner

**Goal:** Find live IP:port pairs

| Input | Output |
|-------|--------|
| CIDR ranges in `data/cidrs.txt` | `[(ip, port), (ip, port), ...]` |

### 2.1 Implementation Details

- **Scanner:** `src/layers/layer1_port_scanner/scanner.py`
- **Tool:** masscan
- **Concurrency:** Single asyncio task watching output file
- **Batching:** Feeds 10 IPs at a time into queue
- **Backpressure:** Blocks when queue full

### 2.2 Masscan Command

```bash
masscan -oL data/scans/results.txt --output-flush \
  -p 80,554,443,8080,8443,8888 \
  -iL - < CIDR_LIST>
```

### 2.3 File Watching (Real-time)

```python
async def _watch_and_feed(self, output_path: Path) -> None:
    offset = 0
    while self._running:
        with open(output_path) as f:
            f.seek(offset)
            lines = f.readlines()
            offset = f.tell()
            for line in lines:
                if line.startswith("open tcp "):  # masscan format
                    parts = line.split()
                    ip = parts[3]
                    port = int(parts[2])
                    await self.output_queue.put((ip, port))
        await asyncio.sleep(0.1)
```

### 2.4 Configuration

```yaml
layer1:
  scanner_type: masscan
  batch_size: 10
  backpressure: block
  masscan_path: masscan
  output_file: data/scans/results.txt
```

---

## 3. Layer 2: Camera Fingerprinter

**Goal:** Identify camera vendor, model, version from IP:port

| Input | Output |
|-------|--------|
| `(ip, port)` | `{ip, port, vendor, model, version, weight}` |

### 3.1 Concurrency Model

**Semaphore-based Asyncio:**
- Single asyncio event loop
- Semaphore limits concurrent requests (default: 200)
- **No multiprocessing yet**
- Continuous processing (no batching)

```python
self._semaphore = asyncio.Semaphore(200)

async def _run(self):
    while self._running:
        item = await self.input_queue.get()
        asyncio.create_task(self._process_item(item))

async def _process_item(self, item):
    async with self._semaphore:
        result = await self.process(item)
```

### 3.2 Optimistic Routing with Vendor Hints

```
Modules run in order, passing vendor_hint between them:

1. Favicon → checks favicon.ico → if match → vendor="hikvision"
2. HTTP (with vendor_hint="hikvision") → skip Dahua checks → Hikvision endpoints only
3. HTTPS (with vendor_hint) → skip non-matching vendor
4. RTSP → tries general RTSP probing
5. ONVIF → tries SOAP GetDeviceInformation
6. SSH → banner grab
```

### 3.3 Module Registry

```python
MODULE_REGISTRY = {
    "favicon": FaviconModule,
    "http": HTTPModule,
    "https": HTTPSModule,
    "rtsp": RTSPModule,
    "onvif": ONVIFModule,
    "ssh": SSHModule
}
```

### 3.4 Fingerprint Schema

```python
class Fingerprint(BaseModel):
    vendor: Optional[str] = None
    model: Optional[str] = None
    version: Optional[str] = None
    raw_banner: Optional[str] = None
    services: List[str] = []
    
    # Evidence fields for tracking detection method
    probe_method: Optional[str] = None   # e.g., "http_server_header", "xml_endpoint"
    evidence: Optional[str] = None        # e.g., "matched Server header: DVRDVS-Webs"
    matched_pattern: Optional[str] = None # The regex or pattern that matched
    endpoint: Optional[str] = None        # e.g., "/ISAPI/System/deviceInfo"
```

### 3.5 Weight Logic (for Layer 3)

| Weight | Success Criteria | Layer 3 Strategy |
|--------|-----------------|------------------|
| High (≥0.8) | Vendor, model, version clearly identified | Query CPE database directly |
| Medium (0.5-0.8) | Vendor + model (version unclear) | Hybrid approach |
| Low (<0.5) | Vendor only (model/version unknown) | LLM reasoning for clues |

---

## 4. Layer 2 Modules

### 4.1 Favicon Module (NEW)

**Purpose:** Quick vendor identification using MMH3 favicon hashing

**Implementation:**
```python
FAVICON_HASHES = {
    -1466785234: "dahua",
    2019488876: "dahua", 
    1653394551: "dahua",
    999357577: "hikvision",
}

class FaviconModule(ProtocolModule):
    async def probe(self, ip: str, port: int, vendor_hint: Optional[str] = None):
        # Download favicon.ico (10KB max)
        # Compute MMH3 hash
        # Return vendor if matched
```

**Fallback Paths:** `/favicon.ico`, `/static/favicon.ico`, `/assets/favicon.ico`, `/img/favicon.ico`

### 4.2 HTTP Module

**Probing Strategy (with vendor hints):**
```python
async def probe(self, ip, port: int, vendor_hint=None):
    if vendor_hint == "hikvision":
        # Go directly to Hikvision endpoints
        return await self._hikvision_probe(ip, port, session, vendor_hint=True)
    
    # No hint - try standard probing
    result = await self._basic_http_probe(ip, port, session, vendor_hint)
    if result:
        return result
    
    # Try Hikvision if no hint or hint not hikvision
    if not vendor_hint or vendor_hint != "hikvision":
        result = await self._hikvision_probe(ip, port, session)
        if result:
            return result
    # ... same for Dahua
```

**Hikvision Endpoints:**
- `/ISAPI/System/deviceInfo` - XML with model/version
- `/ISAPI/System/firmwareInfo` - Firmware version
- `/docu/page.xml` - XML device info
- `/ISAPI/Streaming/channels` - Channel info

**Dahua Endpoints:**
- `/RPC2_Login` - XML-RPC device info
- `/cgi-bin/configManager.cgi?action=getConfig&name=SystemInfo`
- `/config/system` - JSON system info
- `/cgi-bin/magicBox.cgi?action=getSystemInfo`

### 4.3 HTTPS Module

Same as HTTP module with SSL handling:
- Self-signed certificate support (cameras often use this)
- Same probing strategy with vendor hints
- Ports: 443, 8443, 10443

### 4.4 RTSP Module (Future-Proof)

**Current:** Single-pass RTSP DESCRIBE/OPTIONS probing

**Future (with vendor hints):**
- Vendor-specific RTSP paths
- Example: Hikvision uses `/h264/ch1/main/av_stream`, Dahua uses `/cam/realmonitor`

### 4.5 ONVIF Module (Future-Proof)

**Current:** Direct SOAP GetDeviceInformation

**Future (with vendor hints):**
- Vendor-specific ONVIF endpoints
- Hikvision: `/onvif/device_service`, `/ISAPI/System/deviceInfo`
- Dahua: `/onvif/device`, `/onvif/Device`

### 4.6 SSH Module (Future-Proof)

**Current:** Banner grab pattern matching

**Future (with vendor hints):**
- Vendor-specific commands
- Hikvision: `show version`, `show deviceinfo`
- Dahua: `version`, `deviceinfo`

---

## 5. Layer 3: CVE Searcher (Placeholder)

**Goal:** Find CVEs related to identified cameras

| Input | Output |
|-------|--------|
| Output from Layer 2 | CVE information |

**Provisional Concurrency:**
- Asyncio for high weight (API calls: NVD, CVE database)
- Could use process pool for low weight (local LLM reasoning - CPU-bound)

---

## 6. Pipeline: Bounded Queue with Backpressure

```python
from src.core.queue_protocol import InMemoryQueue, BoundedQueue

# Create queues with backpressure
queue1 = BoundedQueue(InMemoryQueue(maxsize=0), maxsize=1000)
queue2 = BoundedQueue(InMemoryQueue(maxsize=0), maxsize=1000)
queue3 = BoundedQueue(InMemoryQueue(maxsize=0), maxsize=1000)
```

**Behavior:**
- Queue full → subsequent layers **block** on put()
- Scanner continues → data "trickles" in until queue has space
- No spillover to disk in current implementation

---

## 7. Database Schema

### 7.1 SQLite Backend

**File:** `data/camera_scan.db`

**Fingerprints Table:**
```sql
CREATE TABLE fingerprints (
    ip TEXT,
    port INTEGER,
    timestamp TEXT,
    vendor TEXT,
    model TEXT,
    version TEXT,
    raw_banner TEXT,
    services TEXT,
    probe_method TEXT,
    evidence TEXT,
    matched_pattern TEXT,
    endpoint TEXT,
    weight REAL
);
```

---

## 8. Configuration

**File:** `config/default.yaml`

```yaml
layers:
  layer1:
    scanner_type: masscan
    batch_size: 10
    backpressure: block
    masscan_path: masscan
    output_file: data/scans/results.txt

  layer2:
    worker_pool:
      pool_type: semaphore
      max_concurrent: 200
    modules:
      - favicon      # Quick vendor ID
      - http        # Main probing
      - https
      - rtsp
      - onvif
      - ssh
    router_strategy: optimistic

storage:
  backend: sqlite
  path: data/camera_scan.db

queue:
  maxsize: 1000
  type: in_memory
```

---

## 9. File Structure

```
camera-scan/
├── config/
│   └── default.yaml
├── data/
│   ├── cidrs.txt              # CIDR ranges to scan
│   ├── ports.txt              # Ports to scan
│   ├── scans/
│   │   └── results.txt         # Masscan output
│   └── test_targets.txt       # Test mode targets
├── src/
│   ├── core/
│   │   ├── config.py
│   │   ├── interfaces.py
│   │   └── queue_protocol.py
│   ├── layers/
│   │   ├── layer1_port_scanner/
│   │   │   └── scanner.py
│   │   ├── layer2_fingerprinter/
│   │   │   ├── fingerprinter.py
│   │   │   └── modules/
│   │   │       ├── base.py
│   │   │       ├── favicon.py
│   │   │       ├── http.py
│   │   │       ├── https.py
│   │   │       ├── rtsp.py
│   │   │       ├── onvif.py
│   │   │       ├── ssh.py
│   │   │       ├── header_parser.py
│   │   │       ├── html_parser.py
│   │   │       └── __init__.py
│   │   └── layer3_cve_searcher/
│   │       └── cve_searcher.py
│   ├── storage/
│   │   ├── base.py
│   │   ├── schemas.py
│   │   └── sqlite_backend.py
│   └── utils/
│       ├── logging.py
│       └── retry.py
├── main.py
├── test_layer2.py
├── PROJECT_SPEC.md
├── requirements.txt
└── .gitignore
```

---

## 10. Future Improvements

### 10.1 RTSP Vendor-Specific Paths

```yaml
rtsp:
  vendor_paths:
    hikvision:
      - "/h264/ch1/main/av_stream"
      - "/ISAPI/Streaming/channels"
    dahua:
      - "/cam/realmonitor"
      - "/stream1"
    axis:
      - "/axis-media/media.amp"
```

**Implementation:**
```python
async def _vendor_specific_probe(self, ip: str, port: int, vendor: str):
    paths = self._get_vendor_paths(vendor)
    for path in paths:
        result = await self._rtsp_describe(ip, port, path, vendor_hint=vendor)
        if result:
            return result
    return None
```

### 10.2 SSH Vendor-Specific Commands

```python
async def _vendor_specific_probe(self, ip: str, port: int, vendor: str):
    if vendor == "hikvision":
        await self._send_command("show version")
    elif vendor == "dahua":
        await self._send_command("version")
```

### 10.3 Additional Favicon Sources

**Current:** `/favicon.ico` with fallback paths

**Future additions:**
- HTML `<link rel="icon">` parsing
- Apple Touch Icons: `/apple-touch-icon.png`
- PWA manifests: `/manifest.json`

### 10.4 Pattern Files Extension

**New files to add when needed:**
```
src/layers/layer2_fingerprinter/modules/
├── rtsp_vendor_paths.py      # Vendor-specific RTSP paths
├── ssh_vendor_commands.py     # Vendor-specific SSH commands
└── onvif_vendor_endpoints.py  # Vendor-specific ONVIF endpoints
```

### 10.5 TODO (Immediate)

- [ ] Update `FAVICON_HASHES` in `favicon.py` with actual vendor mappings
- [ ] Install mmh3 dependency: `pip install mmh3`
- [ ] Test favicon module with known camera IPs
- [ ] Implement Layer 3 CVE Searcher
- [ ] Add tests for vendor hint passing
- [ ] Add vendor-specific RTSP/SSH/ONVIF probing

---

## 11. Dependencies

**requirements.txt:**
```
aiohttp>=3.9.0
aiosqlite>=0.19.0
pydantic>=2.5.0
pyyaml>=6.0.0
mmh3>=3.0.0
```

---

## 12. Usage

**Full Scan:**
```bash
sudo -E python3 main.py
```

**Test Layer 2 Against Specific IPs:**
```bash
# Create data/test_targets.txt with IP:PORT pairs
python test_layer2.py data/test_targets.txt

# Or test specific modules
python test_layer2.py data/test_targets.txt --modules favicon http
python test_layer2.py data/test_targets.txt --max-concurrent 50
```