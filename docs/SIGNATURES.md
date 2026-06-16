# Signatures Guide

Signatures are how the fingerprinter identifies cameras. Each vendor has a YAML file in `config/signatures/` defining patterns to match against data collected from each target.

This guide covers:
- The signature schema and pattern types
- How to add signatures via Discord (`/signature add`)
- How to write signature YAML directly
- Examples for each pattern type

---

## Table of Contents

1. [How Signatures Work](#how-signatures-work)
2. [Pattern Types Reference](#pattern-types-reference)
3. [Adding Signatures via Discord](#adding-signatures-via-discord)
4. [Writing YAML Directly](#writing-yaml-directly)
5. [Examples](#examples)
6. [Tips and Best Practices](#tips-and-best-practices)

---

## How Signatures Work

When the fingerprinter processes a target `(ip, port)`:

1. **Collect** — 5 probers fetch raw data concurrently:
   - **HTTP** — GET `/` for HTML + headers, then probes signature-defined endpoints
   - **HTTPS** — Same as HTTP over TLS + SSL certificate subject
   - **RTSP** — DESCRIBE on signature-defined and generic RTSP paths
   - **ONVIF** — SOAP GetDeviceInformation request
   - **Favicon** — Downloads favicon, computes MMH3 hash

2. **Match** — The signature engine runs **ALL** vendor signatures against **ALL** collected data. No early stopping — every match is recorded.

3. **Resolve** — The aggregator picks the best fingerprint:
   - **Vendor**: majority vote (most matches wins, requires at least one vendor-level match)
   - **Model**: longest value among winning vendor's matches (most specific)
   - **Version**: longest value among winning vendor's matches
   - **CVEs**: union of all CVEs from all winning matches
   - **Weight**: `1.0` if both model and version extracted, `0.7` if model only, `0.4` if version only, `0.0` if neither

---

## Pattern Types Reference

### `brand_keyword`

A plain string (or simple regex) that confirms the vendor if found in the specified data scopes.

```yaml
brand_keywords:
- pattern: hikvision
  scope: [html, headers, rtsp_banner]
  cves: []
```

| Field | Type | Description |
|-------|------|-------------|
| `pattern` | string | String or regex to search for |
| `scope` | list | Where to look: `html`, `headers`, `xml_text`, `json_text`, `rtsp_banner`, `onvif_response`, `ssl_cert` |
| `cves` | list | CVEs associated with this match (optional) |

Matching is case-insensitive by default.

### `model` and `version`

Regex patterns with optional capture groups for extracting model/version strings.

```yaml
model_patterns:
- regex: DS-2CD\d+[A-Za-z\d-]*
  scope: [html, xml_text, rtsp_banner]

- regex: <model>(.*?)</model>
  scope: [xml_text]
  group: 1

version_patterns:
- regex: <firmwareVersion>(.*?)</firmwareVersion>
  scope: [xml_text]
  group: 1
  normalize: prefix_v
```

| Field | Type | Description |
|-------|------|-------------|
| `regex` | string | Python regex |
| `scope` | list | Where to look (same as brand_keyword) |
| `group` | int | Capture group to extract (default 0 = full match) |
| `normalize` | string | Optional: `prefix_v`, `clean_v`, `uppercase` |
| `case_sensitive` | bool | Default false |
| `cves` | list | CVEs associated (optional) |

Normalization options:
- `prefix_v` — prepend `V` if missing (e.g. `5.2.0` → `V5.2.0`)
- `clean_v` — strip non-version chars, prepend `V`
- `uppercase` — convert to uppercase

### `favicon_hash`

An integer MMH3 hash of the favicon. Strong identifier — usually unique per vendor.

```yaml
favicon_hashes:
- 999357577
```

To find a favicon hash, use a favicon hash calculator on the target's `/favicon.ico`.

### `endpoint`

HTTP/HTTPS paths that return XML/JSON/HTML data. The prober fetches these and feeds the response into the matcher (so model/version patterns can match against endpoint responses).

```yaml
endpoint_probes:
- path: /ISAPI/System/deviceInfo
  protocol: [http, https]
  content_type: xml

- path: /docu/webPlugin.html
  protocol: [http, https]
  content_type: html
```

| Field | Type | Description |
|-------|------|-------------|
| `path` | string | URL path |
| `protocol` | list | `http`, `https`, or both |
| `content_type` | string | `xml`, `json`, `html`, `text`, `binary` (optional) |

### `onvif`

ONVIF SOAP response parser. Matches the manufacturer field and extracts model/firmware from XML tags.

```yaml
onvif_parsers:
- manufacturer_match: [hikvision, hik]
  model_tag: tds:Model
  firmware_tag: tds:FirmwareVersion
```

| Field | Type | Description |
|-------|------|-------------|
| `manufacturer_match` | list | Strings to match against the `<Manufacturer>` tag |
| `model_tag` | string | XML tag name for model (default: `tds:Model`) |
| `firmware_tag` | string | XML tag name for firmware (default: `tds:FirmwareVersion`) |

### `rtsp_path`

RTSP URLs to probe. The DESCRIBE response banner is fed into the matcher.

```yaml
rtsp_paths:
- /h264/ch1/main/av_stream
- /ISAPI/Streaming/channels
```

### `extra`

Extensible patterns for custom matching. Currently supports `ssl_cn` for SSL certificate common name matching.

```yaml
extra_patterns:
- type: ssl_cn
  regex: hikvision
  scope: []
  cves: []
```

---

## Adding Signatures via Discord

### Method 1: Test then Add (recommended)

**Step 1: Test your regex**

```
/signature test
```

Opens a modal with two fields:
- **Pattern / Regex** — your regex
- **Sample text** — paste example HTML/XML/text to test against

If it matches, you'll see:
```
Match found
Pattern: DS-2CD\d+[A-Za-z\d-]*
Match: DS-2CD2143G2-I
Group 1: DS-2CD2143G2-I
```

With buttons: **Add to Signature** and **Test Again**.

If no match, you get an **Edit & Retry** button.

**Step 2: Add via the Add button or `/signature add`**

Click **Add to Signature** (from the test result) OR run `/signature add`. Either opens the Add modal:

| Field | Description |
|-------|-------------|
| **Vendor** | e.g. `hikvision`, `dahua`. Creates the vendor if it doesn't exist. |
| **Type** | One of: `brand_keyword`, `model`, `version`, `endpoint`, `favicon_hash`, `onvif`, `rtsp_path`, `extra` |
| **Pattern / Regex / Path** | The regex, keyword, path, or hash value |
| **CVEs** | Comma-separated, e.g. `CVE-2021-36260, CVE-2017-7921` |

After submitting, you see a **Preview** embed with:
- **Test Regex** button — re-test before committing
- **Confirm Add** button — writes to the YAML file and reloads the engine
- **Cancel** button

**Step 3: Verify**

```
/signature show hikvision model
```

Shows all model patterns with their indices. Your new pattern should appear at the bottom.

### Method 2: Write YAML directly

Edit or create a file in `config/signatures/<vendor>.yaml`. The engine hot-reloads every 30 seconds, or run `/signature reload` to force it immediately.

### Method 3: Import a YAML file

```
/signature import
```

Upload a vendor YAML file. It validates against the schema, writes to `config/signatures/`, and reloads the engine.

### Removing a signature

First find the index:

```
/signature show hikvision model
→ [0] /DS-2CD\d+[A-Za-z\d-]*/ scope=['html', 'xml_text', 'rtsp_banner']
  [1] /DS-2TD\d+[A-Za-z\d-]*/ scope=['html', 'xml_text', 'rtsp_banner']
  ...
```

Then remove by index:

```
/signature remove hikvision model 1
```

Shows a confirmation prompt before deleting.

### Exporting a backup

```
/signature export hikvision
```

Downloads `hikvision.yaml` as a Discord attachment.

---

## Writing YAML Directly

A minimal vendor signature:

```yaml
vendor: myvendor
aliases:
- mv
favicon_hashes:
- 123456789
brand_keywords:
- pattern: myvendor
  scope: [html, headers]
model_patterns:
- regex: MV-\d+[A-Z]+
  scope: [html, xml_text]
version_patterns:
- regex: <firmwareVersion>(.*?)</firmwareVersion>
  scope: [xml_text]
  group: 1
  normalize: prefix_v
endpoint_probes:
- path: /api/deviceinfo
  protocol: [http, https]
  content_type: json
onvif_parsers:
- manufacturer_match: [myvendor]
rtsp_paths:
- /stream/ch1
```

### Schema reference

```yaml
vendor: <string>                    # required, must match filename
aliases: [<string>, ...]            # optional, alternative names
favicon_hashes: [<int>, ...]        # optional
brand_keywords:                     # optional
- pattern: <regex>
  scope: [<scope>, ...]
  cves: [<string>, ...]
model_patterns:                     # optional
- regex: <regex>
  scope: [<scope>, ...]
  group: <int>                      # default 0
  normalize: <method>               # optional
  case_sensitive: <bool>            # default false
  cves: [<string>, ...]
version_patterns:                   # optional (same fields as model_patterns)
- ...
endpoint_probes:                    # optional
- path: <string>
  protocol: [http|https, ...]
  content_type: <string>            # optional
onvif_parsers:                      # optional
- manufacturer_match: [<string>, ...]
  model_tag: <string>               # default tds:Model
  firmware_tag: <string>            # default tds:FirmwareVersion
rtsp_paths: [<string>, ...]         # optional
extra_patterns:                     # optional
- type: <string>
  regex: <regex>
  scope: [<scope>, ...]
  cves: [<string>, ...]
```

**Valid scopes**: `html`, `headers`, `xml_text`, `json_text`, `rtsp_banner`, `onvif_response`, `ssl_cert`

---

## Examples

### Example 1: Add a brand keyword for a new vendor

```
/signature add
Vendor: amcrest
Type: brand_keyword
Pattern: amcrest
CVEs: (leave empty)
```

Result in `config/signatures/amcrest.yaml`:
```yaml
vendor: amcrest
aliases: []
brand_keywords:
- pattern: amcrest
  scope: [html]
  cves: []
```

### Example 2: Add a model regex with capture group

```
/signature add
Vendor: amcrest
Type: model
Pattern: IP(\d+[A-Z\d-]+)
CVEs: (leave empty)
```

Then edit the YAML to add scopes and group (the modal only sets the regex):

```yaml
model_patterns:
- regex: IP(\d+[A-Z\d-]+)
  scope: [html, xml_text]
  group: 1
  cves: []
```

### Example 3: Add a favicon hash

```
/signature add
Vendor: amcrest
Type: favicon_hash
Pattern: 123456789
```

### Example 4: Add an endpoint probe

```
/signature add
Vendor: amcrest
Type: endpoint
Pattern: /api/deviceinfo
```

Then edit YAML to add protocol and content_type:

```yaml
endpoint_probes:
- path: /api/deviceinfo
  protocol: [http, https]
  content_type: json
```

### Example 5: Full vendor file

```yaml
vendor: amcrest
aliases:
- amc
favicon_hashes:
- 123456789
- 987654321
brand_keywords:
- pattern: amcrest
  scope: [html, headers, rtsp_banner]
- pattern: Amcrest Technologies
  scope: [html]
model_patterns:
- regex: IP\d+[A-Z\d-]+
  scope: [html, xml_text]
- regex: <model>(.*?)</model>
  scope: [xml_text]
  group: 1
version_patterns:
- regex: <firmwareVersion>(.*?)</firmwareVersion>
  scope: [xml_text]
  group: 1
  normalize: prefix_v
endpoint_probes:
- path: /api/deviceinfo
  protocol: [http, https]
  content_type: json
- path: /cgi-bin/magicBox.cgi
  protocol: [http, https]
  content_type: text
onvif_parsers:
- manufacturer_match: [amcrest]
rtsp_paths:
- /cam/realmonitor
```

---

## Tips and Best Practices

### Test before adding
Always use `/signature test` first. A bad regex won't match anything and will waste scan time.

### Use multiple scopes
A model pattern matching in both `html` and `xml_text` catches more variants:

```yaml
- regex: DS-2CD\d+[A-Za-z\d-]*
  scope: [html, xml_text, rtsp_banner]
```

### Use capture groups for XML tags
Don't try to match the whole tag in one regex. Use a capture group:

```yaml
# Good
- regex: <model>(.*?)</model>
  scope: [xml_text]
  group: 1

# Bad (no group, captures the tags too)
- regex: <model>.*?</model>
  scope: [xml_text]
```

### Annotate CVEs on patterns
If a specific firmware version is vulnerable, attach CVEs to the version pattern:

```yaml
- regex: V?5\.2\.0
  scope: [xml_text]
  cves: [CVE-2021-36260]
```

### Favicon hashes are strong identifiers
A favicon hash match alone can confirm a vendor. Collect them by running the scanner and checking results, or use a favicon hash tool.

### Don't duplicate endpoints
If two vendors probe the same path, the prober only fetches it once. Deduplication is automatic.

### Use aliases for vendor name variants
If a device reports `HIKVISION` vs `Hikvision` vs `hik`, add aliases:

```yaml
vendor: hikvision
aliases: [hik, hik-connect]
```

### Hot reload is automatic
You don't need to restart the bot after editing YAML. The engine checks file mtimes every 30 seconds and reloads if anything changed. Use `/signature reload` to force it immediately.

### Backup before bulk edits
Use `/signature export <vendor>` before making big changes. If something breaks, re-import the backup.
