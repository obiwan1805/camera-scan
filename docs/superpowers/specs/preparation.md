# Layer 3 CVE Searcher — Setup Guide

## 1. System dependencies

```bash
# Python packages
pip3 install -r requirements.txt

# pytest-asyncio (cho tests)
pip3 install pytest-asyncio
```

## 2. Metasploit msfrpcd

Layer 3 dùng msfrpcd để verify CVEs cho targets có weight < 1.0.

```bash
# Install metasploit
sudo apt install metasploit-framework

# Tạo database cho msf
msfdb init

# Start msfrpcd daemon (chạy ở background)
msfrpcd -P your_password -S -a 127.0.0.1 -p 55553
```

Verify msfrpcd đang chạy:

```bash
ss -tlnp | grep 55553
```

Nếu thấy LISTEN → OK.

## 3. Config

Sửa `config/default.yaml`:

```yaml
layer3:
  enabled: true
  nvd:
    api_key: ""              # Optional — tăng rate limit (xem bước 4)
    base_url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
    rate_limit: 50
  msf:
    host: "127.0.0.1"
    port: 55553
    password: "your_password"   # ← cùng password với msfrpcd -P
    module_types:
      - exploit
      - auxiliary
    batch_size: 200
    check_timeout: 30
  target_concurrency: 200
  module_concurrency: 32
```

## 4. (Optional) NVD API key

Không có API key vẫn chạy, nhưng bị giới hạn 50 requests/30s.

Với API key: 100 requests/30s.

Cách lấy:
1. Vào https://nvd.nist.gov/developers/request-an-api-key
2. Điền form (miễn phí, nhận ngay qua email)
3. Thêm vào config:

```yaml
layer3:
  nvd:
    api_key: "your-api-key-here"
```

## 5. Disable Layer 3

Nếu không muốn chạy Layer 3:

```yaml
layer3:
  enabled: false
```

## 6. Không có msfrpcd

Layer 3 vẫn chạy nếu msfrpcd không khả dụng:
- weight == 1.0 targets: NVD search bình thường
- weight < 1.0 targets: fallback sang NVD search (unverified), hoặc skip nếu không có vendor

Log sẽ hiện:
```
[CVESearcher] msfrpcd connection failed: ... MSF check unavailable.
```

## 7. Run

```bash
# Start bot
python3 -m src.bot.bot
```

Trên Discord:
```
/scan start
```

Pipeline tự chạy: Layer 1 → Layer 2 → Layer 3.

## 8. Discord commands

```
/cve status                          # Tổng quan kết quả CVE
/cve list                            # Danh sách CVEs
/cve list vendor:hikvision           # Filter theo vendor
/cve show cve_id:CVE-2021-36260      # Chi tiết 1 CVE
/scan progress                       # Tiến độ cả 3 layers
```

## 9. Output classification

Layer 3 phân loại mỗi target:

| Status | Ý nghĩa |
|--------|---------|
| 🔴 Exploitable | Có CVE + có MSF exploit module (có PoC) |
| 🟠 Affected | Có CVE + version nằm trong affected range (không có PoC) |
| 🟡 Unclear | Có vendor nhưng không xác định được version, MSF check không kết quả |
| ⚪ No result | Không tìm thấy CVE |

Mỗi CVE được tag impact type:

| Impact | Mô tả |
|--------|-------|
| RCE | Remote code execution |
| Auth bypass | Bypass xác thực, default credentials |
| Video access | Xem được video stream |
| Info leak | Leak thông tin, credentials |
| DoS | Denial of service |

## 10. Tests

```bash
# Layer 3 unit + integration tests (42 tests)
python3 -m pytest tests/test_layer3.py -v

# Tất cả tests
python3 -m pytest tests/ -v
```

## 11. Thứ tự start services

```bash
# 1. Start msfrpcd trước
msfrpcd -P your_password -S -a 127.0.0.1 -p 55553

# 2. Verify msfrpcd ready
ss -tlnp | grep 55553

# 3. Start bot
python3 -m src.bot.bot

# 4. Discord: /scan start
```
