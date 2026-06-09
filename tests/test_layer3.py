"""Unit tests for Layer 3 CVE Searcher."""
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestCVEEntry:
    def test_cve_entry_defaults(self):
        from src.storage.schemas import CVEEntry
        entry = CVEEntry(cve_id="CVE-2021-36260")
        assert entry.cve_id == "CVE-2021-36260"
        assert entry.severity is None
        assert entry.cvss_score is None
        assert entry.msf_module is None
        assert entry.exploitable is False
        assert entry.source == ""
        assert entry.verified is False

    def test_cve_entry_full(self):
        from src.storage.schemas import CVEEntry
        entry = CVEEntry(
            cve_id="CVE-2021-36260",
            severity="CRITICAL",
            cvss_score=9.8,
            description="Command injection",
            msf_module="exploit/linux/http/hikvision_cmd_injection",
            exploitable=True,
            source="nvd",
            verified=False,
        )
        assert entry.severity == "CRITICAL"
        assert entry.cvss_score == 9.8
        assert entry.exploitable is True


class TestLayer3Config:
    def test_defaults(self):
        from src.core.config import Layer3Config, NVDConfig, MSFConfig
        nvd = NVDConfig()
        msf = MSFConfig()
        config = Layer3Config(nvd=nvd, msf=msf)
        assert config.enabled is True
        assert nvd.rate_limit == 50
        assert msf.host == "127.0.0.1"
        assert msf.port == 55553
        assert msf.module_types == ["exploit", "auxiliary"]
        assert msf.batch_size == 200
        assert config.target_concurrency == 200
        assert config.module_concurrency == 32

    def test_from_yaml(self):
        from src.core.config import Config
        config = Config.from_yaml("config/default.yaml")
        assert config.layer3.enabled is True
        assert config.layer3.nvd.rate_limit == 50
        assert config.layer3.msf.host == "127.0.0.1"


class TestNVDResultCache:
    def test_empty_cache_miss(self):
        from src.layers.layer3_cve_searcher.cache import NVDResultCache
        cache = NVDResultCache()
        assert cache.get("hikvision", "DS-2CD2142", "V5.4.5") is None

    def test_cache_put_and_get(self):
        from src.layers.layer3_cve_searcher.cache import NVDResultCache
        from src.storage.schemas import CVEEntry
        cache = NVDResultCache()
        entries = [CVEEntry(cve_id="CVE-2021-36260", severity="CRITICAL")]
        cache.put("hikvision", "DS-2CD2142", "V5.4.5", entries)
        result = cache.get("hikvision", "DS-2CD2142", "V5.4.5")
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2021-36260"

    def test_cache_different_key_miss(self):
        from src.layers.layer3_cve_searcher.cache import NVDResultCache
        from src.storage.schemas import CVEEntry
        cache = NVDResultCache()
        cache.put("hikvision", "DS-2CD2142", "V5.4.5", [CVEEntry(cve_id="CVE-2021-36260")])
        assert cache.get("hikvision", "DS-2CD2142", "V5.4.6") is None


class TestMSFModuleCache:
    def test_empty_cache_miss(self):
        from src.layers.layer3_cve_searcher.cache import MSFModuleCache
        cache = MSFModuleCache()
        assert cache.get("hikvision") is None

    def test_cache_put_and_get(self):
        from src.layers.layer3_cve_searcher.cache import MSFModuleCache
        cache = MSFModuleCache()
        modules = [{"name": "exploit/linux/http/hikvision_cmd_injection", "type": "exploit", "cves": ["CVE-2021-36260"]}]
        cache.put("hikvision", modules)
        result = cache.get("hikvision")
        assert len(result) == 1
        assert result[0]["cves"] == ["CVE-2021-36260"]

    def test_find_module_for_cve(self):
        from src.layers.layer3_cve_searcher.cache import MSFModuleCache
        cache = MSFModuleCache()
        modules = [
            {"name": "exploit/linux/http/hikvision_cmd_injection", "type": "exploit", "cves": ["CVE-2021-36260"]},
            {"name": "auxiliary/scanner/http/hikvision_default_creds", "type": "auxiliary", "cves": ["CVE-2017-7921"]},
        ]
        cache.put("hikvision", modules)
        result = cache.find_module_for_cve("hikvision", "CVE-2021-36260")
        assert result["name"] == "exploit/linux/http/hikvision_cmd_injection"

    def test_find_module_for_cve_miss(self):
        from src.layers.layer3_cve_searcher.cache import MSFModuleCache
        cache = MSFModuleCache()
        modules = [{"name": "exploit/...", "type": "exploit", "cves": ["CVE-2021-36260"]}]
        cache.put("hikvision", modules)
        assert cache.find_module_for_cve("hikvision", "CVE-2099-9999") is None


import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


class TestNVDClient:
    @pytest.fixture
    def nvd_config(self):
        from src.core.config import NVDConfig
        return NVDConfig(api_key="", rate_limit=50)

    def test_build_search_query(self, nvd_config):
        from src.layers.layer3_cve_searcher.clients.nvd_client import NVDClient
        client = NVDClient(nvd_config)
        params = client._build_search_params("Hikvision", "DS-2CD2142", "V5.4.5")
        assert params["keywordSearch"] == "Hikvision DS-2CD2142"

    def test_build_search_query_model_only(self, nvd_config):
        from src.layers.layer3_cve_searcher.clients.nvd_client import NVDClient
        client = NVDClient(nvd_config)
        params = client._build_search_params("Dahua", "DH-IPC-HDW2431T", None)
        assert params["keywordSearch"] == "Dahua DH-IPC-HDW2431T"

    @pytest.mark.asyncio
    async def test_search_cache_hit(self, nvd_config):
        from src.layers.layer3_cve_searcher.clients.nvd_client import NVDClient
        from src.layers.layer3_cve_searcher.cache import NVDResultCache
        from src.storage.schemas import CVEEntry
        client = NVDClient(nvd_config)
        client._cache = NVDResultCache()
        client._cache.put("hikvision", "ds-2cd2142", "v5.4.5",
                          [CVEEntry(cve_id="CVE-2021-36260")])
        result = await client.search("Hikvision", "DS-2CD2142", "V5.4.5")
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2021-36260"

    @pytest.mark.asyncio
    async def test_parse_nvd_response(self, nvd_config):
        from src.layers.layer3_cve_searcher.clients.nvd_client import NVDClient
        client = NVDClient(nvd_config)
        mock_response = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-36260",
                        "descriptions": [{"lang": "en", "value": "Command injection in Hikvision web interface"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                        "weaknesses": [{"description": [{"value": "CWE-78"}]}],
                    }
                }
            ]
        }
        entries = client._parse_response(mock_response)
        assert len(entries) == 1
        assert entries[0].cve_id == "CVE-2021-36260"
        assert entries[0].severity == "CRITICAL"
        assert entries[0].cvss_score == 9.8
        assert entries[0].description == "Command injection in Hikvision web interface"

    @pytest.mark.asyncio
    async def test_enrich_returns_metadata(self, nvd_config):
        from src.layers.layer3_cve_searcher.clients.nvd_client import NVDClient
        client = NVDClient(nvd_config)
        client._enrich_cache = {"CVE-2021-36260": {"severity": "CRITICAL", "cvss_score": 9.8, "description": "test"}}
        result = await client.enrich(["CVE-2021-36260"])
        assert len(result) == 1
        assert result[0]["severity"] == "CRITICAL"


class TestMSFRPCClient:
    @pytest.fixture
    def msf_config(self):
        from src.core.config import MSFConfig
        return MSFConfig(host="127.0.0.1", port=55553, password="test")

    @pytest.fixture
    def msf_client(self, msf_config):
        from src.layers.layer3_cve_searcher.clients.msf_rpc_client import MSFRPCClient
        return MSFRPCClient(msf_config)

    def test_module_info_extraction(self, msf_client):
        """Verify module info is parsed from MSF module metadata."""
        raw = {
            "name": "exploit/linux/http/hikvision_cmd_injection",
            "description": "Hikvision command injection",
            "references": [["CVE", "2021-36260"], ["URL", "https://..."]],
            "type": "exploit",
        }
        info = msf_client._extract_module_info("exploit/linux/http/hikvision_cmd_injection", raw)
        assert info["name"] == "exploit/linux/http/hikvision_cmd_injection"
        assert info["type"] == "exploit"
        assert info["cves"] == ["CVE-2021-36260"]

    def test_module_info_no_cves(self, msf_client):
        raw = {
            "name": "auxiliary/scanner/http/hikvision_version",
            "description": "Version scanner",
            "references": [["URL", "https://..."]],
            "type": "auxiliary",
        }
        info = msf_client._extract_module_info("auxiliary/scanner/http/hikvision_version", raw)
        assert info["cves"] == []

    def test_cache_stores_modules(self, msf_client):
        from src.layers.layer3_cve_searcher.cache import MSFModuleCache
        msf_client._module_cache = MSFModuleCache()
        msf_client._module_cache.put("hikvision", [
            {"name": "exploit/.../hikvision_cmd_injection", "type": "exploit", "cves": ["CVE-2021-36260"]}
        ])
        result = msf_client._module_cache.get("hikvision")
        assert len(result) == 1

    def test_find_module_for_cve_via_cache(self, msf_client):
        from src.layers.layer3_cve_searcher.cache import MSFModuleCache
        msf_client._module_cache = MSFModuleCache()
        msf_client._module_cache.put("hikvision", [
            {"name": "exploit/.../cmd_injection", "type": "exploit", "cves": ["CVE-2021-36260"]},
            {"name": "auxiliary/.../default_creds", "type": "auxiliary", "cves": ["CVE-2017-7921"]},
        ])
        result = msf_client.find_module_for_cve("hikvision", "CVE-2021-36260")
        assert result is not None
        assert result["name"] == "exploit/.../cmd_injection"


class TestClassifyExploitability:
    def test_no_result_no_cves(self):
        from src.layers.layer3_cve_searcher.classifier import classify_exploitability
        from src.storage.schemas import Fingerprint, PoC
        fp = Fingerprint(cves=[])
        assert classify_exploitability(fp, []) == "no_result"

    def test_exploitable_has_poc(self):
        from src.layers.layer3_cve_searcher.classifier import classify_exploitability
        from src.storage.schemas import Fingerprint, PoC
        fp = Fingerprint(cves=["CVE-2021-36260"])
        pocs = [PoC(name="test", cve_id="CVE-2021-36260", script_content="exploit/.../hikvision")]
        assert classify_exploitability(fp, pocs) == "exploitable"

    def test_affected_has_version_no_poc(self):
        from src.layers.layer3_cve_searcher.classifier import classify_exploitability
        from src.storage.schemas import Fingerprint, PoC
        fp = Fingerprint(cves=["CVE-2021-36260"], version="V5.4.5")
        pocs = [PoC(name="test", cve_id="CVE-2021-36260")]
        assert classify_exploitability(fp, pocs) == "affected"

    def test_unclear_no_version_no_poc(self):
        from src.layers.layer3_cve_searcher.classifier import classify_exploitability
        from src.storage.schemas import Fingerprint, PoC
        fp = Fingerprint(cves=["CVE-2021-36260"])
        pocs = [PoC(name="test", cve_id="CVE-2021-36260")]
        assert classify_exploitability(fp, pocs) == "unclear"


class TestClassifyImpact:
    def test_rce_from_cwe(self):
        from src.layers.layer3_cve_searcher.classifier import classify_impact
        result = classify_impact("Command injection in web interface", "CWE-78", "exploit", "")
        assert "rce" in result

    def test_auth_bypass_from_description(self):
        from src.layers.layer3_cve_searcher.classifier import classify_impact
        result = classify_impact("Authentication bypass allows access", "CWE-287", "auxiliary", "")
        assert "auth_bypass" in result

    def test_video_access_from_description(self):
        from src.layers.layer3_cve_searcher.classifier import classify_impact
        result = classify_impact("Unauthenticated RTSP stream access", "", "", "")
        assert "video_access" in result

    def test_info_leak_from_cwe(self):
        from src.layers.layer3_cve_searcher.classifier import classify_impact
        result = classify_impact("Information disclosure of credentials", "CWE-200", "", "")
        assert "info_leak" in result

    def test_dos_from_description(self):
        from src.layers.layer3_cve_searcher.classifier import classify_impact
        result = classify_impact("Denial of service via crafted packet", "", "", "")
        assert "dos" in result

    def test_unknown_when_no_match(self):
        from src.layers.layer3_cve_searcher.classifier import classify_impact
        result = classify_impact("Some other vulnerability", "", "", "")
        assert result == ["unknown"]

    def test_multiple_impacts(self):
        from src.layers.layer3_cve_searcher.classifier import classify_impact
        result = classify_impact("RCE and information disclosure", "CWE-78", "exploit", "")
        assert "rce" in result
        assert "info_leak" in result


class TestWeightRouter:
    @pytest.fixture
    def router(self):
        from src.layers.layer3_cve_searcher.router import WeightRouter
        return WeightRouter()

    def test_high_weight_model_version(self, router):
        from src.storage.schemas import CameraFingerprint, Fingerprint
        item = CameraFingerprint(
            ip="1.1.1.1", port=80, weight=1.0,
            fingerprint=Fingerprint(vendor="hikvision", model="DS-2CD2142", version="V5.4.5"),
        )
        assert router.classify(item) == "high"

    def test_low_weight_model_only(self, router):
        from src.storage.schemas import CameraFingerprint, Fingerprint
        item = CameraFingerprint(
            ip="1.1.1.1", port=80, weight=0.7,
            fingerprint=Fingerprint(vendor="hikvision", model="DS-2CD2142"),
        )
        assert router.classify(item) == "low"

    def test_low_weight_vendor_only(self, router):
        from src.storage.schemas import CameraFingerprint, Fingerprint
        item = CameraFingerprint(
            ip="1.1.1.1", port=80, weight=0.0,
            fingerprint=Fingerprint(vendor="hikvision"),
        )
        assert router.classify(item) == "low"

    def test_skip_no_vendor(self, router):
        from src.storage.schemas import CameraFingerprint, Fingerprint
        item = CameraFingerprint(
            ip="1.1.1.1", port=80, weight=0.0,
            fingerprint=Fingerprint(),
        )
        assert router.classify(item) == "skip"
