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
