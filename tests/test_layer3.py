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
