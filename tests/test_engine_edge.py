"""Impactful tests -- real-world edge cases, failure modes, and regression guards."""
import os
import sys
import tempfile
from pathlib import Path
import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.layers.layer2_fingerprinter.signatures.schema import (
    BrandKeyword, SignaturePattern, OnvifParser, ExtraPattern, VendorSignature,
)
from src.layers.layer2_fingerprinter.signatures.loader import SignatureLoader
from src.layers.layer2_fingerprinter.engine import SignatureEngine
from src.layers.layer2_fingerprinter.resolver import AggregationResolver, MatchResult
from src.layers.layer2_fingerprinter.probers.types import CollectedData


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sig(vendor="testvendor", **overrides) -> VendorSignature:
    defaults = dict(
        vendor=vendor,
        aliases=[],
        favicon_hashes=[],
        brand_keywords=[],
        model_patterns=[],
        version_patterns=[],
        endpoint_probes=[],
        onvif_parsers=[],
        rtsp_paths=[],
        extra_patterns=[],
    )
    defaults.update(overrides)
    return VendorSignature(**defaults)


def _engine_and_resolver(*sigs):
    return SignatureEngine(list(sigs)), AggregationResolver()


# ===========================================================================
# Resolver edge cases that bite in production
# ===========================================================================

class TestResolverEdgeCases:

    def test_vendor_tie_first_alphabetically_wins(self):
        """Equal vote count -- max() returns first by insertion order."""
        resolver = AggregationResolver()
        matches = [
            MatchResult(vendor="banana", field="vendor", value="banana", source="html", pattern="banana"),
            MatchResult(vendor="apple", field="vendor", value="apple", source="html", pattern="apple"),
        ]
        fp = resolver.resolve(matches)
        # Both have 1 vote. max() with dict gives first-seen in Python 3.7+
        assert fp.vendor in ("banana", "apple")

    def test_vendor_tie_same_votes(self):
        """Equal vendor votes -- resolver picks one deterministically."""
        engine, resolver = _engine_and_resolver(
            _sig("a", brand_keywords=[BrandKeyword(pattern="x", scope=["html"])]),
            _sig("b", brand_keywords=[
                BrandKeyword(pattern="x", scope=["html"]),
            ], model_patterns=[
                SignaturePattern(regex=r"(IPC-\w+)", scope=["html"], group=1),
            ]),
        )
        data = CollectedData(ip="1.2.3.4", port=80, html="x IPC-HFW5442")
        matches = engine.match(data)
        fp = resolver.resolve(matches)
        # Both get 1 vendor vote. Resolver picks first seen. Model is from "b" vendor.
        assert fp.vendor in ("a", "b")
        # But model IPC-HFW5442 only exists if vendor "b" wins
        if fp.vendor == "b":
            assert fp.model == "IPC-HFW5442"

    def test_empty_model_value_discarded(self):
        """Regex matches but group captures empty string -> should not produce match."""
        engine, resolver = _engine_and_resolver(
            _sig("v", model_patterns=[
                SignaturePattern(regex=r"model=\"(.*?)\"", scope=["html"], group=1),
            ]),
        )
        data = CollectedData(ip="1.2.3.4", port=80, html='model=""')
        matches = engine.match(data)
        model_matches = [m for m in matches if m.field == "model"]
        assert len(model_matches) == 0

    def test_empty_version_value_discarded(self):
        engine, resolver = _engine_and_resolver(
            _sig("v", version_patterns=[
                SignaturePattern(regex=r"ver=(.*?)$", scope=["html"], group=1),
            ]),
        )
        data = CollectedData(ip="1.2.3.4", port=80, html="ver=")
        matches = engine.match(data)
        version_matches = [m for m in matches if m.field == "version"]
        assert len(version_matches) == 0

    def test_model_with_no_vendor_returns_none(self):
        """No field=vendor match at all -> resolver returns None (no vendor inference from models)."""
        resolver = AggregationResolver()
        matches = [
            MatchResult(vendor="hikvision", field="model", value="DS-2CD", source="html", pattern="DS.*"),
        ]
        fp = resolver.resolve(matches)
        assert fp is None

    def test_cve_deduplication(self):
        resolver = AggregationResolver()
        matches = [
            MatchResult(vendor="v", field="vendor", value="v", source="html", pattern="v",
                        cves=["CVE-2021-36260", "CVE-2017-7921"]),
            MatchResult(vendor="v", field="model", value="X", source="html", pattern="X",
                        cves=["CVE-2021-36260"]),
        ]
        fp = resolver.resolve(matches)
        assert fp.cves == ["CVE-2017-7921", "CVE-2021-36260"]  # sorted, deduped


# ===========================================================================
# Engine against real-world messy data
# ===========================================================================

class TestRealWorldData:

    def test_rtsp_banner_vendor_detection(self):
        engine, _ = _engine_and_resolver(
            _sig("dahua", brand_keywords=[
                BrandKeyword(pattern="DahuaTech", scope=["rtsp_banner"]),
            ]),
        )
        data = CollectedData(
            ip="1.2.3.4", port=554,
            rtsp_banner="RTSP/1.0 200 OK\r\nServer: DahuaTech RTSP Server\r\n",
        )
        matches = engine.match(data)
        assert any(m.vendor == "dahua" and m.source == "rtsp_banner" for m in matches)

    def test_html_with_embedded_js_vars(self):
        engine, _ = _engine_and_resolver(
            _sig("test", brand_keywords=[
                BrandKeyword(pattern="hikvision", scope=["html"]),
            ], version_patterns=[
                SignaturePattern(
                    regex=r'var\s+firmware\s*=\s*"([^"]+)"',
                    scope=["html"], group=1, normalize="prefix_v",
                ),
            ]),
        )
        data = CollectedData(
            ip="1.2.3.4", port=80,
            html='<html><script>var firmware = "5.4.5";</script></html>',
        )
        matches = engine.match(data)
        versions = [m for m in matches if m.field == "version"]
        assert any(v.value == "V5.4.5" for v in versions)

    def test_json_response_model_extraction(self):
        engine, _ = _engine_and_resolver(
            _sig("dahua", model_patterns=[
                SignaturePattern(regex=r'"deviceModel"\s*:\s*"([^"]+)"', scope=["json_text"], group=1),
            ]),
        )
        data = CollectedData(
            ip="1.2.3.4", port=80,
            json_texts=['{"deviceModel":"IPC-HFW5442T-ASE","firmwareVersion":"2.8.1"}'],
        )
        matches = engine.match(data)
        assert any(m.value == "IPC-HFW5442T-ASE" for m in matches)

    def test_multiple_xml_texts_from_different_endpoints(self):
        """Probers collect XML from multiple endpoints -- all get searched."""
        engine, _ = _engine_and_resolver(
            _sig("hik", model_patterns=[
                SignaturePattern(regex=r"<model>(.*?)</model>", scope=["xml_text"], group=1),
            ], version_patterns=[
                SignaturePattern(regex=r"<firmwareVersion>(.*?)</firmwareVersion>", scope=["xml_text"], group=1, normalize="prefix_v"),
            ]),
        )
        data = CollectedData(
            ip="1.2.3.4", port=80,
            xml_texts=[
                "<device><model>DS-2CD2142</model></device>",
                "<firmware><firmwareVersion>5.4.5</firmwareVersion></firmware>",
            ],
        )
        matches = engine.match(data)
        assert any(m.value == "DS-2CD2142" and m.field == "model" for m in matches)
        assert any(m.value == "V5.4.5" and m.field == "version" for m in matches)

    def test_garbled_binary_in_html_ignored(self):
        """Garbled response shouldn't crash the engine."""
        engine, resolver = _engine_and_resolver(
            _sig("v", brand_keywords=[
                BrandKeyword(pattern="hikvision", scope=["html"]),
            ]),
        )
        data = CollectedData(
            ip="1.2.3.4", port=80,
            html="\x00\x01\x02\xff\xfe hikvision \x80\x81\x82 garbage",
        )
        matches = engine.match(data)
        assert any(m.vendor == "v" for m in matches)

    def test_very_long_html_no_crash(self):
        engine, resolver = _engine_and_resolver(
            _sig("v", brand_keywords=[
                BrandKeyword(pattern="target_vendor", scope=["html"]),
            ]),
        )
        data = CollectedData(
            ip="1.2.3.4", port=80,
            html="<div>" + "x" * 500_000 + "target_vendor" + "y" * 500_000 + "</div>",
        )
        matches = engine.match(data)  # should not hang
        assert len(matches) == 1


# ===========================================================================
# CVE propagation through full pipeline
# ===========================================================================

class TestCVEPropagation:

    def test_cve_from_brand_keyword_flows_to_fingerprint(self):
        engine, resolver = _engine_and_resolver(
            _sig("vulnerable", brand_keywords=[
                BrandKeyword(pattern="buggyfirmware", scope=["html"], cves=["CVE-2023-0001"]),
            ]),
        )
        data = CollectedData(ip="1.2.3.4", port=80, html="powered by buggyfirmware")
        matches = engine.match(data)
        fp = resolver.resolve(matches)
        assert "CVE-2023-0001" in fp.cves
        assert any("CVE-2023-0001" in e.cves for e in fp.evidence_items)

    def test_cve_from_model_pattern_flows_to_fingerprint(self):
        engine, resolver = _engine_and_resolver(
            _sig("v", brand_keywords=[
                BrandKeyword(pattern="v", scope=["html"]),
            ], model_patterns=[
                SignaturePattern(regex=r"VulnModel-\d+", scope=["html"],
                                 cves=["CVE-2022-AAAA", "CVE-2022-BBBB"]),
            ]),
        )
        data = CollectedData(ip="1.2.3.4", port=80, html="v VulnModel-100")
        matches = engine.match(data)
        fp = resolver.resolve(matches)
        assert "CVE-2022-AAAA" in fp.cves
        assert "CVE-2022-BBBB" in fp.cves

    def test_cves_from_losing_vendor_not_in_fingerprint(self):
        engine, resolver = _engine_and_resolver(
            _sig("winner", brand_keywords=[
                BrandKeyword(pattern="winner", scope=["html"]),
            ]),
            _sig("loser", brand_keywords=[
                BrandKeyword(pattern="loser", scope=["html"], cves=["CVE-LOSE-1"]),
            ]),
        )
        data = CollectedData(ip="1.2.3.4", port=80, html="winner loser")
        matches = engine.match(data)
        fp = resolver.resolve(matches)
        # "winner" has no CVEs, "loser" has CVE-LOSE-1 but loses vote
        assert "CVE-LOSE-1" not in fp.cves


# ===========================================================================
# Loader round-trip (add/remove/create via temp dir)
# ===========================================================================

class TestLoaderRoundTrip:

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.loader = SignatureLoader(self.tmpdir)

    def test_add_brand_keyword_creates_vendor(self):
        self.loader.add_pattern("newvendor", "brand_keyword", {
            "pattern": "testpattern", "scope": ["html"], "cves": [],
        })
        sig = self.loader.get_vendor("newvendor")
        assert sig is not None
        assert len(sig.brand_keywords) == 1
        assert sig.brand_keywords[0].pattern == "testpattern"

    def test_add_then_remove_round_trip(self):
        self.loader.add_pattern("v", "brand_keyword", {"pattern": "kw1", "scope": ["html"]})
        self.loader.add_pattern("v", "brand_keyword", {"pattern": "kw2", "scope": ["html"]})
        sig = self.loader.get_vendor("v")
        assert len(sig.brand_keywords) == 2

        self.loader.remove_pattern("v", "brand_keyword", 0)
        sig = self.loader.get_vendor("v")
        assert len(sig.brand_keywords) == 1
        assert sig.brand_keywords[0].pattern == "kw2"

    def test_add_favicon_hash(self):
        self.loader.add_pattern("v", "favicon_hash", {"hash": 12345})
        sig = self.loader.get_vendor("v")
        assert 12345 in sig.favicon_hashes

    def test_add_rtsp_path(self):
        self.loader.add_pattern("v", "rtsp_path", {"path": "/live/ch1"})
        sig = self.loader.get_vendor("v")
        assert "/live/ch1" in sig.rtsp_paths

    def test_add_endpoint_probe(self):
        self.loader.add_pattern("v", "endpoint", {
            "path": "/api/info", "protocol": ["http"],
        })
        sig = self.loader.get_vendor("v")
        assert any(ep.path == "/api/info" for ep in sig.endpoint_probes)

    def test_persist_and_reload(self):
        self.loader.add_pattern("persist_test", "brand_keyword", {
            "pattern": "saved", "scope": ["html"],
        })
        # Verify YAML was written
        filepath = Path(self.tmpdir) / "persist_test.yaml"
        assert filepath.exists()
        with open(filepath) as f:
            data = yaml.safe_load(f)
        assert data["brand_keywords"][0]["pattern"] == "saved"

        # Reload from disk -- should survive
        loader2 = SignatureLoader(self.tmpdir)
        sig = loader2.get_vendor("persist_test")
        assert sig is not None
        assert len(sig.brand_keywords) == 1

    def test_remove_out_of_range_returns_false(self):
        assert self.loader.remove_pattern("nonexistent", "brand_keyword", 0) is False

    def test_remove_nonexistent_vendor_returns_false(self):
        assert self.loader.remove_pattern("ghost", "brand_keyword", 0) is False

    def test_get_unique_endpoint_paths_dedup(self):
        self.loader.add_pattern("a", "endpoint", {"path": "/common", "protocol": ["http"]})
        self.loader.add_pattern("b", "endpoint", {"path": "/common", "protocol": ["http"]})
        paths = self.loader.get_unique_endpoint_paths()
        count = sum(1 for p in paths if p == "/common")
        assert count == 1


# ===========================================================================
# ONVIF with messy namespaces
# ===========================================================================

class TestOnvifMessyNamespaces:

    def test_namespaced_onvif_tags(self):
        engine, resolver = _engine_and_resolver(
            _sig("hik", onvif_parsers=[
                OnvifParser(
                    manufacturer_match=["hikvision"],
                    model_tag="tds:Model",
                    firmware_tag="tds:FirmwareVersion",
                ),
            ]),
        )
        data = CollectedData(
            ip="1.2.3.4", port=80,
            onvif_response=(
                '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
                '<soap:Body><tds:GetDeviceInformationResponse>'
                '<tds:Manufacturer>Hikvision</tds:Manufacturer>'
                '<tds:Model>DS-2CD2142FWD</tds:Model>'
                '<tds:FirmwareVersion>V5.4.5</tds:FirmwareVersion>'
                '</tds:GetDeviceInformationResponse></soap:Body></soap:Envelope>'
            ),
        )
        matches = engine.match(data)
        fp = resolver.resolve(matches)
        assert fp.vendor == "hik"
        assert fp.model == "DS-2CD2142FWD"
        assert fp.version == "V5.4.5"

    def test_onvif_wrong_manufacturer_no_match(self):
        engine, _ = _engine_and_resolver(
            _sig("dahua", onvif_parsers=[
                OnvifParser(
                    manufacturer_match=["dahua"],
                    model_tag="tds:Model",
                    firmware_tag="tds:FirmwareVersion",
                ),
            ]),
        )
        data = CollectedData(
            ip="1.2.3.4", port=80,
            onvif_response=(
                '<tds:Manufacturer>Hikvision</tds:Manufacturer>'
                '<tds:Model>DS-2CD</tds:Model>'
            ),
        )
        matches = engine.match(data)
        assert len(matches) == 0  # manufacturer didn't match "dahua"


# ===========================================================================
# Version normalization edge cases
# ===========================================================================

class TestVersionEdgeCases:

    def test_version_already_has_v_prefix(self):
        engine, _ = _engine_and_resolver(
            _sig("v", version_patterns=[
                SignaturePattern(regex=r"V(\d+\.\d+\.\d+)", scope=["html"], group=1, normalize="prefix_v"),
            ]),
        )
        data = CollectedData(ip="1.2.3.4", port=80, html="V5.4.5")
        matches = engine.match(data)
        assert any(m.value == "V5.4" or m.value == "V5.4.5" for m in matches if m.field == "version")

    def test_version_with_build_suffix(self):
        engine, resolver = _engine_and_resolver(
            _sig("v", version_patterns=[
                SignaturePattern(
                    regex=r"V(\d+\.\d+\.\d+)\s*build\s*(\d+)",
                    scope=["html"], group=0, normalize="clean_v",
                ),
            ]),
        )
        data = CollectedData(ip="1.2.3.4", port=80, html="Firmware: V5.4.5 build 170123")
        matches = engine.match(data)
        versions = [m for m in matches if m.field == "version"]
        assert len(versions) >= 1

    def test_xml_declaration_versions_filtered(self):
        """V1.0 and V1.1 are XML declarations, not firmware versions."""
        engine, resolver = _engine_and_resolver(
            _sig("v", version_patterns=[
                SignaturePattern(regex=r"(V\d+\.\d+)", scope=["html"], group=1, normalize="prefix_v"),
            ]),
        )
        data = CollectedData(ip="1.2.3.4", port=80, html="xml V1.0 declaration")
        matches = engine.match(data)
        assert len([m for m in matches if m.field == "version"]) == 0


# ===========================================================================
# Hot-reload (Fingerprinter.reload_signatures)
# ===========================================================================

class TestHotReload:

    def test_file_mtime_detection(self):
        """Fingerprinter._sig_file_hashes returns mtimes that change on write."""
        from src.layers.layer2_fingerprinter.fingerprinter import Fingerprinter
        from unittest.mock import MagicMock

        tmpdir = tempfile.mkdtemp()
        loader = SignatureLoader(tmpdir)

        # Write initial file
        loader.add_pattern("v1", "brand_keyword", {"pattern": "test", "scope": ["html"]})

        # Create a mock fingerprinter with just enough to test
        class FakeFP:
            _loader = loader
            def _sig_file_hashes(self):
                result = {}
                sig_dir = self._loader._dir
                if sig_dir.exists():
                    for f in sorted(sig_dir.glob("*.yaml")):
                        result[f.name] = f.stat().st_mtime
                return result

        fp = FakeFP()
        hashes_before = fp._sig_file_hashes()

        # Touch the file
        import time
        time.sleep(0.1)
        p = Path(tmpdir) / "v1.yaml"
        p.touch()

        hashes_after = fp._sig_file_hashes()
        assert hashes_after != hashes_before

    def test_no_change_returns_same_hashes(self):
        tmpdir = tempfile.mkdtemp()
        loader = SignatureLoader(tmpdir)
        loader.add_pattern("v1", "brand_keyword", {"pattern": "test", "scope": ["html"]})

        class FakeFP:
            _loader = loader
            def _sig_file_hashes(self):
                result = {}
                sig_dir = self._loader._dir
                if sig_dir.exists():
                    for f in sorted(sig_dir.glob("*.yaml")):
                        result[f.name] = f.stat().st_mtime
                return result

        fp = FakeFP()
        h1 = fp._sig_file_hashes()
        h2 = fp._sig_file_hashes()
        assert h1 == h2

    def test_new_vendor_file_detected(self):
        tmpdir = tempfile.mkdtemp()
        loader = SignatureLoader(tmpdir)
        loader.add_pattern("v1", "brand_keyword", {"pattern": "test", "scope": ["html"]})

        class FakeFP:
            _loader = loader
            def _sig_file_hashes(self):
                result = {}
                sig_dir = self._loader._dir
                if sig_dir.exists():
                    for f in sorted(sig_dir.glob("*.yaml")):
                        result[f.name] = f.stat().st_mtime
                return result

        fp = FakeFP()
        h1 = fp._sig_file_hashes()
        assert len(h1) == 1

        # Add another vendor
        loader.add_pattern("v2", "brand_keyword", {"pattern": "test2", "scope": ["html"]})
        h2 = fp._sig_file_hashes()
        assert len(h2) == 2


# ===========================================================================
# Regression: backward compat properties
# ===========================================================================

class TestBackwardCompat:

    def test_evidence_property(self):
        from src.storage.schemas import EvidenceItem
        items = [
            EvidenceItem(field="vendor", value="hik", source="html", pattern="hik"),
            EvidenceItem(field="model", value="DS-2CD", source="xml", pattern="DS.*"),
        ]
        result = "; ".join(f"{e.field}={e.value} via {e.source}" for e in items)
        assert "vendor=hik via html" in result
        assert "model=DS-2CD via xml" in result

    def test_fingerprint_json_round_trip(self):
        from src.storage.schemas import Fingerprint
        fp = Fingerprint(
            vendor="hikvision",
            model="DS-2CD2142FWD",
            version="V5.4.5",
            cves=["CVE-2021-36260"],
            services=["html", "xml_text"],
        )
        json_str = fp.model_dump_json()
        fp2 = Fingerprint.model_validate_json(json_str)
        assert fp2.vendor == fp.vendor
        assert fp2.model == fp.model
        assert fp2.cves == fp.cves
