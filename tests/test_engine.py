"""Unit tests for the signature engine core."""
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.layers.layer2_fingerprinter.signatures.schema import (
    BrandKeyword, SignaturePattern, OnvifParser, ExtraPattern, VendorSignature,
)
from src.layers.layer2_fingerprinter.engine import SignatureEngine
from src.layers.layer2_fingerprinter.resolver import AggregationResolver, MatchResult
from src.layers.layer2_fingerprinter.probers.types import CollectedData


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hikvision_sig() -> VendorSignature:
    return VendorSignature(
        vendor="hikvision",
        aliases=["hik"],
        favicon_hashes=[999357577],
        brand_keywords=[
            BrandKeyword(pattern="hikvision", scope=["html"]),
            BrandKeyword(pattern="DVRDVS-Webs", scope=["headers"]),
        ],
        model_patterns=[
            SignaturePattern(regex=r"DS-2CD\d+[A-Za-z\d-]*", scope=["html"]),
            SignaturePattern(regex=r"<model>(.*?)</model>", scope=["xml_text"], group=1),
        ],
        version_patterns=[
            SignaturePattern(
                regex=r"<firmwareVersion>(.*?)</firmwareVersion>",
                scope=["xml_text"], group=1, normalize="prefix_v",
            ),
        ],
        onvif_parsers=[
            OnvifParser(
                manufacturer_match=["hikvision", "hik"],
                model_tag="tds:Model",
                firmware_tag="tds:FirmwareVersion",
            ),
        ],
        extra_patterns=[
            ExtraPattern(type="ssl_cn", regex="hikvision", scope=["ssl_cert"]),
        ],
    )


def _dahua_sig() -> VendorSignature:
    return VendorSignature(
        vendor="dahua",
        aliases=["dh"],
        favicon_hashes=[2019488876],
        brand_keywords=[
            BrandKeyword(pattern="dahua", scope=["html"]),
            BrandKeyword(pattern="DahuaWEB", scope=["headers"]),
        ],
        model_patterns=[
            SignaturePattern(regex=r"IPC-HFW\d+[A-Za-z\d-]*", scope=["html"]),
        ],
        version_patterns=[
            SignaturePattern(
                regex=r"<firmwareVersion>(.*?)</firmwareVersion>",
                scope=["xml_text"], group=1, normalize="prefix_v",
            ),
        ],
        endpoint_probes=[],
        onvif_parsers=[],
        rtsp_paths=[],
        extra_patterns=[],
    )


# ===========================================================================
# Engine tests
# ===========================================================================

class TestSignatureEngine:

    def setup_method(self):
        self.engine = SignatureEngine([_hikvision_sig(), _dahua_sig()])

    def test_favicon_hash_match(self):
        data = CollectedData(ip="1.2.3.4", port=80, favicon_hash=999357577)
        matches = self.engine.match(data)
        vendors = [m for m in matches if m.field == "vendor"]
        assert any(m.vendor == "hikvision" for m in vendors)
        assert not any(m.vendor == "dahua" for m in vendors)

    def test_favicon_hash_no_match(self):
        data = CollectedData(ip="1.2.3.4", port=80, favicon_hash=12345)
        matches = self.engine.match(data)
        favicon_matches = [m for m in matches if m.source == "favicon_hash"]
        assert len(favicon_matches) == 0

    def test_brand_keyword_in_html(self):
        data = CollectedData(ip="1.2.3.4", port=80, html="<title>Hikvision Camera</title>")
        matches = self.engine.match(data)
        assert any(m.vendor == "hikvision" and m.source == "html" for m in matches)

    def test_brand_keyword_in_headers(self):
        data = CollectedData(
            ip="1.2.3.4", port=80,
            headers={"server": "DVRDVS-Webs"},
        )
        matches = self.engine.match(data)
        assert any(m.vendor == "hikvision" and m.source == "headers" for m in matches)

    def test_brand_keyword_case_insensitive(self):
        data = CollectedData(ip="1.2.3.4", port=80, html="WELCOME TO HIKVISION")
        matches = self.engine.match(data)
        assert any(m.vendor == "hikvision" for m in matches)

    def test_model_pattern_extraction(self):
        data = CollectedData(
            ip="1.2.3.4", port=80,
            html="<div>Camera DS-2CD2142FWD</div>",
        )
        matches = self.engine.match(data)
        model_matches = [m for m in matches if m.field == "model"]
        assert len(model_matches) >= 1
        assert any(m.value == "DS-2CD2142FWD" for m in model_matches)

    def test_model_xml_group_extraction(self):
        data = CollectedData(
            ip="1.2.3.4", port=80,
            xml_texts=["<model>DS-2CD2142FWD</model>"],
        )
        matches = self.engine.match(data)
        model_matches = [m for m in matches if m.field == "model"]
        assert any(m.value == "DS-2CD2142FWD" for m in model_matches)

    def test_version_with_prefix_v_normalize(self):
        data = CollectedData(
            ip="1.2.3.4", port=80,
            xml_texts=["<firmwareVersion>5.4.5</firmwareVersion>"],
        )
        matches = self.engine.match(data)
        version_matches = [m for m in matches if m.field == "version"]
        assert len(version_matches) >= 1
        # Both vendors have firmwareVersion pattern; at least one should normalize
        values = [m.value for m in version_matches]
        assert "V5.4.5" in values

    def test_version_skips_xml_declaration(self):
        data = CollectedData(
            ip="1.2.3.4", port=80,
            xml_texts=["<firmwareVersion>1.0</firmwareVersion>"],
        )
        matches = self.engine.match(data)
        version_matches = [m for m in matches if m.field == "version"]
        assert len(version_matches) == 0

    def test_onvif_manufacturer_match(self):
        data = CollectedData(
            ip="1.2.3.4", port=80,
            onvif_response=(
                '<tds:GetDeviceInformationResponse>'
                '<tds:Manufacturer>HIKVISION</tds:Manufacturer>'
                '<tds:Model>DS-2CD2142FWD</tds:Model>'
                '<tds:FirmwareVersion>V5.4.5</tds:FirmwareVersion>'
                '</tds:GetDeviceInformationResponse>'
            ),
        )
        matches = self.engine.match(data)
        assert any(m.vendor == "hikvision" and m.source == "onvif_response" for m in matches)
        assert any(m.field == "model" and m.value == "DS-2CD2142FWD" for m in matches)
        assert any(m.field == "version" and m.value == "V5.4.5" for m in matches)

    def test_extra_ssl_cn_match(self):
        data = CollectedData(
            ip="1.2.3.4", port=443,
            ssl_subject="CN=hikvision.local, O=Hikvision Digital",
        )
        matches = self.engine.match(data)
        assert any(m.source == "ssl_cert" and m.vendor == "hikvision" for m in matches)

    def test_no_matches_returns_empty(self):
        data = CollectedData(ip="1.2.3.4", port=80)
        matches = self.engine.match(data)
        assert matches == []

    def test_multiple_vendor_matches(self):
        """Both vendors can match on the same data (e.g., shared firmwareVersion tag)."""
        data = CollectedData(
            ip="1.2.3.4", port=80,
            html="<html>hikvision dahua</html>",
        )
        matches = self.engine.match(data)
        vendors = set(m.vendor for m in matches)
        assert "hikvision" in vendors
        assert "dahua" in vendors

    def test_all_signatures_run_no_early_stop(self):
        """Engine never stops at first vendor match -- all signatures are checked."""
        data = CollectedData(
            ip="1.2.3.4", port=80,
            favicon_hash=999357577,
            html="<title>Hikvision DS-2CD2142FWD</title>",
            headers={"server": "DVRDVS-Webs"},
            xml_texts=["<firmwareVersion>5.4.5</firmwareVersion>"],
        )
        matches = self.engine.match(data)
        # Should have matches from favicon, brand_keyword (html), brand_keyword (headers),
        # model (html), model (xml), version (xml)
        hik = [m for m in matches if m.vendor == "hikvision"]
        assert len(hik) >= 5


# ===========================================================================
# Resolver tests
# ===========================================================================

class TestAggregationResolver:

    def setup_method(self):
        self.resolver = AggregationResolver()

    def test_empty_returns_none(self):
        assert self.resolver.resolve([]) is None

    def test_vendor_majority_vote(self):
        matches = [
            MatchResult(vendor="hikvision", field="vendor", value="hikvision", source="html", pattern="hikvision"),
            MatchResult(vendor="hikvision", field="vendor", value="hikvision", source="headers", pattern="DVRDVS"),
            MatchResult(vendor="dahua", field="vendor", value="dahua", source="html", pattern="dahua"),
        ]
        fp = self.resolver.resolve(matches)
        assert fp.vendor == "hikvision"

    def test_model_picks_longest(self):
        matches = [
            MatchResult(vendor="hikvision", field="vendor", value="hikvision", source="html", pattern="hikvision"),
            MatchResult(vendor="hikvision", field="model", value="DS-2CD", source="html", pattern="DS-2CD.*"),
            MatchResult(vendor="hikvision", field="model", value="DS-2CD2142FWD", source="html", pattern="DS-2CD.*"),
        ]
        fp = self.resolver.resolve(matches)
        assert fp.model == "DS-2CD2142FWD"

    def test_version_picks_longest(self):
        matches = [
            MatchResult(vendor="hikvision", field="vendor", value="hikvision", source="html", pattern="hikvision"),
            MatchResult(vendor="hikvision", field="version", value="V5.4", source="xml", pattern=".*"),
            MatchResult(vendor="hikvision", field="version", value="V5.4.5 build 1701", source="xml", pattern=".*"),
        ]
        fp = self.resolver.resolve(matches)
        assert fp.version == "V5.4.5 build 1701"

    def test_cves_union(self):
        matches = [
            MatchResult(vendor="hikvision", field="vendor", value="hikvision", source="html", pattern="hikvision",
                        cves=["CVE-2021-36260"]),
            MatchResult(vendor="hikvision", field="model", value="DS-2CD", source="html", pattern=".*",
                        cves=["CVE-2021-36260", "CVE-2017-7921"]),
        ]
        fp = self.resolver.resolve(matches)
        assert "CVE-2021-36260" in fp.cves
        assert "CVE-2017-7921" in fp.cves

    def test_evidence_items_from_winning_vendor_only(self):
        matches = [
            MatchResult(vendor="hikvision", field="vendor", value="hikvision", source="html", pattern="hikvision"),
            MatchResult(vendor="dahua", field="vendor", value="dahua", source="html", pattern="dahua"),
        ]
        fp = self.resolver.resolve(matches)
        assert len(fp.evidence_items) == 1
        assert fp.evidence_items[0].field == "vendor"

    def test_services_from_sources(self):
        matches = [
            MatchResult(vendor="hikvision", field="vendor", value="hikvision", source="html", pattern="hikvision"),
            MatchResult(vendor="hikvision", field="model", value="DS-2CD", source="xml_text", pattern=".*"),
        ]
        fp = self.resolver.resolve(matches)
        assert "html" in fp.services
        assert "xml_text" in fp.services

    def test_model_only_returns_none(self):
        """Model/version matches without any vendor keyword should not produce a fingerprint."""
        matches = [
            MatchResult(vendor="hikvision", field="model", value="DS-2CD", source="html", pattern=".*"),
            MatchResult(vendor="hikvision", field="version", value="V5.4", source="xml", pattern=".*"),
        ]
        fp = self.resolver.resolve(matches)
        assert fp is None


# ===========================================================================
# Engine normalization tests
# ===========================================================================

class TestNormalization:

    def setup_method(self):
        self.engine = SignatureEngine([_hikvision_sig()])

    def test_prefix_v_adds_v(self):
        assert self.engine._normalize("5.4.5", "prefix_v") == "V5.4.5"

    def test_prefix_v_keeps_existing(self):
        assert self.engine._normalize("V5.4.5", "prefix_v") == "V5.4.5"

    def test_clean_v_strips_noise(self):
        # clean_v keeps only v/V, digits, and dots
        result = self.engine._normalize("V5.4.5_build_1701", "clean_v")
        assert result == "V5.4.51701"  # strips underscores and letters, keeps digits/dots

    def test_uppercase(self):
        assert self.engine._normalize("hikvision", "uppercase") == "HIKVISION"

    def test_no_normalize(self):
        assert self.engine._normalize("5.4.5", None) == "5.4.5"


# ===========================================================================
# Scoped text tests
# ===========================================================================

class TestScopedText:

    def setup_method(self):
        self.engine = SignatureEngine([_hikvision_sig()])

    def test_html_scope(self):
        data = CollectedData(ip="1.2.3.4", port=80, html="<h1>test</h1>")
        text = self.engine._get_scoped_text(["html"], data)
        assert "<h1>test</h1>" in text

    def test_headers_scope(self):
        data = CollectedData(ip="1.2.3.4", port=80, headers={"server": "nginx"})
        text = self.engine._get_scoped_text(["headers"], data)
        assert "server: nginx" in text

    def test_xml_text_scope(self):
        data = CollectedData(ip="1.2.3.4", port=80, xml_texts=["<root>data</root>"])
        text = self.engine._get_scoped_text(["xml_text"], data)
        assert "<root>data</root>" in text

    def test_multiple_scopes_concatenated(self):
        data = CollectedData(
            ip="1.2.3.4", port=80,
            html="<h1>test</h1>",
            headers={"server": "nginx"},
        )
        text = self.engine._get_scoped_text(["html", "headers"], data)
        assert "<h1>test</h1>" in text
        assert "server: nginx" in text

    def test_empty_scope_returns_none(self):
        data = CollectedData(ip="1.2.3.4", port=80)
        text = self.engine._get_scoped_text(["html"], data)
        assert text is None


# ===========================================================================
# Full pipeline integration test
# ===========================================================================

class TestFullPipeline:

    def test_hikvision_full_fingerprint(self):
        sigs = [_hikvision_sig(), _dahua_sig()]
        engine = SignatureEngine(sigs)
        resolver = AggregationResolver()

        data = CollectedData(
            ip="192.168.1.1", port=80,
            html="<html><title>Hikvision</title>DS-2CD2142FWD</html>",
            headers={"server": "DVRDVS-Webs"},
            favicon_hash=999357577,
            xml_texts=["<firmwareVersion>5.4.5</firmwareVersion>"],
        )

        matches = engine.match(data)
        fp = resolver.resolve(matches)

        assert fp is not None
        assert fp.vendor == "hikvision"
        assert fp.model == "DS-2CD2142FWD"
        assert fp.version == "V5.4.5"
        assert len(fp.evidence_items) >= 5
        assert fp.evidence is not None  # backward compat
        assert fp.matched_pattern is not None  # backward compat

    def test_dahua_full_fingerprint(self):
        sigs = [_hikvision_sig(), _dahua_sig()]
        engine = SignatureEngine(sigs)
        resolver = AggregationResolver()

        data = CollectedData(
            ip="192.168.1.2", port=80,
            html="<html>Dahua IPC-HFW5442T</html>",
            headers={"server": "DahuaWEB"},
            favicon_hash=2019488876,
        )

        matches = engine.match(data)
        fp = resolver.resolve(matches)

        assert fp is not None
        assert fp.vendor == "dahua"
        assert fp.model == "IPC-HFW5442T"

    def test_no_data_returns_none(self):
        engine = SignatureEngine([_hikvision_sig()])
        resolver = AggregationResolver()

        data = CollectedData(ip="1.2.3.4", port=80)
        matches = engine.match(data)
        fp = resolver.resolve(matches)
        assert fp is None

    def test_conflicting_signals_majority_wins(self):
        """When two vendors get equal vendor votes, model/version break the tie."""
        sigs = [_hikvision_sig(), _dahua_sig()]
        engine = SignatureEngine(sigs)
        resolver = AggregationResolver()

        # Both vendors get 1 brand keyword match, but hikvision gets favicon
        data = CollectedData(
            ip="1.2.3.4", port=80,
            html="hikvision dahua",
            favicon_hash=999357577,
        )

        matches = engine.match(data)
        fp = resolver.resolve(matches)

        assert fp.vendor == "hikvision"  # favicon breaks the tie


# ===========================================================================
# Case-sensitive model pattern tests
# ===========================================================================

class TestCaseSensitiveModels:

    def test_case_sensitive_prevents_webpack_hash_false_positive(self):
        """Lowercase webpack hash 'fd34c8dc' must NOT match case-sensitive FD pattern."""
        sig = VendorSignature(
            vendor="vivotek",
            model_patterns=[
                SignaturePattern(
                    regex=r'\bFD\d{3,}[A-Za-z\d-]*\b',
                    scope=["html"],
                    case_sensitive=True,
                )
            ],
        )
        engine = SignatureEngine([sig])
        data = CollectedData(
            ip="1.2.3.4", port=80,
            html='chunk-111c3e62.fd34c8dc.1770210573261.js',
        )
        matches = engine.match(data)
        assert len(matches) == 0

    def test_case_sensitive_matches_real_model(self):
        """Uppercase 'FD9187-HT' must match case-sensitive FD pattern."""
        sig = VendorSignature(
            vendor="vivotek",
            brand_keywords=[BrandKeyword(pattern="vivotek", scope=["html"])],
            model_patterns=[
                SignaturePattern(
                    regex=r'\bFD\d{3,}[A-Za-z\d-]*\b',
                    scope=["html"],
                    case_sensitive=True,
                )
            ],
        )
        engine = SignatureEngine([sig])
        data = CollectedData(
            ip="1.2.3.4", port=80,
            html='Vivotek FD9187-HT Network Camera',
        )
        matches = engine.match(data)
        assert len(matches) == 2  # 1 brand + 1 model
        model_match = [m for m in matches if m.field == "model"][0]
        assert model_match.value == "FD9187-HT"

    def test_case_insensitive_still_default(self):
        """Without case_sensitive flag, regex still matches both cases."""
        sig = VendorSignature(
            vendor="test",
            model_patterns=[
                SignaturePattern(
                    regex=r'\bDS-2CD\d+\b',
                    scope=["html"],
                )
            ],
        )
        engine = SignatureEngine([sig])
        # lowercase
        data1 = CollectedData(ip="1.2.3.4", port=80, html="ds-2cd1234")
        assert len(engine.match(data1)) == 1
        # uppercase
        data2 = CollectedData(ip="1.2.3.4", port=80, html="DS-2CD1234")
        assert len(engine.match(data2)) == 1
