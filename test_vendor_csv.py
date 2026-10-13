import pytest

from qraf.cbom_lite.adapters.vendor_csv import read_vendor_questionnaire
from qraf.model import EvidenceLevel


def test_template_rows(root):
    findings = read_vendor_questionnaire(root / "examples" / "vendor_questionnaire_template.csv")
    assert len(findings) == 2
    first = findings[0]
    assert first.evidence_level == EvidenceLevel.VENDOR_ATTESTED
    assert first.source == "vendor_csv"
    assert first.vendor.startswith("Example Core Processor")
    assert first.algorithm == "ECDH"
    assert first.extra["pqc_roadmap_date"] == "2028-06"


def test_missing_column(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("vendor,service\nA,B\n")
    with pytest.raises(ValueError, match="algorithm"):
        read_vendor_questionnaire(bad)
