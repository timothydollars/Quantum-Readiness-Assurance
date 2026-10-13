"""Acceptance tests for the PEM adapter. Run scripts/make_test_certs.sh first."""

from pathlib import Path

import pytest

from qraf.cbom_lite.adapters.pem_certs import read_certificates
from qraf.model import AssetType, EvidenceLevel

CERTS = Path(__file__).parent / "fixtures" / "certs"

pytestmark = pytest.mark.skipif(
    not (CERTS / "rsa2048.pem").exists(), reason="run: bash scripts/make_test_certs.sh"
)


def by_subject(findings, cn):
    return next(f for f in findings if cn in f.extra.get("subject", ""))


def test_reads_directory_and_skips_non_certs():
    findings = read_certificates(CERTS)
    assert len(findings) == len(list(CERTS.glob("*.pem")))  # notes.txt is skipped


def test_rsa_certificate():
    f = by_subject(read_certificates(CERTS), "qraf-test-rsa")
    assert (f.algorithm, f.parameter) == ("RSA", "2048")
    assert f.asset_type == AssetType.CERTIFICATE
    assert f.evidence_level == EvidenceLevel.OBSERVED
    assert f.source == "pem_file"
    for key in ("subject", "issuer", "serial", "not_before", "not_after", "signature_algorithm"):
        assert f.extra.get(key), key


def test_ec_certificate():
    f = by_subject(read_certificates(CERTS), "qraf-test-ec")
    assert (f.algorithm, f.parameter) == ("ECDSA", "P-256")


def test_single_file():
    assert len(read_certificates(CERTS / "rsa2048.pem")) == 1
