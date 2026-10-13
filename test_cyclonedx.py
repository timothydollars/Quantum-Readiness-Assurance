"""Acceptance tests for docs/CBOM_MAPPING.md."""

import json

import pytest

from qraf.cbom_lite.cyclonedx import to_cyclonedx
from qraf.model import AssetType, EvidenceLevel, Finding


def sample_findings():
    return [
        Finding(
            asset_id="cert-1", location="lab/rsa2048.pem", source="pem_file",
            evidence_level=EvidenceLevel.OBSERVED, asset_type=AssetType.CERTIFICATE,
            algorithm="RSA", parameter="2048", primitive="signature",
            extra={"subject": "CN=qraf-test-rsa", "issuer": "CN=qraf-test-rsa", "serial": "1",
                   "not_before": "2026-10-12T00:00:00Z", "not_after": "2027-10-12T00:00:00Z",
                   "signature_algorithm": "sha256WithRSAEncryption"},
        ),
        Finding(
            asset_id="kex-1", location="lab-web:443", source="tls_scan",
            evidence_level=EvidenceLevel.OBSERVED, asset_type=AssetType.ALGORITHM,
            algorithm="ML-KEM", parameter="768", primitive="kem",
        ),
        Finding(
            asset_id="proto-1", location="lab-web:443", source="tls_scan",
            evidence_level=EvidenceLevel.OBSERVED, asset_type=AssetType.PROTOCOL,
            algorithm="TLS", protocol="TLS 1.3", extra={"version": "1.3"},
        ),
    ]


@pytest.fixture
def bom():
    return to_cyclonedx(sample_findings())


def test_top_level(bom):
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.6"
    assert bom["serialNumber"].startswith("urn:uuid:")
    assert bom["version"] == 1


def test_components(bom):
    refs = [c["bom-ref"] for c in bom["components"]]
    assert len(refs) == len(set(refs))
    assert {"cert-1", "cert-1:key", "kex-1", "proto-1"} <= set(refs)
    for c in bom["components"]:
        assert c["type"] == "cryptographic-asset"
    by_ref = {c["bom-ref"]: c for c in bom["components"]}
    assert by_ref["cert-1:key"]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
    assert by_ref["kex-1"]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3
    assert by_ref["proto-1"]["cryptoProperties"]["protocolProperties"]["type"] == "tls"
    assert {"ref": "cert-1", "dependsOn": ["cert-1:key"]} in bom["dependencies"]


def test_schema_valid(bom):
    validation = pytest.importorskip("cyclonedx.validation.json")
    from cyclonedx.schema import SchemaVersion

    validator = validation.JsonStrictValidator(SchemaVersion.V1_6)
    errors = validator.validate_str(json.dumps(bom))
    assert errors is None, errors
