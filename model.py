"""Shared data model for CBOM-Lite and QESM.

This file is part of the starter template. It defines the shapes that every
adapter must produce and every writer must consume. You may extend it (add
fields), but keep the existing field names so the acceptance tests still run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class EvidenceLevel(str, Enum):
    """How a finding was obtained. Auditors rely on observed evidence most."""

    OBSERVED = "observed"            # seen directly by a scan or file read
    VENDOR_ATTESTED = "vendor-attested"  # reported by a vendor questionnaire
    INFERRED = "inferred"            # deduced (e.g. from a library version)


class AssetType(str, Enum):
    """Mirrors CycloneDX cryptoProperties.assetType."""

    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    RELATED_CRYPTO_MATERIAL = "related-crypto-material"


class Category(str, Enum):
    """QRAF quantum-risk category for one algorithm (see docs/CLASSIFICATION.md)."""

    VULNERABLE = "quantum-vulnerable"
    RESISTANT = "quantum-resistant"
    HYBRID = "hybrid"
    SYMMETRIC_OK = "symmetric-adequate"
    SYMMETRIC_REVIEW = "symmetric-review"
    UNKNOWN = "unknown"


@dataclass
class Classification:
    category: Category
    nist_quantum_level: int | None  # 0 = not quantum-safe; 1-5 = NIST categories; None = n/a
    classical_weak: bool = False    # broken or deprecated even without a quantum computer


@dataclass
class Finding:
    """One place where cryptography is used. Adapters return lists of these."""

    asset_id: str                     # unique within one inventory run
    location: str                     # host:port, file path, or vendor/service name
    source: str                       # "pem_file", "tls_scan", "ssh_scan", "vendor_csv"
    evidence_level: EvidenceLevel
    asset_type: AssetType
    algorithm: str                    # normalized family name, e.g. "RSA", "ECDSA", "ML-KEM"
    parameter: str = ""               # e.g. "2048", "P-256", "768"
    primitive: str = ""               # CycloneDX primitive, e.g. "signature", "kem", "key-agree"
    protocol: str = ""                # e.g. "TLS 1.2" for protocol findings
    owner: str = ""
    vendor: str = ""
    data_classes: list[str] = field(default_factory=list)
    found_at: str = ""                # ISO 8601 date
    extra: dict[str, str] = field(default_factory=dict)  # certificate fields, raw names, notes
