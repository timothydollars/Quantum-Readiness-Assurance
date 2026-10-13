"""Acceptance tests for docs/CLASSIFICATION.md. Do not edit to make them pass; fix the code."""

import pytest

from qraf.cbom_lite.classify import classify, normalize_algorithm
from qraf.model import Category


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("ML-KEM-768", ("ML-KEM", "768")),
        ("mlkem768", ("ML-KEM", "768")),
        ("MLKEM_1024", ("ML-KEM", "1024")),
        ("ML-DSA-65", ("ML-DSA", "65")),
        ("mldsa44", ("ML-DSA", "44")),
        ("SLH-DSA-SHA2-128s", ("SLH-DSA", "SHA2-128s")),
        ("rsaEncryption", ("RSA", "")),
        ("RSA", ("RSA", "")),
        ("X25519MLKEM768", ("X25519MLKEM768", "")),
        ("SomethingNew", ("SomethingNew", "")),
    ],
)
def test_normalize(raw, expected):
    assert normalize_algorithm(raw) == expected


@pytest.mark.parametrize(
    "family, param, category, level, weak",
    [
        ("RSA", "2048", Category.VULNERABLE, 0, False),
        ("RSA", "1024", Category.VULNERABLE, 0, True),
        ("ECDSA", "P-256", Category.VULNERABLE, 0, False),
        ("ECDH", "X25519", Category.VULNERABLE, 0, False),
        ("Ed25519", "", Category.VULNERABLE, 0, False),
        ("DH", "2048", Category.VULNERABLE, 0, False),
        ("ML-KEM", "512", Category.RESISTANT, 1, False),
        ("ML-KEM", "768", Category.RESISTANT, 3, False),
        ("ML-KEM", "1024", Category.RESISTANT, 5, False),
        ("ML-DSA", "44", Category.RESISTANT, 2, False),
        ("ML-DSA", "65", Category.RESISTANT, 3, False),
        ("ML-DSA", "87", Category.RESISTANT, 5, False),
        ("SLH-DSA", "SHA2-128s", Category.RESISTANT, 1, False),
        ("SLH-DSA", "SHAKE-256f", Category.RESISTANT, 5, False),
        ("X25519MLKEM768", "", Category.HYBRID, 3, False),
        ("AES", "256", Category.SYMMETRIC_OK, None, False),
        ("SHA-256", "", Category.SYMMETRIC_OK, None, False),
        ("AES", "128", Category.SYMMETRIC_REVIEW, None, False),
        ("SHA-1", "", Category.SYMMETRIC_REVIEW, None, True),
        ("3DES", "", Category.SYMMETRIC_REVIEW, None, True),
        ("FooCipher", "", Category.UNKNOWN, None, False),
    ],
)
def test_classify(family, param, category, level, weak):
    result = classify(family, param)
    assert result.category == category
    assert result.nist_quantum_level == level
    assert result.classical_weak == weak
