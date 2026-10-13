# QRAF toolkit: CBOM-Lite and QESM

Open tools that help U.S. community banks, credit unions and their technology
providers prepare for post-quantum cryptography:

* **CBOM-Lite** finds where public-key cryptography is used (certificates, TLS,
  SSH, vendor answers) and writes a CycloneDX 1.6 cryptographic bill of materials.
* **QESM** (Quantum Exposure Scoring Model) ranks those assets for migration using
  data shelf-life, migration time, exposure, criticality and vendor dependency,
  with a sensitivity analysis.

Status: **pre-release (v0.1 in development)**. Part of the Quantum-Readiness
Assurance Framework (QRAF).

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
bash scripts/make_test_certs.sh   # throw-away certificates for the tests
pytest                            # acceptance tests
```

## Specifications

* `docs/CLASSIFICATION.md`: how algorithms are classified for quantum risk
* `docs/CBOM_MAPPING.md`: how findings map to CycloneDX 1.6
* `docs/QESM_SPEC.md`: the scoring model and sensitivity analysis

## Safety

Scan only systems you own or have written permission to scan. CBOM-Lite records
cryptographic metadata only, never transaction or customer data.

## Authorship and credits

Project proposed for Timothy Olatunji Ogundola. The uploaded starter skeleton, specifications,
and acceptance tests were supplied for this task; implementation of the unfinished modules
was generated with AI assistance in this ChatGPT session on October 12, 2026.
Timothy must review, test, and document his actual personal contributions before making
any authorship statements in an immigration petition or public repository.
List third-party code and libraries and preserve their applicable licences.

## Licence

Apache License 2.0 (see `LICENSE`).

## Implemented prototype and verification

See [Implementation and verification](docs/IMPLEMENTATION_AND_VERIFICATION.md) for the implemented CLI, synthetic examples, and the exact strict CycloneDX 1.6 validation procedure. A passing local unit-test suite is **not** a substitute for the strict schema validation test.
