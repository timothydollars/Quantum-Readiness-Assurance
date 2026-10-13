# QRAF CBOM-Lite v0.1 — implementation and verification

## Scope
This is an early research prototype for **authorized, synthetic** cryptographic inventory demonstrations. It does not prove banking-sector adoption, 80% discovery coverage, or operational PQC compliance. It must not be used for scanning systems without written authorization.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate   # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e '.[dev]'
bash scripts/make_test_certs.sh  # requires OpenSSL and a Bash shell
python -m pytest -v
```

The `dev` dependency includes the CycloneDX 1.6 strict JSON validator. A complete run **must** report 60 passed, 0 skipped, 0 failed. If the strict test skips, do not claim schema certification. The current authoring environment lacked the `cyclonedx-python-lib` package and could not download it; strict validation remains pending on a networked environment.

## Example workflow

```bash
qraf certs tests/fixtures/certs -o cert_findings.json
qraf vendors examples/vendor_questionnaire_template.csv -o vendor_findings.json
qraf cbom cert_findings.json vendor_findings.json -o inventory.cdx.json
qraf qesm examples/qesm_assets_example.csv -c config/qesm_weights.yaml -o ranked.csv --sensitivity sensitivity.json
```

**Important:** Finding identifiers from independent adapter runs can collide; this initial implementation checks for duplicate IDs and fails rather than silently overwriting. The `certs` adapter requires compatible `cryptography` or an OpenSSL executable for ML-DSA public-key certificates.

## Strict schema check (explicit)

```python
import json
from cyclonedx.validation.json import JsonStrictValidator
from cyclonedx.schema import SchemaVersion
bom=json.load(open('inventory.cdx.json',encoding='utf-8'))
errors=JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(bom))
assert errors is None, errors
print('CycloneDX 1.6 strict validation passed')
```

## Evidence required before public release

1. Save the full `pytest -v` output with a date, Python version and package versions.
2. Run the commands above and archive the synthetic outputs.
3. Confirm the strict schema validator passes with zero skipped tests.
4. Have a second developer follow the README on a clean environment.
5. Record actual development authorship and contributions accurately.
6. Create a real public repository, tag `v0.1.0`, and archive the release if desired. Do not backdate commits or represent this sandbox build as an already published release.

## Current limitations

- TLS and SSH parsers accept documented subsets of scanner JSON and need integration tests against pinned, actual scanner versions before production use.
- `classify()` follows the starter's simplified algorithm categories; it is not a formal NIST conformance assessment.
- The output schema test is defined by the starter but has not been executed in the authoring environment.
- The current CLI processes supplied scanner outputs; it does not initiate network scans.
- There are no institutional pilots, independently verified benchmarks, or security audit results included.
