# Finding -> CycloneDX 1.6 mapping (specification)

`qraf.cbom_lite.cyclonedx.to_cyclonedx` must produce a document that passes the
official CycloneDX 1.6 JSON schema (the test uses `cyclonedx-python-lib`'s strict
validator). Read the OWASP *Authoritative Guide to CBOM* before starting.

## Top level

| Field | Value |
| --- | --- |
| `bomFormat` | `"CycloneDX"` |
| `specVersion` | `"1.6"` |
| `serialNumber` | `"urn:uuid:<new uuid4>"` |
| `version` | `1` |
| `metadata.timestamp` | UTC time of the run, ISO 8601 |
| `metadata.tools.components` | one entry: `{"type": "application", "name": "CBOM-Lite", "version": tool_version}` |

## One component per Finding

* `type`: `"cryptographic-asset"`; `bom-ref`: the Finding's `asset_id` (must be unique).
* `name`: algorithm plus parameter (for example `"RSA-2048"`); for certificates the subject.
* `cryptoProperties.assetType`: the Finding's `asset_type` value.
* **algorithm** findings: `cryptoProperties.algorithmProperties` with `primitive`,
  `parameterSetIdentifier` (if a parameter exists) and `nistQuantumSecurityLevel`
  (from `classify`; leave it out when the level is `None`).
* **certificate** findings: `cryptoProperties.certificateProperties` with
  `subjectName`, `issuerName`, `notValidBefore`, `notValidAfter` and
  `certificateFormat: "X.509"`. Also emit a second component for the certificate's
  public-key algorithm (bom-ref `"<asset_id>:key"`, assetType `algorithm`) and link
  the two in the top-level `dependencies` list:
  `{"ref": "<asset_id>", "dependsOn": ["<asset_id>:key"]}`.
* **protocol** findings: `cryptoProperties.protocolProperties` with `type`
  (`"tls"` or `"ssh"`) and `version`.
* `properties` (name/value pairs) carry QRAF fields that CycloneDX has no slot for:
  `qraf:evidenceLevel`, `qraf:source`, `qraf:location`, `qraf:category`,
  `qraf:classicalWeak`, and, when present, `qraf:owner`, `qraf:vendor`,
  `qraf:dataClasses` (comma-separated).
