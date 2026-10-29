# Vulnerability domain contracts

`remediator.domain` exports Pydantic v2 models independent of the API, scanners,
and persistence. These are validated observations, not exploitation claims or
verified remediation outcomes. The API continues to expose only its existing
health endpoint and documentation.

## Concepts

- `Asset`: `type` is `repository` or `container_image`; `locator` identifies the
  assessed repository or image. A package is a component, never an asset.
- `Component`: `name`, `ecosystem`, and `installed_version` are required;
  `location` optionally identifies a manifest, file, or scanner target location.
  Versions and ecosystems are opaque strings; no version comparison is implied.
- `Vulnerability`: required `primary_id`, optional `aliases`, `title`,
  `description`, `severity`, and advisory `references`. Severity is an optional
  source label, not a synthesized classification. Missing metadata stays `None`
  or an empty reference/alias list. IDs and aliases keep their source spelling;
  there is no deduplication, alias correlation, or CVE-only restriction.
- `Scanner`: required `name` and optional `version` when known.
- `Evidence`: `scanner`, timezone-aware `observed_at`, scanned `target`, and an
  opaque `artifact_reference` to the original output. References are not fetched
  or interpreted. Findings carry provenance, not duplicated raw reports.
- `Finding`: composes an `asset`, `component`, `vulnerability`, `evidence`, and
  `fix`. No database IDs, exploitation assertions, or remediation state exist.
- `ScanResult`: an opaque scanner `execution_id`, one `asset` and `scanner`,
  explicit `status`, normalized `findings`, and diagnostic `errors`.

## Validation and tradeoffs

Every model rejects unknown fields, including nested models. Required text and
provided optional text must contain a non-whitespace character; numeric values
are not coerced to text. Text is otherwise preserved rather than stripped or
canonicalized. Locators, artifact references, advisory IDs, and versions have no
universal format restriction. No URL availability, digest, or ecosystem-specific
validation is performed.

`observed_at` rejects naive datetimes and accepts ISO 8601 timestamps with offsets.
Serialization retains the represented offset (UTC may serialize as `Z`), not
necessarily the exact input timestamp spelling. JSON output is deterministic for
a given validated model; list ordering and source values are preserved rather
than sorted. Missing defaults become explicit when dumping JSON.

Fix information always has an explicit semantic state:

| `fix.status` | `fixed_versions` | Meaning |
| --- | --- | --- |
| `unknown` (default) | Empty | No fixed-version information was supplied. |
| `no_fix` | Empty | Source explicitly reports no fix for this observation. |
| `available` | Nonempty | Source supplies candidate fixed versions. |

Omitting `fix` means **unknown**, never confirmed no fix. A `no_fix` observation
is limited to its source and observation time; it is not proof that a fix can
never exist. Candidate versions do not assert that an upgrade works or has been
verified. Available versions require `available`; the other states reject them.

| Scan status | Findings | Errors |
| --- | --- | --- |
| `success` | Zero or more | Must be empty |
| `partial` | Zero or more | At least one nonblank diagnostic required |
| `failed` | Must be empty | At least one nonblank diagnostic required |

A successful empty scan is a completed scan with no reported findings. A partial
or failed empty scan must never be interpreted as a clean result. Recoverable
output from an unsuccessful run uses `partial`, even if it contains no findings.
Finding assets and scanner metadata must equal the enclosing scan's metadata;
aggregating multiple scanners or assets is deliberately outside this contract.
Adapters must apply the same known scanner version consistently at both levels.
These invariants validate supplied status; the model cannot detect an adapter
that incorrectly labels incomplete output as successful.

These models validate construction and deserialization, not workflow transitions.
They use ordinary mutable Pydantic collections; callers should revalidate after
editing a payload. `model_construct` and `model_copy(update=...)` bypass validation
and should not be used to accept untrusted observations.

## Examples

The offline, entirely synthetic examples in
[`repository_scan.json`](../tests/fixtures/repository_scan.json) and
[`container_image_scan.json`](../tests/fixtures/container_image_scan.json)
show both asset types, source aliases, artifact references, optional scanner
versions, and different fix states. They are not scanner report schemas.

```python
from pathlib import Path

from remediator.domain import ScanResult

scan = ScanResult.model_validate_json(
    Path("tests/fixtures/repository_scan.json").read_text()
)
encoded = scan.model_dump_json()
assert ScanResult.model_validate_json(encoded) == scan
```

Scanner execution/parsing, enrichment, storage, package-version comparison,
remediation, verification, and new endpoints are intentionally excluded.
