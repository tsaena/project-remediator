# Finding correlation

`remediator.correlation` relates the findings of two scans of the same asset:
which observation in the earlier scan corresponds to which in the later one. It
is pure and deterministic: no scanning, I/O, or persistence.

## Correlation is not verification

Correlation never says that anything was fixed. An advisory that appears only in
the earlier scan (`only_before`) may have been remediated. It may equally have
disappeared because coverage changed, a manifest moved, advisory data changed,
or the scan was incomplete. Telling these apart is the job of independent
verification (Milestone 7), which will consume correlation together with
coverage and provenance. No correlation kind or reason means fixed, resolved, or
verified.

## Component slots

A finding is placed in a **component slot**: where a dependency is declared,
independent of its version or checkout.

| Part | Source |
|---|---|
| `asset_key` | The caller-supplied `Asset.key` (CLI `--asset-key`). Checkout paths are not identity. |
| `ecosystem` | As reported, compared exactly. |
| `name` | PEP 503 normalized for `PyPI` (`Django` → `django`, `zope.interface` → `zope-interface`); other ecosystems exactly as reported. |
| `manifest_path` | `Component.location` relative to `Asset.locator`, computed lexically with `/` separators. |

Installed version, execution ID, and timestamps are never part of a slot, so an
upgrade keeps its slot. The manifest path is derived from fields every report
already records, so this adds no schema change. A finding whose location is
missing, or lies outside the asset root, cannot be placed in a slot and is
reported as `ambiguous` with reason `slot_unavailable`.

## Advisory groups

Within one slot of one scan, advisories are grouped into **connected
components** of their identifiers (primary ID plus aliases). A group keeps
every original advisory ID, the union of identifiers, and each underlying
observation (finding index, aliases, installed version).

- Grouping is order-independent: the same findings in any order produce the same
  groups. OSV-Scanner v2.3.0's own `groups` are order-dependent and not
  transitive, so they stay in the raw `stdout.json` artifact as reported evidence
  and are not used as identity.
- Groups never span slots, so a CVE shared by two packages, or by the same
  package in two manifests, does not merge them.
- A group whose identifiers include more than one CVE is flagged
  `multiple_cves`: shared aliases may have linked distinct vulnerabilities.

`group_advisories(scan, asset_key)` returns one scan's groups.

## Correlating two scans

`correlate(before, after)` returns a `Correlation` with a comparability
`status`, `restrictions`, and `entries`.

Within each slot, groups from both scans are linked when their identifiers
intersect. Each connected set becomes one entry:

| Kind | Meaning | Reasons |
|---|---|---|
| `matched` | Exactly one group on each side | `identifiers_changed`, `version_changed`, `multiple_cves` (informational) |
| `only_before` | A group with no counterpart in the later scan | `possible_manifest_move`, `multiple_cves` |
| `only_after` | A group with no counterpart in the earlier scan | `possible_manifest_move`, `multiple_cves` |
| `ambiguous` | The relationship cannot be resolved | `alias_split` (one group became several), `alias_merge` (several became one), `overlapping_groups` (several on both sides), `duplicate_slot` (one slot held several installed versions in a scan, for example marker-split pins), `slot_unavailable` |

A moved manifest changes the slot, so its findings are always `only_before` and
`only_after`. When the same package's identifiers appear on both sides in
different manifests, both entries get the hint `possible_manifest_move`. A hint
never becomes a match.

## Comparability

Before entries are trusted, consider `status`:

- `unavailable`: no entries were produced. Either scan lacks an asset key, the
  keys or asset types differ, or a scan failed (it has no findings, so everything
  would look removed).
- `restricted`: entries were produced, but known differences limit what they can
  support. Each is listed in `restrictions` with the scan it applies to:
  partial scan, coverage missing or not `no_known_gaps`, provenance missing,
  scanner or scanner version changed or unknown, advisory source unknown,
  changed, or not reproducible, or advisory data fingerprints changed.
- `comparable`: none of the above. This still is not a verdict; it only means
  the two reports have no known reason to be incomparable.

Reports from before schema version 2 have no asset key, so they always correlate
as `unavailable`.

## Example

```python
from remediator.correlation import correlate
from remediator.domain import ScanResult

before = ScanResult.model_validate_json(open("before.json").read())
after = ScanResult.model_validate_json(open("after.json").read())
result = correlate(before, after)
for entry in result.entries:
    print(entry.kind, entry.slot, entry.reasons)
```

Not included: fixed-version interpretation (Milestone 4b), remediation, and
verification verdicts.
