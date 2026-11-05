# Fixed-version candidates

For exactly versioned PyPI dependencies, each finding carries a fixed-version
**candidate** when the advisory's own range data supports one, with the evidence
behind it. A candidate is what an advisory reports. It is not proof that the
release exists on PyPI, installs, resolves with other dependencies, or is
compatible. A candidate can also be a large jump: an advisory with only
`introduced: 0, fixed: 5.2.16` names 5.2.16 even for Django 2.2.0. Nothing here
edits files, plans, or verifies.

## When a finding is evaluated

The adapter evaluates a finding only when coverage confirms its installed
version is an **exact pin**: a lockfile entry, or a direct `==`/`===` pin whose
version is exactly the one the scanner reported (see
[coverage evidence](osv-scanner.md#coverage-evidence)). Anything else, such as a
lower bound like `requests>=2.0` or a package reached through `-r`, gets reason
`installed_version_unconfirmed`. Other ecosystems are not evaluated: their fix
information stays `unknown` with no evidence.

## How ranges are interpreted

Each advisory is evaluated independently, using only its `affected` entries for
the finding's own package (`PyPI`, PEP 503 name match) and only `ECOSYSTEM`
ranges. Versions are compared with PEP 440 (`packaging`), never lexically, so
`1.9 < 1.10`, pre-releases sort first, and `2.2 == 2.2.0`.

Following the OSV schema, events are sorted by version. `introduced` is
inclusive (`0` is unbounded below, so it covers even `0.0.dev1`), `fixed` is exclusive, and `last_affected`
is inclusive. The interval containing the installed version determines the
result:

| Situation | `fix.status` | `evidence.reason` |
|---|---|---|
| The interval is closed by a `fixed` event | `available`, `fixed_versions` = that event | `fixed_event` |
| The interval ends at `last_affected` (names no fix) | `unknown` | `last_affected_only` |
| The interval has no closing event | `unknown` | `open_ended` |
| Several containing intervals name different fixes | `unknown` | `conflicting_ranges` |
| Another range of the same advisory still contains the candidate | `unknown` | `candidate_still_affected` |
| No range contains the installed version | `unknown` | `not_affected_by_ranges` |
| The explicit `versions` list and the ranges disagree | `unknown` | `versions_list_disagrees` |
| No affected entry for this package, or no `ECOSYSTEM` range | `unknown` | `no_matching_package`, `no_supported_range` |
| `limit` events, a range without `introduced`, events at the same version, or an invalid PEP 440 version | `unknown` | `unsupported_event`, `invalid_range`, `invalid_version` |
| An affected entry for this package cannot be parsed | `unknown` | `malformed_affected` |

Advisory ranges never produce `no_fix`. The scanner's own match is not assumed
to be correct. For example, OSV-Scanner v2.3.0 matches PYSEC-2015-17 to
`requests` 2.0 through its explicit `versions` list even though its range starts
at 2.1.0. That disagreement stays `unknown`.

## What a report records

Schema version 3 adds two optional fields:

- `vulnerability.affected`: the advisory's affected entries for the finding's
  package, with every range and its events as reported (including non-ECOSYSTEM
  ranges) and the count of explicitly listed versions. The full advisory stays
  in the raw `stdout.json` artifact.
- `fix.evidence`: `applicability` (`affected`, `not_affected`, or `unknown`),
  `reason`, a `detail`, the `introduced`/`fixed`/`last_affected` bounds of the
  containing interval, and `listed_in_versions`.

The models enforce the rules: only `fixed_event` evidence makes a fix
`available`, `fixed_versions` must equal the evidenced event, and evidence can
never accompany `no_fix`.

## Advisory groups

`group_fix(group, scan)` combines the per-advisory results for an alias group
from [correlation](correlation.md):

- `candidate`: every advisory in the group is `available` with the same fixed
  version under PEP 440. One reported spelling is chosen deterministically.
- `conflict`: some advisories name a fix and others do not, or they name
  different fixes. No version is selected; the highest is never chosen silently.
- `unknown`: no advisory supports a fix, or the group spans several installed
  versions.

Every per-advisory result is returned alongside the group status.

Not included: release existence checks, dependency resolution, compatibility
testing, remediation plans, and verification.
