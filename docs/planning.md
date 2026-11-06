# Remediation planning

`remediator.planning.plan(scan)` turns a normalized scan report into a
**remediation plan**: a specific upgrade proposal for each vulnerable dependency
it can defend, and an explicit refusal, with a reason, for every other one.
Planning is pure. It reads nothing but the report, makes no network calls,
starts no processes and edits nothing. It runs the same way in the CLI, the
container image, a worker or an API handler.

A proposal is evidence, not proof. It never establishes that the release exists
on PyPI, installs, resolves with other dependencies, or is compatible. Every
proposal lists these as `unknowns`.

```sh
uv run python -m remediator.planning report.json --output plan.json
```

The report is read without following symlinks and is limited to 64 MiB. The
plan is written under the same rules as scan output: a new file, no symlinked
path components, mode 0600.

## What gets a proposal

Plans have one entry per vulnerable **component slot** (asset key, ecosystem,
PEP 503 name, manifest path; see [correlation](correlation.md)). A slot gets a
proposal only if every check passes, in this order:

| Check | Refusal reason |
|---|---|
| The scan status is `success` | `scan_not_successful` |
| The finding's manifest is inside the scanned asset | `slot_unavailable` |
| The ecosystem is PyPI | `unsupported_ecosystem` |
| The manifest declares one version of the package | `multiple_installed_versions` |
| The manifest is a `*requirements*.txt` file (lockfiles are regenerated, not edited) | `unsupported_manifest` |
| Coverage confirms the installed version as an exact pin | `version_unconfirmed` |
| Each finding's recorded fix matches its own advisory ranges, recomputed | `no_fix_candidate`, `inconsistent_evidence` |
| No advisory group disagrees on a fix ([group status](fixes.md#advisory-groups) `conflict`) | `conflicting_advisories` |
| Every advisory group has a candidate (none is `unknown`) | `no_fix_candidate` |
| The highest candidate is newer than the installed version | `target_not_newer` |
| No range of any advisory for the package contains the highest candidate | `target_still_affected`, `target_unverifiable` |

The last check matters. Choosing the highest fixed version is safe only if no
advisory is reintroduced at that version, so the planner re-evaluates it
against every range with the same PEP 440 logic as [fixes](fixes.md). If any
group lacks a candidate, the whole slot is refused, so a proposal never
knowingly leaves an advisory open. Partial upgrades are deferred.

Reports are treated as input. The planner recomputes each finding's fix from its
advisory ranges and refuses a slot whose recorded evidence does not match.

## What a plan records

- `source`: the scan's execution ID, asset (including its key), scanner, status,
  coverage status, advisory source and execution window, so that later
  verification can check comparability.
- `limitations`: an unsuccessful scan, missing or incomplete coverage
  (unassessed packages may be vulnerable and are not planned), or a missing
  asset key. A plan with no entries is "nothing to propose" only when it also
  has no limitations.
- `entries`, for each slot:
  - the decision, the reason and a detail;
  - the installed versions;
  - every advisory group, with its identifiers and per-advisory fix evidence;
  - for proposals, the `change`: the manifest path, the package as reported by
    the scanner, the current and proposed versions, the new requirement, and
    `crosses_major_version`. Candidates can be large jumps: Django 2.2.0 →
    5.2.17 in the vulnerable fixture.

    `requirement` is the bare `name==version` the change implies. Applying it
    (Milestone 6) must preserve the original line's extras, environment markers
    and options; `--hash` values must be regenerated, which is why
    `requirement_hashes` is always listed as unknown.

The models enforce these rules:
- A proposal must have a slot, a candidate for every group, the highest
  candidate as its version, an upgrade of the single installed version, and
  every unknown listed.
- A refusal never carries a change.
- An unsuccessful scan can never produce a proposal.

Plans are deterministic: the same report gives byte-identical JSON, whatever
the order of its findings. `plan_schema_version` is 1.

## Not included

- Editing files and approval flows (Milestone 6).
- Checking that a release exists, resolver runs, and compatibility testing.
- Lockfiles, pyproject and indirect dependencies.
- An HTTP endpoint.
- Verification (Milestone 7).
