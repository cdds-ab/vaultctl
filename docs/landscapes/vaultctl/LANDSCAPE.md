# vaultctl Landscape

vaultctl is a single-repo tool — there is no cross-repo landscape in the
client-engagement sense. This directory exists because the tool has
accumulated several cross-cutting design decisions worth documenting in
a structured way, separate from CLAUDE.md (which describes the
*current* state) and PR descriptions (which describe *changes*).

The convention follows the Architecture Decision Records (ADR) pattern
for `decisions/`. Subdirectories `patterns/` and `initiatives/` may be
added later if needed.

## Decisions

| # | Title | Status |
|---|-------|--------|
| [0001](decisions/0001-schema-inference-via-python-walker.md) | Schema inference via Python walker, not `cue import` | Accepted |

## Why a Landscape (Note on Convention)

Per the global Claude Code guideline, tool repos typically don't have a
landscape — landscapes group cross-repo work for client engagements.
vaultctl is an exception by virtue of size and decision density: the
choice to stay in Python over Go/Rust, the subprocess pattern for
`ansible-vault` and `cue`, the project-local `.vaultctl/` layout, the
schema inference approach — these are all decisions that future
contributors (including the user's future self) will benefit from
seeing in one place.

If the convention should win, the directory can collapse to flat
`docs/decisions/` later. The ADR files would migrate unchanged.

## Backlog of Decisions to Backfill

When relevant, these existing-but-undocumented decisions should be captured:

- Python over Go/Rust for the implementation language (#36 era — covered
  briefly in CLAUDE.md but not as an explicit ADR).
- CUE validation via `cue` binary subprocess instead of native Python
  binding (#34 — rationale lives in the issue body and PR #39 description).
- Project-local `.vaultctl/` directory layout, no backward compatibility
  with the legacy root-level `.vaultctl.yml` (#37/PR #38).

These remain in their PR descriptions and CLAUDE.md sections for now —
backfill is a P4 chore.
