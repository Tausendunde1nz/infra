# TU1NZ Control SSOT

This repository branch is the authoritative, versioned source for TU1NZ control artifacts at `/opt/tu1nz_repos/control`.

Only the explicit allowlist in `.gitignore` is versioned. Existing legacy, diagnostic, secret-like, and generated files in the directory remain untracked by design.

Operational changes follow this sequence:

1. document the intended state here;
2. create and verify a rollback backup;
3. commit and push the change;
4. activate the committed artifact;
5. validate the live state and record the result.

The branch `control-main` in `Tausendunde1nz/infra` is the baseline for this independent Control history. M1 application work must use a separate repository and branch.
