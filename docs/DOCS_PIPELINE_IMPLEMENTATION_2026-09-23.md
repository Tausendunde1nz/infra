# Safe Docs pipeline: tested preparation, not yet activated

Current baseline: clean Docs main at4644acf9d04d291323962ea4710ad07fe1f7a111,
matching remote origin git@github.com:Tausendunde1nz/docs.git.
All five live unit/script files matched the prior hash/owner/mode manifest.
PDF prerequisites completed2026-09-23T18:02:34Z: only file, libpoppler134 and
poppler-utils installed at pinned versions; existing package versions unchanged.
Evidence: pdf-prerequisites-20260923T163256Z/ in the protected private base.

## Exact change
Install scripts/tu1nz_doc_pipeline.py as /usr/local/bin/tu1nz_doc_pipeline.py.
Replace only tu1nz_doc_auto.sh and tu1nz_doc_update.sh with the documented safe
wrapper. No arguments means --stage. Explicit --stage, --validate DIRECTORY,
or --publish DIRECTORY --reviewed-sha256 SHA256 are the only modes.
Correct only WorkingDirectory in the existing active drop-in from docs_repo to
docs. User/group chatops, HOME, base unit and timer schedule remain unchanged.
The timer calls the default staging mode and cannot reach commit or push.
No MyChatBuddy, container, Hetzner or Tailnet change is included.

Staging lives in /opt/tu1nz_repos/doc-staging, directory0700, outputs0600.
Reports contain only UTC date, fixed verified server name, five service-state
enums and the node/cAdvisor target states. Exact input keys/values are allowlisted.
No ENV/config secrets, application data, logs or arbitrary caller text are read.
Report labels explicitly limit this to an operational summary, not a full audit.
Unknown fields/values, suspicious extracted text and private-key markers block.

## PDF and iteration evidence
The installed wkhtmltopdf generated a first valid report, but a repeated isolated
staging test timed out at60seconds. Nothing live had been changed. The final
builder therefore uses deterministic Python-standard-library PDF generation:
one A4 page, embedded text commands and Helvetica, no JavaScript/external assets.
A standard binary comment ensures Git treats PDF bytes as binary; the initial
ASCII-heavy PDF otherwise triggered whitespace checks on valid xref padding.
No additional dependency was installed for generation.
Every artifact passes signature, file, pdfinfo (one page), exact pdftotext content,
secret scan, and first-page pdftoppm PNG rendering. Layout bounds are enforced.
The final layout was visually inspected: readable, complete, no clipping.
Final validated fixture:
/opt/tu1nz_repos/network-hardening-private-2026-09-22/pipeline-offline-tests/stage-20260923T180922Z-l6owvtt2/

Final suite:10 tests passed in3.666seconds. Covers valid PDF; invalid PDF;
empty/simulated-secret input; dirty/untracked files not staged; missing/wrong
remote; successful publication to a temporary bare remote; repeat with no new
commit; rejected push with no false success; reviewed-hash requirement;
staging with all Git calls forbidden and unchanged local/remote HEAD; and
actual transaction restore function restoring fixture bytes/mode and removing
only the newly created fixture file (systemctl mocked in that offline test).
Production Docs Git was unchanged and clean after all tests.

## Publish behavior
Requires chatops, exact configured remote, clean repository/index, main branch,
remote HEAD equal local HEAD, current UTC report date, and explicitly reviewed
PDF checksum. Validates text and rendered PDF again. Copies atomically after
backing up an existing target. Stages only the expected filename and checks exact
staged/committed path plus committed blob SHA before pushing and verifying remote.
Unchanged extracted content produces no commit. Pipeline flock serializes its
own runs; it does not claim to lock out arbitrary external Git actors. Repository
state and HEAD are rechecked before commit. Unrelated changes block publication.
A failed push preserves the reviewed local commit for diagnosis, returns failure,
and never resets shared Git history. Do not blindly rerun publication then:
resolve remote/pending-commit state explicitly. No forced push is used.

## Transaction / rollback
Executable private copy:
/opt/tu1nz_repos/network-hardening-private-2026-09-22/apply-doc-pipeline.py
The source scripts/tu1nz_doc_pipeline_transaction.py is identical and pins both
candidate source hashes. It verifies original files, service inactivity, active
timer, clean Docs Git and matching remote before mutation. Creates a fresh
UTC docs-transaction-* directory with full file bytes, uid/gid/mode/SHA256 and
engine absence marker. Files0600, directory0700. Tests an offline copy round-trip.
Writes engine first, safe wrappers next, path correction last; then daemon-reload
and systemctl start of the safe no-push service. Requires exit0, Result=success,
correct effective path, and unchanged Docs local/remote HEAD and worktree.
It waits up to1800seconds for VALIDATED.json after agent-side PDF review and
explicit publication verification. Error, signal, ROLLBACK marker or timeout
restores only these files and original owner/mode, reloads systemd, rechecks hashes
and original WorkingDirectory. Concurrent unexpected file edits stop restoration
rather than overwrite someone else's work. Abrupt SIGKILL/power loss needs manual
recovery; no in-process guard can cover that. The existing timer schedule stays.
Rollback restores configuration; historical systemd execution timestamps and a
reviewed published Git commit are not erased. Staged evidence remains protected.

Independent manual recovery, as root after stopping a still-running transaction:
python3 TRANSACTION_DIRECTORY/rollback.py --rollback TRANSACTION_DIRECTORY
The copied executable requires the captured manifest and original files; do not
restore unrelated directories or reset Git history. Keep the recovery console.

## Remaining live gates
Privileged activation requires the operator's private sudo entry. No live script,
unit, Docs commit/push or systemd change has yet occurred in this preparation.
After activation: inspect service result/journal, validate/review generated PDF,
confirm no auto-commit/push, invoke explicit reviewed publication as chatops,
verify local/remote commit and safe timer, then acknowledge transaction and
record results. Phase4 and Phase5 are still unactivated.
