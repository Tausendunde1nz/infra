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


## Live Docs pipeline completed — 2026-09-23T18:12:57Z
Preparation commit aa66bfc7f23ccc31e732d79988a9d79dc0bd306a was pushed before
activation. Privileged transaction docs-transaction-20260923T181203Z completed
with COMPLETE.json at18:12:57.570435Z. Fresh originals, metadata, executable
rollback, offline proof and validation acknowledgment are in the private base:
/opt/tu1nz_repos/network-hardening-private-2026-09-22/docs-transaction-20260923T181203Z/

Effective WorkingDirectory is /opt/tu1nz_repos/docs, user/group chatops.
The safe systemd run at18:12:05-18:12:06Z exited0 with Result=success and staged
one valid PDF. Docs local and remote HEAD remained4644acf and worktree remained
clean before explicit publication: no automatic commit or push occurred.
All PDF checks passed again, extracted content matched the strict allowlist,
and the actual live page was rendered and visually inspected without clipping.
Stage: /opt/tu1nz_repos/doc-staging/stage-20260923T181205Z-juhvnebs/
PDF SHA256:34248f56c3f67fbe1a665f21fdee7f6ca0baf8de2bd8eca9a08a5f17323f7fd2.
Only after this review was explicit publish invoked as chatops with that hash.
Docs commit537aa8fd69d755c641246cc1b507c69b3e1cd5f5 contains only
System_Dokumentation_Tausendunde1nz_2026-09-23.pdf. Push to Docs main and exact
remote HEAD verified; worktree clean. Timer remains active, next run22:00UTC,
and now performs staging only. The in-process rollback wait has completed.
For later configuration rollback use the captured rollback.py --rollback with
its transaction directory, after checking drift; this does not erase published
Git history or rewrite historical systemd timestamps.

## Phase4 resumed: no activation yet
Fresh provider read still shows original TCP80-8080, TCP22, TCP443 and ICMP,
attached to the same server. No provider mutation occurred.
External Mac preflight: n8n.mychatbuddy.dev and lighting.tu1nz.com DNS both resolve
to91.98.112.14; HTTP301 redirects to corresponding HTTPS; HTTPS200 with normal
certificate validation. These external tests are authorized by the latest order.
Backup latest run completed03:34:56UTC with Result=success. The doc service is
no longer in systemctl --failed; protected pre-existing private-alpha failure
and spicymila_bot unhealthy state remain, untouched. No bot message was sent.
One enabled nginx config (tu1nz.conf) is not readable as chatops, so the complete
current routing inventory still needs a privileged read. Do not claim it passed.
control-main remote is now7c634d3b82572e8459d51c69f04dce82c624d766; upstream
integration/dependency review remains outstanding. Canonical checkout untouched.
The previously opened recovery tab was absent; reopening its known console URL
succeeded, but Chrome then blocked automation because another extension UI was
open. Recovery login/session could not be freshly verified. Provider activation
is gated on restoring that independent recovery access and remaining preflight.
Phase5 remains unactivated. No additional security change or merge performed.
