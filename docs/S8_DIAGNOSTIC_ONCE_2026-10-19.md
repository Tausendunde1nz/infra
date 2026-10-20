# PR236: one synthetic S8 measurement

Baseline: `d72cbff7708f8faa4635679b9813f73700cb6abe`; previous failing run
`39276355222`, restore job `118180907356`. No production guard is modified.

## Trigger planned before push

One reviewed commit with subject
`S8: one synthetic measurement s8-measure-20261019-1` is pushed once to
`codex/b-precopy-once-r1`. Only its push changing `tests/s8_diagnostic_once.py`
selects the new public/synthetic workflow. Run attempts other than 1 are refused.
No manual rerun, intermediate push or follow-up repair push is authorized.
The original PR workflow also triggers normally and remains mandatory; its
private Environment job is not approved by this diagnostic task. No old
Environment rule is repurposed or modified. No merge/freeze is permitted.

## Measurement boundary

Same `ubuntu-24.04` runner label, existing pinned native Dockerfile, default
Docker storage, privileged isolated PID1, network none, read-only source mount
and private cgroup/run/tmp mounts as `tests/s8_anchor_native.sh`. The hosted
runner image/provisioner cannot be guaranteed equal to the failed historical
run; Setup-job metadata and actual kernel/storage/image IDs must accompany
the result. No new runner, rights, Environment, private token, artifact or input.
Container startup is bounded by the existing readiness check; the one five-case
sequence has a 90-second deadline, 10-second kill grace, whole job 10 minutes.
Only this job's disposable container is stopped/removed by its existing-style
cleanup. No sourcehost or pre-existing data is touched.

The fixed sequence covers NewStock, ProtectedJournal record seal, raw inode
flag assumption, fenced immutable handoff, and controlled foreign chmod/restore.
It does not retry cases. Original unittest failures and skips remain a failed
measurement job; this is not a substitute for mandatory restore acceptance.

Test-only wrappers delegate each original read/ioctl/fsync/check/close exactly
once, preserving bytes/results/exceptions. No additional event read, peek, drain,
event allowlist or guard-policy change. Reads report mask/name/cookie/watch root;
flag ioctls report bound fd dev/inode/mode and operation timing. Guard reads are
labelled at their existing check boundaries, and stale fd labels are removed.
Inotify has no event actor: observer caller PID/TID must not be represented as
event origin. Only the separately controlled foreign child's actual chmod
action is attributed. No table/process environment/content/credential capture.

Extra clock/fstat/readlink/stdout operations and wrappers perturb timing and
thread scheduling; a reproduced mechanism cannot establish historical causality.
No replica profile guarantee and no inference from one green measurement alone.

## Fixture delta and retained checks

Affected Anchor/NewStock fork children catch every unexpected BaseException
and `_exit(99)`; accidental return is `_exit(98)`. Intentional `_exit(0/3/77)`
is unchanged. Parent expected-exit, readiness, no-adoption and result assertions
are retained. Anchor phase fixtures reset their own disposable objects in a
finally block, so one failed child does not manufacture stale-root failures in
later phases. Unexpected child failure never continues the inherited suite.
Independent review and targeted exception/fallthrough/intentional-exit and
observer byte/exception preservation tests are required before commit/push.

## Stop condition

Report masks/objects/operation ordering and actual runner/image/provisioner,
distinguish observation from event attribution and historical CI causality.
No automatic production guard fix, event exception, repeated diagnostic run,
new infrastructure, private CI approval, merge, freeze or export follows.
