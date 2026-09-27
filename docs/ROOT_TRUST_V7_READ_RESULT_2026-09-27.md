# V7 targeted archive read — verified collection, incomplete semantics

Base commit: fdeabb42b436ccfdf53918c6cd6cab46d483dc96.
Daniel confirmed readiness and entered the password directly in Terminal.
Exactly the authorized pinned reader ran through the prepared launcher.
No further sudo command, live configuration change, service/container restart,
watchdog or activation followed.

## Verified evidence

Private redacted result:
`/Users/daniel/.codex/tu1nz-recovery/root-trust-v7-20260927/result-20260927T173740Z-b4215a6d/result.json`

Result SHA-256:
`501fbb7fb0944439b9e86df60f8644a5ebf3e65f47d437764f3f0a286df93271`

Reader SHA-256:
`3b9e28472b66c6c17c438a8075fe29eca2d86c835fae76a3dc7f369ece3dd64b`

The archive source matched
`878fdc573fe13393656b73d2d0d9f38e93477af3b8e3094f03ac375c0defa311`:
948 bytes, 31 lines. SSH/reader exit was zero. No .env was opened; no archived
code was executed. Raw source stays in the root-private archive.

## Actual interpretation and limitation

V7's line-by-line lexer reports parse errors on lines 22, 23 and 29,
command substitution, compound syntax, unknown command positions and an .env
reference needing dataflow review. Multiline syntax is a hypothesis for the
lexer errors, not proof of a defective shell script. No source/eval hit is
NOT a proof of safe parsing while those constructs remain unresolved.
The sampler's active_caller_proved=false likewise means absence of proof,
not a finding that the file is historical or unreachable.

A command/path fingerprint at lines 2 and 31 matches the already inventoried
`/usr/local/bin/tu1nz_lock.sh`. This match was obtained only by comparing known
V5.1 graph paths, not by guessing secret values. Its current unprivileged read
confirms root-owned 0755, 1829 bytes, SHA-256
`4ae8336db8c2eb202e5662f53221a5fc083c196a86ea3117d69aab5c8c09c16c`.
It does not prove an active caller for backup_notify. V5.1 still has no direct
incoming literal call edge. Dynamic callers remain unresolved.

The reader was too limited to answer the requested full semantic question in
one pass. This is a limitation of the preparation, not a new security finding
or grounds to weaken the migration gate. The original reader, launcher and
result remain unchanged. No second privileged read is implicitly authorized
by a cached sudo credential and none was attempted.

## Consequence

The migration remains NO-GO: whether this archived .env reference reaches shell
execution or privileged arguments, and whether an active root caller reaches
it, cannot be determined from the redacted output. A complete installer cannot
be called ready on this evidence. No additional broad inventory is indicated.
A future narrow continuation needs a parser/redaction strategy that preserves
multiline syntax and dataflow without exposing values, and an independently
proved caller chain. That continuation has not been run or represented as ready.

The result-review helper and five regression tests enforce that collection
success, missing positive flags and lexical parse failure cannot become SAFE.

Validation: all 282 preparation tests passed. The 42 hardening hashes and
1,125 V3 evidence hashes are unchanged; historical tracked files are unchanged.
