# backup_notify reader v2: protected result and migration hold

Base: `84a18e9c2af763fd34a574d07e588cb231cc1a25`. No activation, service restart, new privileged run, watchdog or PR.

## Immutable evidence

Private result: `/Users/daniel/.codex/tu1nz-recovery/backup-notify-v2-20260927/result-20260927T180444Z-471acea8/result.json`
SHA-256: `43ab895c8dad9d39793bf79b0d7c99c622142a3434463443bd14ef3bf7466062`. The private JSON is not committed.
Reader SHA-256: `7342e55dcfe6c8628477570fd433ad60d66ba345fcfaf29e1a6376e033a4e3d2`.
Archived script SHA-256: `878fdc573fe13393656b73d2d0d9f38e93477af3b8e3094f03ac375c0defa311`.
SSH return code 0; collection `COLLECTED`; security classification `REVIEW_REQUIRED`; activation_ready false.
The v2 reader, manifest, sources, launcher and result are not rewritten. V7 evidence is also unchanged.

## Proven findings

Both full-script syntax procedures accepted the source (86 AST nodes). The old physical-line lexer failures reproduced at 22, 23 and 29. Line 22 reports LINE_CONTINUATION; line 29 MULTILINE_DOUBLE_QUOTE. Redaction did not precede the failing old lexer.
Runtime nevertheless returned INCOMPLETE_ERROR_SITE_COVERAGE because line 22 had no AST node covering its column-zero offset. The engine tests `start <= line_start < end`; it does not test overlap with non-whitespace syntax on that line. An isolated fixture with an indented continued command reproduces precisely this empty offset coverage while both parsers accept it. This proves a defect in the reporting criterion, not the exact indentation of the protected source, whose bytes are intentionally unavailable locally. The immutable production result is not relabeled PARSED_COMPLETE.

ENV_PARSED_AS_DATA is proven. MULTIPLE_STATIC_ASSIGNMENTS and UNKNOWN_COMMAND_EFFECTS remain unresolved. `validation_proved` and `semantics_complete` are false. No conclusion that all values are safely bounded, that shell evaluation is absent in dependencies, or that root execution is harmless follows from the syntax pass. Empty tainted-argument lists are not proof of safety with unresolved effects.

The fixed archive scan checked 3027 sources / 4281807 bytes and found zero literal hits. No active root caller was established. Coverage remains explicitly open: dynamically assembled program names and indirect execution are not excluded. NO_ACTIVE_CALLER would therefore be unsupported. No fresh broad inventory was performed.

## Concrete evidence boundary

The redacted output omits the assignment identities, command targets and execution-chain semantics necessary to close the remaining dataflow and caller graph. Those facts cannot be reconstructed offline from hashes, counts and AST category summaries. Offline fixtures cannot substitute for the missing protected-source evidence. There is no justified decision yet between unreachable historical code and an active root-influenced path. Consequently no blocker is removed and no replacement or migration is claimed ready.

Any future targeted investigation must first correct line-range coverage without weakening whole-source coverage, export only bounded semantic proof sufficient for assignment flow and exact fixed dependencies, and resolve dynamic edges within the existing candidate set. This document does not authorize another privileged run or activation. No new launcher is prepared by this follow-up.

## Offline regressions

Added five tests: indented continuation reproduction; no-literal-hit cannot prove no caller; syntax success cannot prove semantic safety; data reading cannot prove validation; incomplete coverage cannot authorize classification. Historical tests and artifacts are retained.

Rollback: additive repository evidence/tests only; revert this follow-up commit if needed. No live rollback is necessary because no live state was changed. Private result remains retained independently.

## Verification outcome

Full privileged-ops offline suite: 392 tests passed on server Python 3.12 (4.851 seconds). All 42 baseline Hardening files and all 1125 V3 evidence files match their recorded SHA-256 values. All previously tracked files were unchanged before adding this report and its five regressions. Detached checkout remains clean at `7c634d3b82572e8459d51c69f04dce82c624d766`. No live mutation command was issued in this follow-up; this is not a claim that unrelated services cannot change independently.
