# Commercial S10.2D-R7 aggregate recovery

Status: `P0_SOURCE_PUBLIC_RECOVERY_GREEN`

## Objective and boundary

Restore the already selected safe source application and its public SFW
endpoints after the versioned R7 rollback stopped at public startup. This is a
one-time state-shape recovery, not a second Community cutover and not a source
feature change. It performs no database, Telegram profile, Community, Adult,
AVS, payment, publishing, acquisition or production mutation.

## Root cause

The target application validly added `COMMUNITY_CTA` to the shared, anonymous
landing aggregate. The source application accepts only `LANDING_VIEW` and
`TELEGRAM_CTA`. R7 restored the source Git/configuration/systemd surface but its
backup set did not include this aggregate file. The source services therefore
failed closed when they read the forward-shaped file.

## Backup-first recovery

The recovery requires the exact clean source Application commit/tree and the
exact clean, post-merge Control commit/tree. It also verifies the hash-bound
source configuration and systemd surface, requires all aggregate writers to be
stopped, and rejects unknown events, duplicate JSON keys, unsafe metadata or an
unexpected path.

Before replacing anything it creates a root-only recovery directory and saves:

1. the exact original aggregate bytes;
2. the source-compatible `LANDING_VIEW` and `TELEGRAM_CTA` view;
3. the isolated forward-only `COMMUNITY_CTA` view;
4. hashes, ownership/mode and count-conservation evidence without dimensions,
   content, messages, media or identifiers.

The server backup parent is intentionally setgid. Linux can therefore create a
new child directory as mode `2700` even when `0700` was requested. The recovery
accepts only that exact inherited-bit case on an already root-owned directory,
removes the setgid bit to obtain `0700`, persists the directory entry, and
rejects every other ownership or mode deviation.

Some successful inactive one-shot health units are not retained in systemd's
loaded-unit set. Calling `reset-failed` for such a unit returns an error even
though no failure exists. The recovery therefore issues `reset-failed` only
when `ActiveState=failed`; inactive or active healthy units proceed directly
to the already required start and result verification.

The Telegram poller may need one bounded long-poll cycle before it writes its
fresh runtime heartbeat. Health one-shots are therefore started on the fixed
schedule `0, 5, 15, 30` seconds (50 seconds total at most), stopping at the
first success. The poller remains running between attempts; the full final
health, service, timer and public verification remains mandatory.

Every file and parent-directory entry is durably synchronized before the live
file can change. The script then stops the affected timers, workers and public
services, confirms that the original aggregate hash did not race after backup,
and replaces the shared file atomically with its original owner, group and
mode. Forward-only aggregates are not deleted; they remain in the protected
backup beside the exact original bytes. If startup or verification fails, the
script stops all affected timers, workers and writers, restores the exact
original bytes atomically and remains fail-closed.

## Success gate

Success requires source Application and Control to remain exact and clean,
the recovered baseline hash to match its backup, the live aggregate to contain
only source-supported events without count regression, all S7/S8/S10/nginx
services active with zero restarts, every S9/S10 timer enabled with a future
run, the S8/S9/S10 health guards successful, internal and public health
`ok=true` with the exact SFW brand/mode, public SFW pages HTTP 200, the German
domain HTTP 308, and all Adult/AVS/payment/publishing/beta/production boundaries
closed.

No follow-on infrastructure sprint or cutover is authorized by this recovery.

## Executed result

The final version-bound recovery completed GREEN on 2026-09-08 using Control
commit `75afbf4586461bcce72b7d123910cfdf8e0f641b`, tree
`67c55421b6e67f0ac2d890018a0ee4bdeb51c53a`, and post-merge CI
`34247579828`. Its root-only evidence is stored under recovery identifier
`20260908T155418Z`.

The live source-compatible view retained 37 entries with aggregate total 6732.
The single forward-only entry with total 1 remains separately preserved beside
the exact original bytes; all three views are SHA-256 bound. Two preceding
fail-closed runtime attempts preserved their separate evidence and restored the
original hash and metadata before the final execution.

Independent verification found the source Application and final Control exact
and clean, S7/S8 Landing/S8 Telegram/S10 WMS/nginx active with zero restarts,
all S9/S10 timers enabled, active, waiting and future-scheduled, all S8/S9/S10
health guards successful, all required public pages HTTP 200, the German domain
HTTP 308, and public health GREEN with every forbidden product boundary closed.
