# M4.26 — First-Start Contract Refresh / Read-only Preflight

Date: 2026-08-28

Decision: **read-only technical preflight complete; NO-GO for first start**

## Authorized scope

M4.26 begins only after PR #33 and PR #34 were merged by merge commit into
`control-main`. It refreshes the historical M4.24 contract against the stopped
M4.25 unit, binds every relevant release and recovery hash, and records a full
Tailscale-only read-only first-start preflight. It does not modify the server.

The following remain prohibited: starting, restarting or enabling the
commercial unit; daemon reload; provider or Telegram activation; real tokens,
media or payments; X, Reddit or Telegram publication; deployment or production
activation.

## Merge and release binding

PR #34 was revalidated before merge with exactly its reviewed 12-file diff,
mergeable state `CLEAN`, and successful retargeted CI run `33201839238`. It was
merged by merge commit
`132d971dca214dcfa1cf2e3d48fbec172751e937`, whose first parent is the PR #33
merge boundary and whose second parent is the exact PR #34 head. Post-merge CI
run `33202557484` completed successfully.

The resulting base tree is
`c50ce73098d344763fd29f12ba077fb24139b38c`. The installed immutable Control
release deliberately remains
`3135197ba4ac577bbb7fd28341d0c2dc845a7ebe`; the application remains
`52494d6121660ead53774deb8616701f14bb7a8f`. This difference is not drift:
`control-main` is the documentation and control SSOT, while `control-current`
is the separately installed, stopped release bound by its manifest.

## Read-only server preflight

The server was reached only through Tailscale at `100.121.130.51`. At
`2026-08-28T19:13:59Z` the following complete boundary was observed without a
write or service action:

- canonical `control-main`, cached `origin/control-main`, SHA and tree all
  matched the PR #34 merge; tracked status was clean;
- the 23 ignored legacy/generated entries described by the repository
  allowlist were sorted and bound by SHA-256
  `b23591e86c2b43fbc11a376eb3d0a68c19e3979b1538aa4ac50711b598300e89`;
- application and active Control releases were clean and the active release
  gate returned `COMMERCIAL_S0_RELEASE_GATE_OK`;
- installed unit and release manifest hashes were exact;
- the candidate was loaded, inactive, dead and static with `Restart=no`, an
  exact 180-second runtime maximum, zero restarts, zero PID, zero timestamps,
  zero journal lines, no trigger, no runtime status and no runtime lock;
- native unit verification passed and the offline exposure remained
  `0.6 SAFE`;
- PostgreSQL, persistent S1 and the encrypted-backup timer were active; the
  backup service was inactive; the only failed unit remained the previously
  accepted unrelated `tu1nz-doc.service`;
- no commercial timer, process, runtime-user process, cron reference, Docker
  mount or open file was present;
- no sensitive manager or unit environment variable name was present;
- the database remained 39 tables, 21 TU1NZ functions, zero other sessions,
  exact synthetic seed counts and zero business rows; the state file remained
  empty and byte-bound;
- the fresh encrypted archive remained exactly 64,488,092 bytes with SHA-256
  `f892758dccf2157b4fa11afa38fe61dfcd36f18076230a76f1d23627bf18afc0`;
  the isolated restore and `restore-evidence.txt` hash matched M4.25;
- capacity exceeded the existing minimums. Swap remains absent.

The initial probe wrapper failed locally before SSH because shell text was
interpreted by the JavaScript wrapper. No remote command ran. A corrected first
probe then used two inaccurate unit names and an unavailable `rg` binary; its
ambiguous fields were discarded. The final probe used the versioned M4.24/M4.25
names and gates and produced the contract evidence above. The diagnosis records
this explicitly.

## Fail-closed interpretation

The technical read-only checks pass, but M4.26 is intentionally not an
authorization contract. It remains inactive and records five blockers:

1. first start has not been approved;
2. the no-swap risk has not been accepted for the first-start window;
3. the M4.26 artifacts are not yet merged into `control-main`;
4. they are not yet present in the server canonical checkout;
5. a fresh prestart revalidation is mandatory immediately before any future
   first start.

The exact legacy ignored-file baseline is accepted only because it is already
the documented repository design and is cryptographically bound. A new,
missing or reordered entry fails the M4.26 gate. Tracked dirt always remains a
failure.

## Separate approval point

M4.26 ends after local versioning, CI and Draft-PR review. A later explicit
authorization is required before Ready/Merge, server synchronization or any
new first-start authorization contract. Even after that, the actual first
start must be separately approved and preceded by a fresh full read-only
preflight. M4.26 itself can never be changed into a start authorization.
