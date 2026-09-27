# backup_notify reader v2 (2.0.0) — preparation only

Base: `1c1bc5fbbdd85b12c54261f4f304a23d192c0785`.
V7, its generated launcher, result and diagnosis remain byte-identical.
No sudo read, service action, live migration, watchdog or PR is performed here.

## What is known and what cannot yet be claimed

The original script is 948 bytes/31 lines and remains protected. Its SHA-256 is
`878fdc573fe13393656b73d2d0d9f38e93477af3b8e3094f03ac375c0defa311`.
V7's shlex invocation processed each physical line independently, before output
redaction. It reported ValueError at lines 22, 23 and 29. Those errors cannot be
attributed to redaction preceding parsing: redaction happened afterward.
The V7 output does not preserve enough structure to identify the original three
constructs offline. Fixtures reproduce candidate syntax classes, not claimed
copies of unknown production syntax. No original source lines or values are used.

V2 parses the complete source and, inside the protected read, repeats V7's exact
line-lexer operation only at those three positions. It records lexical failure,
covering AST node kinds and bounded syntax categories (multiline quote, heredoc,
continuation, substitutions, function/compound), never source fragments. It cannot
report target PARSED_COMPLETE unless both full parsers agree, the AST covers all
code, all three positions have AST coverage and the old errors reproduce.

## Independent syntax paths

1. Fixed `/usr/bin/bash --noprofile --norc -n -s`, source on stdin, sanitized
   environment with no BASH_ENV, no sourced startup file, cwd `/`, five-second
   timeout. stdout/stderr remain in memory and are never exported. No command or
   substitution in the target is executed. Binary SHA-256 is pinned:
   `bc5945feb8bd26203ebfafea5ce1878bb2e32cb8fb50ab7ae395cfb1e1aaaef1`.
   Server version: GNU Bash 5.2.21(1)-release x86_64-pc-linux-gnu.
2. Vendored bashlex 0.18, upstream commit
   `ae1e11a8227d7ca8531b94c7fe821b83bd714ca5`:
   https://github.com/idank/bashlex/tree/0.18
   It has an independent Python tokenizer/parser and AST, rather than V7's shlex.
   Its documented grammar limitations are not hidden: arrays, `[[ ]]`, arithmetic
   and unsupported/complex parameter expansions refuse completion. A successful
   Bash parse cannot override missing structural support.

The vendor patches disable table writing explicitly and replace evaluation
of fixed grammar literals with ast.literal_eval. No script text reaches that
literal evaluator. License and source remain present (GPLv3+); exact file hashes
are in PARSER_MANIFEST.json. The optional tag `v0.18` did not exist; discovery of
actual upstream tags preceded the successful clone of tag `0.18`. No system
package, pip dependency or parser service was installed.

The generated reader contains a deterministic ZIP of the pinned parser, engine,
runtime and fixed caller bindings. Linux loads it from a sealed anonymous memfd,
not from a writable repository import path. The ZIP hash is checked before import;
bytecode and parser-table writes are disabled. The generated source is checked
against the build in tests. A real Linux unprivileged fixture validates sealed
memory loading, independently of the direct filesystem-vendor tests.

## Semantic scope and conservative output

Assignments, command substitutions and parameters are followed to a conservative
fixed point. Simple static path assignments can resolve the literal .env target.
Shell sourcing/eval/shell-command taint is separated from data-reader output,
quoted argument flow, unquoted argument-boundary flow and dynamic commands.
Aliases, indirect/complex expansion, embedded languages, unknown command effects,
URL/options and unproved validation stay review-required. ENV_PARSED_AS_DATA alone
is not a claim that its values, keys, destinations or argument semantics are safe.
No variable names, literals, URLs, messages or AST word values are emitted.

PARSED_COMPLETE concerns syntax/coverage only. It does not imply semantic closure
or activation readiness. ACTIVE_SAFE_DATA_PARSER requires independently proved
validation and a closed active caller contract; V2 never invents that proof.

## Fixed caller set, no broad live inventory

CALLER_BINDINGS.json derives 3,027 root-owned source blobs from the already
collected V5.1 systemd, cron, local-program, boot, network, additional and package
hook categories. These are fixed archive records with exact file and source hash,
not a traversal of the current filesystem. No .env record is included. Only
records containing the exact basename `backup_notify.sh` are parsed as possible
callers; a comment or echo argument is not an execution edge.

Cron schedule/user fields and systemd Exec fields are handled as distinct outer
grammars, not passed wholesale to a Bash parser. Source/exec/wrapper/path-dependent
calls are distinguished. For a concrete hit only, its already bound live path is
checked against the archive hash. Fixed `systemctl show` queries can provide
fresh User/ActiveState/UnitFileState/DropInPaths for cron or the relevant service.
The systemctl binary is pinned to
`92066bd4ffe127635ea06eed35d03b0e2bfd1c3aa51ee9ee4470aa8259de576e`.
No program or action from the inspected script can become a subprocess command.

Unknown drop-ins, wrappers, script-to-script activation and dynamic-name absence
remain open. In particular no incoming literal match is not NO_ACTIVE_CALLER.
The narrow archive scan cannot itself prove absence of every dynamically assembled
caller. The final category stays REVIEW_REQUIRED until those reachable contracts
are joined from existing evidence. That limitation must not be converted into a
claim that a historical script is active, or that all 13,296 literals are blockers.
The reader can positively classify a proven active root shell/argument path;
other categories require their explicit evidence predicates.

## Read boundaries and launcher

The fixed target and each archived candidate require safe root-owned ancestors,
regular single-link files, private modes, no unexpected ACL, matching SHA-256 and
stable descriptor metadata. Live caller reads are restricted to exact bound hits.
Source and caller hash changes fail closed. Limits: two MB per archive source,
64 MB total caller source, 45 CPU seconds, 60 elapsed seconds and 512 MB memory.
Partial results survive as a redacted INCOMPLETE record; raw diagnostics do not.
No root filesystem output directory is created; only anonymous memory is written.

The local launcher verifies generated-reader bytes. The remote unprivileged
bootstrap reads the corresponding committed file and verifies the same hash,
then pipes those exact bytes to one `sudo /usr/bin/python3 -I -S -c` bootstrap, which
verifies them again before compile. This avoids an oversized command-line payload
and avoids executing a mutable root import. Sudo reads a password from the terminal;
no credential is supplied as an argument, environment value or logged input.
The local launcher stores only prefixed redacted JSON under a fresh 0700 result
directory, file 0600. It has not been executed during preparation.

## Tests and remaining gate

Fixtures cover multiline single/double quotes, continuations, old error-site
coverage, heredocs, subshells, functions, process substitution, source/dot, eval,
bash/sh -c, taint, unquoted expansions, data reads, incomplete ASTs, parser disagreement,
unsupported arrays/[[ ]]/indirect expansion, active/inactive/text-only callers,
caller/source drift, links, owners, redaction and nonexecution canaries. Upstream
parser/tokenizer tests are retained unchanged. A local harness initially used the
Linux Bash path on macOS; fixtures now explicitly select `/bin/bash` only on macOS.
The production reader remains pinned to the Linux binary. A stale generated bundle
was correctly rejected after source edits and was rebuilt, not exempted from tests.

The privileged read is the next separate gate. No claim is made that the three
unknown original forms or the current caller category have already been decided.
After the read, source semantics and fresh caller facts must be evaluated before
any migration readiness declaration. Live activation remains separately prohibited.

## Final preparation verification

All **387 tests passed** under server Python 3.12.3 in the final combined run: all previous 282, 48 new tests, and 57 unchanged upstream tests. No skipped test. Root execution was not used. All 42 hardening hashes and 1,125 V3 evidence hashes remain unchanged, as do all historical tracked files. Parser, reader, launcher and bundle bindings match READER_V2_MANIFEST.json. No privileged reader run has occurred.

The sole later terminal command is:

```sh
python3 /Users/daniel/.codex/tu1nz-recovery/backup-notify-v2-20260927/tu1nz_backup_notify_launcher_v2.py
```

This is one sudo read-only diagnostic call, not an activation. The `-S` root bootstrap additionally suppresses global site startup hooks.

The staged diff check additionally found six pre-existing trailing-whitespace lines in the vendored parser. They were normalized in the new vendor copy, recorded in its manifest, and the reader/launcher were rebuilt and re-pinned. No historical project or upstream checkout file was altered. The complete suite is repeated for the final bytes before commit.
