# V3 offline validation

All 438 privileged-ops tests passed: historical 392 plus 46 V3 tests. Python 3.12 on the server; no sudo. Includes real sealed-memfd import in an independent Python process. All 42 baseline Hardening files and all 1125 historical V3 evidence files match recorded SHA-256 values. Historical tracked files, V1/V2 readers, manifests and diagnostics remain unchanged. No privileged V3 run or live activation has occurred.

The daily-cron hook regression distinguishes executable shell hooks from /etc/cron.d crontab grammar. All new code has mode0644 in Git; there is no executable activation launcher. The sole reader launcher is explicitly invoked with Python and pins exact reader bytes.
