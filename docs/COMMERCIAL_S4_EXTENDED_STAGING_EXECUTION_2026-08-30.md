# Commercial S4 extended-staging execution

## Outcome

Commercial S4 completed its bounded server-staging acceptance and is stopped. The final two-hour run produced 25 consecutive GREEN observations from `2026-08-29T20:53:23Z` through `2026-08-29T22:53:23Z`. The service was then stopped, the disabled staging contract and verify-only runtime authorization were restored, and the evidence set was strictly verified.

## Exact releases

- Application candidate: `ffce727d8e1e45c93323bd805e77e5965e8b3941`
- Application tree: `6492a0cc6efcfaca8d8c8fd19e38ccb770f9c85a`
- Canonical application merge after acceptance: `d544a190ffb86ab49fd47e01067ff3750055a0a0` (same tree)
- Control candidate used for the final run: `abc71b56a434075de9be952ec172453459fd51ce`
- Control tree: `633885c950cb10ee7f302c98e6c597ea06c79f0d`
- Database schema: `0018_commercial_s4_provider_beta_readiness`
- Migration chain: `2a7763b33834493ca612f06b9762a3b00fef9f6af042154bba7918f624c32dae`

## Recovery and evidence

- Pre-mutation recovery point: `/opt/tu1nz_repos/backups/commercial-s4-extended-staging/20260829T202700Z-pre-mutation`
- Recovery index digest: `34b9d5019db0ad48df8f73bddd77e079eb515659b9e2fabbd0c49ee7753361d7`
- Successful acceptance evidence: `/opt/tu1nz_repos/backups/commercial-s4-extended-staging/20260829T213000Z-s4-extended`
- Acceptance evidence index digest: `3548bc31f478aa7643f339954464814d551904857d408aa549e30bf3d6aa8569`

The earlier pre-readiness run is retained separately at `20260829T211000Z-s4-extended` with its own corrected evidence index. It demonstrated the fixed-sleep readiness race, not a Telegram poll failure. The final run used explicit phase-18 readiness.

## Stability measurements

- Samples: 25/25 GREEN at five-minute intervals
- Red samples: 0
- Yellow samples: 0
- Main PID changes: 0
- systemd restarts: 0
- RSS: 64,209.12 KiB average; 67,788 KiB peak
- File descriptors: 5 minimum and maximum
- CPU delta: 17,918,263,000 ns
- Database connections: maximum 1 observer connection
- Journal growth: 104 bytes
- State growth: 0 bytes
- Unexpected TCP destination class: 0
- S4 provider event rows: 0
- S4 beta metric rows: 0

The final database aggregate also contained zero Telegram polling rows and revisions; the runtime's protected local cursor remained present and safe. No media, identity/biometric material, payment data or provider receipt was created.

## Final stopped state

- `ActiveState=inactive`
- `SubState=dead`
- `MainPID=0`
- `NRestarts=0`
- `Restart=no`
- `UnitFileState=static`
- `RuntimeMaxUSec=6h`
- Disabled contract SHA-256: `41e5682934cc632b8d00cd0afd542cd823ef3c99f1c9b418efcb01ccd1ad2f23`
- Verify-only authorization SHA-256: `21916f05912789c19d43759cc0a9356ca5419d93fb2f260a6b37526ecd200a1f`

The authorization digest above is the value used during the candidate acceptance. After the byte-identical application merge, the canonical verify-only authorization is rebound to merge SHA `d544a190ffb86ab49fd47e01067ff3750055a0a0` with digest `ec04090243f63e53fa3e7aa58c8b956418e46f32f690a90b6a6abe7a93e00282`; it still authorizes no start or provider.

Post-acceptance verification found that migration 0018 had not granted the
dedicated runtime role access to the two empty S4 evidence tables. App merge
`a745540b81a368b2e5f09d1fcdb49342b686ae0e` adds reversible migration 0019,
updates the chain to `2feab99548eae5c2ae571ec45974cd196dfc3a3d4a316011ee3e4abbd3f83802`,
and includes both tables in the bounded prestart gate. This correction does not
change the historical acceptance measurements and authorizes no service start
or provider.

## Provider readiness decision

- AVS primary: Yoti; fallback: VerifyMy.
- Payment primary: Segpay; fallback: CCBill.
- Integration state: offline contracts and deterministic simulators only.
- Provider credentials: absent.
- Provider calls: zero.
- Real payment/money: zero.

## Mandatory external risk gate

This sprint stops before real provider credentials, a first real AVS/payment call, identity or biometric data, real money or payment instruments, Telegram Stars, adult media, external publishing, open registration, controlled beta or production. Each requires a new separate legal/security/provider authorization. Commercial S4 acceptance does not authorize any of them.
