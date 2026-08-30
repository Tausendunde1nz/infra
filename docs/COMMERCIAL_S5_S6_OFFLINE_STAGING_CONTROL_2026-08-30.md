# Commercial S5/S6 offline staging control

## Outcome and release binding

Commercial S5 engineering and Commercial S6 payment-readiness engineering are complete in application merge commit `99a179990ae67aeab420eccef984915ae2aebfbd` with tree `ecd67fa84fbd1248dd2b7b29a6cafba7bdc0d527`. The database target is `0020_commercial_s6_payment_readiness`; the complete reversible migration-chain digest is `84fe9df14d3e37b45fde96bf541f8cdcc7cb8947a0ed3765699abdf4bdb2cf5b`.

The server transaction authorized here is installation-only and network-free with respect to Yoti, Segpay and all publishers. It permits a clean application fast-forward, hash-locked dependency installation, migration 0020 and installation of two disabled provider contracts. It does not authorize a service start, a systemd change, Telegram intake, adult media, real identity data, payment instruments, external publishing or production.

## Provider decisions

Yoti engineering is `GO`. The real Yoti sandbox remains `WAITING_EXTERNAL_ORGANISATION_VERIFICATION` because the provider organisation is `INCOMPLETE`; this is not retried or bypassed. Yoti production remains `NO_GO` pending organisation verification, adult-use approval, contract, pricing, DPA/DPIA, data-location and retention review, KJM/UK age-assurance review, and production credentials.

Segpay engineering is `GO`. The adapter, hosted signed-request model, protected TU1NZ callback ingress, normalized postbacks, replay/idempotency controls, simulator, PostgreSQL event/grant/reversal records, credit-ledger effects and creator-safe UX are complete offline. A first Segpay demo or sandbox call remains `WAITING_HUMAN_PROVIDER_GATE`; real money and production remain `NO_GO` pending merchant onboarding, underwriting, contract, credentials, pricing/reserve/settlement confirmation and explicit first-call authorization.

The commercial model is a publishing/distribution service. Initial beta payment should be a one-time purchase. Internal credits are non-transferable, non-withdrawable service-use rights and are not represented as currency or stored value. Merchant/legal confirmation remains mandatory before a real offer is activated. The TU1NZ credit ledger, not Segpay, remains the entitlement SSOT.

## Risk, backup and rollback

The service must be `inactive/dead/static`, `Restart=no`, `MainPID=0`, `NRestarts=0`, and no candidate process may exist. Application and Control worktrees must be clean. A fresh root-owned recovery point below `/opt/tu1nz_repos/backups/commercial-s4-extended-staging/` must be created and strictly verified before the application, virtual environment, database or `/etc/tu1nz` changes.

The principal reversible deltas are: application fast-forward from `a745540b81a368b2e5f09d1fcdb49342b686ae0e`; package installation from `requirements-s5.lock`; migration 0020; and two inactive `0600 root:root` configuration copies. Failure leaves the service stopped. Rollback requires a separate decision: verify the bound recovery point, prove all three S6 provider tables and provider ledger entries remain empty, apply the versioned 0020 down migration, restore the recorded application/control Git refs, virtual environment/configuration/database as required, and re-run the prior stopped-state checks. Rollback never starts or enables the service.

## Execution sequence

1. Revalidate Tailscale identity, server hostname, paths, owners, permissions, active services/timers/containers/open handles, disk/memory, Git state and the stopped service.
2. Synchronize the newly merged Control release only after recording its exact SHA/tree.
3. Create and strictly verify a fresh recovery point with the existing versioned S4 backup controller.
4. Run `tu1nz_adult_commercial_s5_s6_offline_stage.sh preflight` with exact Control SHA/tree and recovery path.
5. Run its `stage` action once. It may fast-forward only to the bound application SHA, install only the hash-locked S5 dependencies, install migration 0020 only from the bound file, and copy only the two disabled contracts.
6. Run `verify`. Expected AVS health is `AVS_CONFIG=GREEN`, `AVS_ADAPTER=GREEN`, `AVS_NETWORK=DISABLED_EXPECTED`, `AVS_AUTH=DISABLED_EXPECTED`. Payment config/network remain `DISABLED_EXPECTED` because the Segpay contract is inactive.
7. Confirm the service never started, no provider was contacted and no provider/payment/media rows exist.

## Stop gate

After offline staging, stop at the next true human provider gate. Do not enter or install Yoti/Segpay credentials, do not retry Yoti OAuth while the organisation remains incomplete, do not create a Segpay merchant account or accept a contract, and do not perform a first real provider call without a new explicit authorization.
