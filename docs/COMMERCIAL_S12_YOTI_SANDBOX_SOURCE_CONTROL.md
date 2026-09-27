# Commercial S12 Yoti Sandbox source Control SSOT

## Decision

The Application source is ready for a future, separately authorized Yoti
Sandbox runtime. This Control contract does not install, deploy, start, enable
or network-enable S12. The active S11 runtime is not modified.

```text
S12_SOURCE_READINESS=S12_SANDBOX_SOURCE_GREEN
YOTI_PROVIDER_READINESS=YOTI_SANDBOX_CREDENTIALS_ABSENT
NEXT_S12_SANDBOX_RUNTIME_READY=true
S12_RUNTIME_EXTERNAL_BLOCKER=YOTI_SANDBOX_CREDENTIALS_REQUIRED
```

The first boolean means that the reviewed source is technically ready for a
future Sandbox authorization. It does not mean credentials exist or runtime is
authorized.

## Exact Application binding

```text
application_commit=41340900abdff09a03891761ac114646958eff9a
application_tree=b7285dca2218d7249769f5369a53ff8d7e5d6f14
```

The Application release contains the provider-neutral AVS domain, exact-host
Yoti Sandbox adapter, authenticated result-fetch contract, replay/expiry/retry
guards, minimal audit model, synthetic downstream WMS workflow, A-M simulator,
tests, threat model and product-boundary documentation.

## Runtime and secrets

The committed Control manifest records:

- environment `SANDBOX`;
- provider `YOTI`;
- only `AGE_ESTIMATION`, threshold 18;
- authenticated result fetch as the decision authority;
- Sandbox SDK ID and private-key **references**, never values;
- credentials absent;
- networking, installation, start and deployment false;
- `YOTI_SANDBOX_ENABLED=false`;
- all real AVS, Adult media, publishing, payment, beta and production flags
  false.

No systemd unit or runtime activation artifact is added by S12.0. A future
runtime package needs its own authorization, backup, exact release-bound
activation contract, provider credential provisioning and health acceptance.

## Sandbox-only freeze

After the Control PR is merged, create a new annotated tag named
`s12-yoti-sandbox-source-freeze-r1`. The tag targets the exact final Control
merge commit and binds:

- exact Application commit/tree;
- exact Control commit/tree;
- SHA-256 of all S12 Application source, simulator, tests and SSOT documents;
- SHA-256 of the Control manifest, freeze tool, test and this SSOT document;
- canonical Sandbox-only flags and readiness classifications.

The verifier requires an annotated tag, every canonical key exactly once,
zero aliases, zero unknown values and exact artifact hashes read from the bound
commits. It does not repurpose or mutate the S11 freeze.

## Rollback

Before merge, rollback is normal Git reversal of the source branches. After
merge, rollback is a new reviewed revert; immutable tags are never rewritten.
There is no runtime rollback because S12.0 performs no runtime mutation.

## Operator handoff

After Yoti organisation approval, create/select an Age Verification Sandbox
service in Yoti Hub, provision the Sandbox SDK ID and matching private key into
the approved private paths, and report only completion. Never paste values into
chat, Git, commands, logs or evidence. Do not create Production credentials or
use a real person, document, selfie or biometric.

Real AVS, Adult media, external publishing, payment, Controlled Beta and
production remain closed and require independent authorization and final legal,
privacy and youth-protection review.
