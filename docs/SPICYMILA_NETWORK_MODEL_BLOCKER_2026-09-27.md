# Spicymila network-model investigation — 2026-09-27

Status: BLOCKED BEFORE ACTIVATION-PREPARATION COMPLETION. No production activation,
Compose edit, production container recreation, or network attachment change was performed.
The explicit stop condition applies: Compose 2.40.3 cannot reproduce the current empty
endpoint alias list exactly. The historical reason for this shared attachment also remains
unproven. This document does not authorize a substitute network model.

## Existing network and provenance

`tausendunde1nz_net` ID
`470c1e93874782eeea4d9060f0502efdc6911d7afd96171c147e13a7013cd646`
was created 2025-10-12T10:25:00.210828579Z. Local bridge, IPv4 enabled, IPv6 disabled;
default IPAM driver, subnet 172.25.0.0/16, gateway 172.25.0.1. Internal, attachable,
ingress and config-only are false; network options and labels are empty.

Its only attached containers are `spicymila_bot` (172.25.0.3/16) and
`telegram_bot_mommyramona` (172.25.0.2/16). Both also have their own Compose default
network. The spicymila primary is `spicymila_bot_default`, ID
`156b16ca93d6252a660969f3793c8625d3a13cd5e75cbab56a245762fd0ac1f8`,
IP 172.21.0.2/16 and gateway 172.21.0.1.

Git searches across all locally available refs of the two application repositories found
no historical declaration of this shared network. Spicymila Compose history starts with
f4a99b9 (2025-10-17 auto backup); the peer Compose history starts with 2e666e9
(2025-10-12 initial import). Searches of control history only found the recent recovery
documents. No matching shared-network/address/manual-connect reference was found in the
searched application files, canonical control tree, readable systemd units and nginx files.
This is bounded negative evidence, not proof of how or why the original connection was made.
No shell history or secret environment values were printed.

No peer-name/shared-address reference was found in either running main.py or relevant
container environment values. At the sampled instant their TCP tables showed the application
listeners and Docker DNS, with no established peer connection. This does not exclude past
or intermittent communication. Spicymila's default route uses 172.21.0.1; the peer's default
route uses 172.25.0.1. The shared network therefore currently supplies the peer's default
route. Its functional requirement specifically for spicymila is still unresolved.
No production packets, webhook calls, audit rules or new monitoring were introduced.

## Endpoint inventory

Full network/endpoint inventories are retained privately, including generated endpoint IDs.
The spicymila shared endpoint has IPAMConfig `{}`, Links null, Aliases `[]`, DriverOpts `{}`,
GwPriority 0, MAC `9a:0d:fe:75:58:8e`, gateway 172.25.0.1, IPv4 172.25.0.3/prefix16;
IPv6 gateway/address empty and prefix0. DNSNames contain the container name and short ID.
The primary has IPAMConfig null, Links null, Aliases `[spicymila_bot, spicymila_bot]`,
DriverOpts null, GwPriority0, MAC `86:54:08:d8:c9:96`, and the primary addresses above.
DNSNames likewise contain the container name and short ID.

Generated container/endpoint IDs necessarily change on recreation; they must not be confused
with configurable identity requirements. Explicit ipv4_address also changes IPAMConfig from
an allocation result to an explicit request. Neither this difference nor automatic aliases
has been silently accepted as equivalent to the required exact model.

## Isolated Compose experiment

Used existing local image content ID
`sha256:1237cbc00246fccf9f15c015453ae09a55d3ac064d329f4dcbee215b8791efa4`.
Entrypoint was overridden to Python sleep, with no application startup or supplied bot secrets.
The test had no volumes or published ports, read-only rootfs, all capabilities dropped,
no-new-privileges, 64 MiB memory, 0.1 CPU, PID limit32 and restart=no.
Two uniquely named INTERNAL test bridges were marked external in the test Compose model.
Neither production network was used. All objects were automatically removed and absence verified.

The successful modeling experiment was `tu1nz-hc-v2-test-20260927t092020z`.
Both endpoints explicitly requested `aliases: []`, but Inspect returned
`[tu1nz-hc-v2-test-20260927t092020z, probe]`. Static test IPv4 addresses were honored.
Thus declaring the existing production network external can preserve the network itself,
but cannot preserve the current empty endpoint aliases with ordinary Compose up.

This is corroborated by getAliases in the exact installed version:
https://github.com/docker/compose/blob/v2.40.3/pkg/compose/create.go#L360-L368
It always adds the container name and, for normal service creation, the service name.
An empty aliases list only adds no *additional* aliases; it does not disable these defaults.

Two preceding isolated attempts failed before container creation because Docker forbids
explicit addresses on networks whose subnet was automatically allocated rather than explicitly
configured. They were fully cleaned up. The final experiment recreated only its own empty test
networks with explicit non-overlapping subnets. These were test-harness failures, not production
failures and not successful rollback failure-injection tests. The first attempt did not preserve
stderr; the repeated attempt did and established the daemon rejection.

## Stop decision and remaining implementation

No new application transaction or launcher was produced. A disconnect/reconnect supplement
could be investigated to replace Compose-generated endpoint aliases, but would create another
intermediate network state and must prove IP, MAC, route, DNS and rollback behavior first.
It is not accepted or implemented as a normal production path here. The explicit instruction
to stop when Compose cannot model the endpoint losslessly takes precedence over inventing
an equivalence or silently extending the activation scope.

Accordingly, rollback failure-injection coverage, the continuous monotonic socket recorder,
and the new 108-step full workflow run are NOT completed in this investigation. The previous
19 focused tests and 108-step results are historical evidence, not results of this run.
No PR was created; no activation command is provided. The healthcheck remains the original
8090 target and the container remains unhealthy for that known reason.

The old launcher remains invalid: it pins HEAD cfd19d181e825308519e664c0a508639794c0df7
and script SHA256 dc89cc87dd8dcd90d4ed936f6a2163ecd0de62584b8c890f2f59be04f7eb86e6.
The investigation started at a28628e3e2092a5a9fc5ca66fe87285cccc89ee6; current script SHA256
is 08b8db752739541ff6481afee0d020248dadf112c0e5e592fe31989620b8e418. The launcher was inspected, not executed or updated.

## Preservation and evidence

Private evidence root:
`/opt/tu1nz_repos/network-hardening-private-2026-09-22/`

- `spicymila-network-model-20260927T091914Z`: initial full production/network inventories,
  first test model/result and checksums.
- `spicymila-network-model-20260927T091955Z`: captured daemon rejection and cleanup proof.
- `spicymila-network-model-20260927T092020Z`: successful alias experiment, full test Inspect,
  result, final production Inspect, preservation proof and checksums.

Private directories are 0700 and evidence files 0600. Full Inspect/environment data is not committed.
Production Compose SHA256 remains
`04c65475baa7a55067366b78295c8fa663df7996beca04980e191dded7dc3da0`.
All production container IDs, images, Config, HostConfig, network endpoints, mounts,
start times and restart counts equal the pre-investigation snapshot. Mount records are compared
by destination because Inspect returned the same cAdvisor mounts in a different list order.
The original raw failed comparison is retained, with this exact diagnosis recorded separately;
there was no changed mount. Health history naturally advances and is not an immutable field.
All 42 hardening files match the original baseline hashes. 1cf0d79 remains an ancestor.
Canonical checkout remains detached at 7c634d3b82572e8459d51c69f04dce82c624d766 and clean.
No production config or detached checkout was written. No claims of a fresh privileged firewall
or process-attributed listener audit are made.
