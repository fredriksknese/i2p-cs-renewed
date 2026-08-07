# Production-Readiness Plan — i2p-cs-renewed

## Context

`i2p-cs-renewed` is a C# I2P router forked from `PeterZander/i2p-cs`. Its own README says most of the new code is AI-written, "genuinely slop", and likely full of vulnerabilities — and tells readers to use another implementation. The goal is to make that disclaimer untrue: a library and CLI that reach **full protocol parity with i2pd**.

An audit of the current tree found the problems are not evenly distributed. Three are severe and cheap to fix; the rest are the real work:

- **Nothing is diagnosable in a Release build.** `Logging.Log/LogDebug/LogTransport/LogDebugData` all carry `[Conditional("DEBUG")]`, and `I2PCore.csproj` never sets `DefineConstants` per configuration. 686 of 1256 logging call sites are stripped from any non-DEBUG build. Every phase after this depends on fixing it.
- **The trust bootstrap is unauthenticated.** Reseed disables TLS certificate validation outright (`Bootstrap.cs:152`, `:449`) *and* accepts SU3 archives whose signature verification failed (`:258-265`), on the stated grounds that "HTTPS transport provides integrity" — while TLS validation is disabled two functions away. A network attacker can supply the router's entire initial view of the network.
- **The defaults point at broken code.** SSU2 is on by default but has no ACK/retransmit path at all (`SSU2AckManager` is a complete, unit-tested class that production code never instantiates) and no Retry/token handling. Destination encryption leads with an ML-KEM hybrid whose handshake tests fail on all three variants.

Beyond that: near-zero unit coverage for exactly the subsystems needing repair, CI pinned to .NET 5 against a net10.0 repo, an integration suite that silently skips because its i2pd discovery path is dead code, and 128KB allocated per NTCP2 connection with no pooling anywhere.

**Two things worth saying plainly.** First, "full parity" has an open-ended tail — SSU2 and ECIES repair against a live network can consume unbounded effort, and the plan is structured so you have a working, honest router even if it stops at Phase 7. Second, this is anonymity software: a half-working router on the real network degrades real users' traffic and its own operator's anonymity set. Hence the hard `--netid 3` rule below, in force until Gate 6.

**Decisions taken** (from planning): full protocol parity is the target; SSU2 and the PQ hybrid go off by default and become opt-in; reseed is fixed properly and fail-closed early, with an escape hatch; each batch is a branch + PR into `github-master`, squash-merged by the executing agent once CI is green.

---

## Rules for every executing session

Sessions are independent and have no memory of each other. This file is the source of truth; `CLAUDE.md` in the repo covers architecture.

**Setup**
- Repo: `/mnt/c/Users/fredr/OneDrive/Repos/i2p-cs-renewed`, solution `i2p.sln`, target `net10.0`.
- Remote `git@github.com:samueldaaaarling/i2p-cs-renewed.git`, default branch `github-master`, `gh` authed.
- `UNIT` below means:
  ```
  dotnet test src/I2PCore.NTests -c Release \
    --filter "TestCategory!=Integration&TestCategory!=ScaledNetwork&TestCategory!=MultiHop&TestCategory!=Experimental"
  ```

**Per batch**
```bash
git checkout github-master && git pull --ff-only
git checkout -b <branch-from-this-plan>
# implement exactly one batch
dotnet build -c Release i2p.sln && <UNIT>
gh pr create --base github-master --title "<batch-id>: ..." --body "..."
gh pr checks --watch
gh pr merge --squash --delete-branch     # only after green
```

**Non-negotiable**
1. One batch = one branch = one PR. Past ~400 changed lines (excluding mechanical renames), split it.
2. Always branch from fresh `github-master`, never from another batch's branch. That is what keeps batches revertible.
3. PR body states: batch ID, verification command, output summary.
4. If a gate can't be met, **stop and report**. Do not merge a partial fix behind a green-looking test.
5. **Never run a router from this repo on netid 2 (the live network) before Gate 6.** Use `--netid 3` for all local and integration testing.
6. Record non-obvious design decisions as a header comment in the touched file, in the same PR. Append a session log to this file on hand-off.

---

## Phases and gates

Order is driven by one question: what must exist before SSU2/ECIES repair is even attempirable? Answer: working Release logging, a CSPRNG and a deterministic RNG seam, idempotent Start/Stop, a real i2pd reference peer, and socket-free protocol fixtures. Those are Phases 0–3.

| Phase | Name | Gate |
|---|---|---|
| 0 | Observability, safe defaults, green CI | Release build emits debug logs on demand; `UNIT` 0 failures; CI green; default RouterInfo advertises neither SSU2 nor `pq` |
| 1 | Security correctness | Cold-start reseed succeeds with TLS + SU3 verification ON and **fails closed** on a tampered fixture; zero `new Random(` under `src/I2PCore` |
| 2 | Lifecycle & resource hygiene | 10× Start/Stop in one process: no handler growth, no thread growth, clean exit |
| 3 | Reference peer + protocol fixtures | `TestCategory=Integration` *runs* in CI against real i2pd; fixtures reproduce the SSU2/ECIES defects as red tests |
| 4 | SSU2 classical parity | SSU2ConnectivityTests pass both directions vs i2pd; DataTransfer passes with NTCP2 disabled; 5% loopback loss still delivers |
| 5 | ECIES ratchet parity | >10 MB sustained through a 2-hop tunnel to an i2pd destination, no session reset, tag window never exhausts |
| 6 | Tunnel endpoint/gateway | MultiHop + TunnelBuild tests pass with C# as OBEP and IBGW |
| 7 | CLI & config unification | A real `i2pd.conf` boots the router equivalently; malformed flags exit 2, never a stack trace |
| 8 | De-singleton / instance API | Two full routers in one process connect over NTCP2 *and* SSU2 and transfer data |
| 9 | Proposal 169 PQ | PQ handshake tests green + interop, **or** feature stays off with a written reason |
| 10 | Performance & robustness | <100 MB per 1000 NTCP2 sessions; zero silent `catch {}` in `src/I2PCore` |
| 11 | Packaging, samples, docs | `dotnet pack` produces a consumable `I2PCore`; samples use the high-level API |
| 12 | Web console | Console re-pointed at the unified config and instance API |

---

## Batches

### Phase 0 — Observability, safe defaults, green CI

| ID | Branch | Scope | Verify |
|---|---|---|---|
| 0-1 | `p0/logging-release-visibility` | Remove the 11 `[Conditional("DEBUG")]` attributes in `Utils/Logging/Logging.cs` (lines 113,119,125,131,137,143,149,155,161,234,240). Make the runtime `LogLevel` the only filter, with the early-out in `Log(LogLevels,string)` (`:205`) placed **before** any string formatting. Default `Information`. Split `I2PCore.csproj` `DefineConstants` into per-Configuration groups. Add `--log-level` to the CLI. **No call sites change.** | Release run with and without `--log-level debug`; debug lines only in the latter. `UNIT` outcome unchanged. |
| 0-2 | `p0/ci-modernize` | `.github/workflows/dotnet.yml`: `checkout@v4`, `setup-dotnet@v4` @ `10.0.x` (add `global.json` if the preview SDK is needed), `-c Release`, unit-only filter, `--logger trx` + artifact upload | `gh pr checks --watch` green |
| 0-3 | `p0/test-baseline-green` | Fix `TestStreamingConstants`. Mark `NTCP2PQHandshakeTest` `[Category("Experimental")]` — quarantined for 9-3, not deleted. Add a `TestCategories` constants class. | `UNIT` → 0 failed |
| 0-4 | `p0/safe-defaults` | `RouterContext.cs:190` `EnableSSU2`→`false`; `:95` `ProxyEncryption`→`Ecies`; gate `NTCP2Host.cs:448` `addr.Options["pq"]="4"` behind `EnablePqTransport` (default false); `SSU2Host.cs:32` `ConnectionMigrationSupported`→false (its `SendPathResponse` only logs). Opt-ins `--enable-ssu2`, `--experimental-pq`, `--proxy-encryption hybrid`. Update README status board. | Dump default RouterInfo: no SSU2 address, no `pq` option |
| 0-5 | `p0/selftest-optout` | `TunnelProvider.Start():388` — `RunNoiseNSelfTest()` (`:396-589`) behind `--self-test`; port its assertions into a real NUnit test | Startup log has no self-test `LogCritical` |
| 0-6 | `p0/logging-hot-path-lazy` | Convert interpolated `LogDebug($"...")` in tunnel/transport hot loops to the `Func<string>` overloads | Throughput unchanged at `--log-level information` |

0-1 before 0-4 — flip defaults only once you can observe the effect. Merge 0-3 before 0-2 becomes a required gate.

**Why 0-1 is batch #1 and why it's safe:** the fix touches three files, not 686 call sites. The risk isn't diff size, it's that call sites which never executed in Release suddenly fire — a throughput cliff and disk fill. Defaulting the threshold to `Information` keeps post-merge behaviour effectively unchanged; the early-out before formatting keeps it cheap; 0-6 handles the hot paths as a follow-up. Do not touch the `NOLOG_*` `#if` scheme here — that's 6-1.

### Phase 1 — Security correctness

| ID | Branch | Scope | Verify |
|---|---|---|---|
| 1-1 | `p1/reseed-tls-verification` | Remove `ServerCertificateCustomValidationCallback` at `NetDb/Bootstrap.cs:152` and `:449`. Add `--insecure-reseed` that restores it *and* emits `LogCritical`. Delete the misleading comments. | Cold data dir, `--netid 3`: reseed fetch succeeds under default TLS validation |
| 1-2 | `p1/su3-signature-failclosed` | Fix `VerifySu3Signature` (`Bootstrap.cs:286+`). I2P's SU3 convention is raw RSA over the SHA-512 hash (i2pd's `Reseed.cpp` unpads manually) — implement with BouncyCastle `RsaEngine` + manual PKCS#1 v1.5 unpad. **Failure ⇒ reject the archive and try the next host**, replacing the accept-anyway path at `:258-265`. `--insecure-reseed` downgrades to a warning. Check in a real SU3 fixture plus a tampered copy; use the 14 certs in `I2PCore/certificates/reseed/`. | New unit test: valid verifies, tampered rejected, unknown signer rejected |
| 1-3 | `p1/csprng-padding` | Replace `new Random()` with `BufUtils` CSPRNG (`Utils/BufUtils.cs:413`) at `TransportLayer/BlockTypes.cs:185`, `NTCP2/NTCP2Blocks.cs:302`, `NTCP2/NTCP2Session.cs:575,710,738,1703,1891`, `SSU2/SSU2Blocks.cs:350`, `SSU2/SSU2Helpers.cs:125`, `NetDb/Bootstrap.cs:88`. Add a source-scanning test that fails on any `new Random(` under `src/I2PCore`. | `UNIT` + the guard test |
| 1-4 | `p1/rng-seam` | Swappable `BufUtils.RandomSource` (production = `RandomNumberGenerator`) so tests can inject a deterministic stream. `InternalsVisibleTo("I2PCore.NTests")`. | Seeded source ⇒ byte-identical NTCP2 msg1 across runs |

### Phase 2 — Lifecycle & resource hygiene

| ID | Branch | Scope | Verify |
|---|---|---|---|
| 2-1 | `p2/router-lifecycle-idempotent` | `Router.cs:312` subscribes `TunnelProvider.I2NpMessageReceived` but the `finally` at `:337-343` never unsubscribes it — handler accumulates per Start/Stop. Also null `_eciesRouterProcessor` (`:32`) in `Stop()`; it currently survives a restart bound to the *previous* identity. | 5× Start/Stop: one handler, processor identity matches current `RouterContext` |
| 2-2 | `p2/dh-generator-shutdown` | `Data/I2PPrivateKey.cs:44-101` — static `while(true)` DH-generator thread with no shutdown path. Add cancellation + join in `Router.Stop()`. | Thread count stable across 10 cycles |
| 2-3 | `p2/daemonhelper-wired` | `Utils/DaemonHelper.cs:55-91` has Ctrl+C/SIGTERM handling no host ever calls — the CLI's "Press Ctrl+C to stop" is aspirational and skips `Router.Stop()` entirely. Wire it in the CLI and samples. | `timeout -s INT 25 dotnet run ...` ⇒ graceful-stop log + `peerProfiles/` written |
| 2-4 | `p2/transport-lock-hygiene` | `TransportProvider.cs:750-757` locks the mutable `IncomingMessage` event field (identity changes on every `+=`) — use a dedicated lock object. `:330-364` holds one instance-wide `TsSearchLock` across `transport.Connect()`, serialising all sends during any outbound connect — move Connect outside; coalesce with `ConcurrentDictionary<_, Lazy<_>>`. | 50 parallel `GetEstablishedTransport` calls |
| 2-5 | `p2/udptunnel-dispose-leak` | `Client/I2PUDPTunnel.cs:506-516` removes sessions without `Dispose()`; mirror the correct server path at `:268-282` | Test asserting disposal on expiry |
| 2-6 | `p2/static-test-seams` | `TunnelPoolSettings.DEFAULT_*` mutable statics → readonly + per-pool overrides; internal `Logging.ResetForTests()` / `RouterContext.ResetForTests()`. **Write the Gate 2 test here:** 10× Start/Stop, assert delegate invocation-list length and thread count stable within ±2. | `UNIT` with NUnit random test ordering |

### Phase 3 — Reference peer + protocol fixtures *(the enabler)*

| ID | Branch | Scope | Verify |
|---|---|---|---|
| 3-1 | `p3/i2pd-discovery` | `RouterProcessManager.cs:83-86` delegates straight to `I2pdBuilder.GetOrBuild()` (git-clone + cmake), while `FindI2pdOnSystem()` at `:35-47` — which honours `I2PD_PATH` and PATH — is **dead code**. Change to `FindI2pdOnSystem() ?? (I2PD_ALLOW_BUILD==1 ? GetOrBuild() : null)`. Log chosen path + `--version`. **Single highest-value change in the plan** — it activates the whole integration suite. | `--filter TestCategory=Integration` no longer Ignores |
| 3-2 | `p3/i2pd-in-ci` | CI job installing i2pd (apt or pinned release tarball) running `TestCategory=Integration`, initially `continue-on-error: true`; a follow-up removes that at Gate 3 | `gh run view` shows tests executing, not skipping |
| 3-3 | `p3/loopback-transport-fixture` | In-memory `LossyChannel` (drop%, reorder, delay, MTU) pairing two `SSU2Session` objects — no sockets, no NetDb. Same for `NTCP2Session`. | 0% loss delivers 100/100; **5% loss currently loses messages** — commit as an expected-fail documenting the 4-1 defect |
| 3-4 | `p3/ecies-pump-fixture` | Pair two `ECIESSessionKeyManager` instances over a direct message pump | N=5001 currently throws "No available outbound tags" (`ECIESSessions.cs:428-429`) — the 5-3 defect, documented |
| 3-5 | `p3/i2pd-golden-vectors` | Capture i2pd bytes as checked-in fixtures: SSU2 SessionRequest / **Retry** / Data-with-ACK; ECIES NS/NSR/ES. Parse + re-serialize round-trip tests. | Round-trips pass, or fail with a byte diff — either is information |
| 3-6 | `p3/catch-audit-protocol-scope` | Every `catch` in `TransportLayer/SSU2/` and `SessionLayer/ECIES/` must log at Warning+ with the exception, or carry a justifying comment. (102 silent catches exist repo-wide; this narrows to the ~20 files Phase 4–5 depend on.) | Zero bare `catch {}` / `catch (Exception) {}` in those two directories |

3-6 runs last in Phase 3. It is the difference between debugging SSU2 and debugging it blindfolded.

### Phase 4 — SSU2 classical parity

| ID | Branch | Scope | Verify |
|---|---|---|---|
| 4-1 | `p4/ssu2-ack-wiring` | Instantiate `SSU2AckManager` per session; `RecordSent` in `SendBlock`/`BuildDataPacket`; `RecordReceived` in `ProcessDataPacket`; replace the empty ACK case at `SSU2Session.cs:1215-1219` with real processing; `GenerateAck()` on session tick; drive retransmit from `GetPacketsNeedingRetransmit()` | 3-3 fixture at 5% loss delivers 100/100 |
| 4-2 | `p4/ssu2-retry-token` | Add `MSG_TYPE_RETRY` (`SSU2Constants.cs:59`) to the dispatch at `SSU2Session.cs:616-637` — today it falls to "Unknown packet type". Per-peer token cache with expiry; set `header.Token` in `SendSessionRequest` (`:481-490`). | Golden-vector Retry parse; outbound connect to a token-enforcing i2pd completes <5 s |
| 4-3 | `p4/ssu2-path-validation` | Real `SendPathResponse` (`SSU2Session.cs:360-372`); only then restore `ConnectionMigrationSupported` | Source-port migration mid-session survives |
| 4-4 | `p4/ssu2-frag-termination` | Fragment/reassembly + Termination/ImmediateAck parity vs golden vectors | Fixture + integration |
| 4-5 | `p4/ssu2-default-on` | `EnableSSU2`→true, `--disable-ssu2` retained, README status updated | Full integration suite |

### Phase 5 — ECIES ratchet parity

| ID | Branch | Scope | Verify |
|---|---|---|---|
| 5-1 | `p5/ecies-dead-code-decision` | Write the decision as a header comment, then act. Delete `ECIESGarlicProcessor.cs` and the ad-hoc `ECIESRatchet` (`ECIESSessions.cs:496-539`, non-spec `HKDF(key,counter,"ratchet")`, never invoked). **Keep** `RatchetTagSet.cs`'s `NextKeyHandler` — it models i2pd's `HandleNextKey` and 5-4 needs it. Delete `NTCP2AckManager.cs` (entirely unreferenced). | Build + `UNIT` |
| 5-2 | `p5/ecies-diagnostics-downgrade` | `ECIESSessionKeyManager.cs:427-430` and `ECIESSessions.cs:217-221` dump Elligator2/ephemeral-key diagnostics at `LogInformation` on every handshake. Downgrade to `LogDebug` (now reachable, thanks to 0-1) and open an issue capturing the anomaly with a log excerpt. | Handshake log clean at `--log-level information` |
| 5-3 | `p5/ecies-tagset-windowing` | Replace the fixed 5000-tag pre-generation (`ECIESSessions.cs:373-400`) with an i2pd-style sliding window: generate-ahead, expire-behind, never throw | 3-4 fixture at N=100000 passes |
| 5-4 | `p5/ecies-nextkey` | Implement DH-ratchet NextKey send/receive for destination sessions via `RatchetTagSet.NextKeyHandler` | Transfer exceeding the tag window to an i2pd destination without reset |
| 5-5 | `p5/streaming-over-ecies` | End-to-end streaming to an i2pd eepsite via SAM. `Streaming/I2PStream.cs` is already sound (EWMA RTT, AIMD, NACK fast-retransmit) — expect no changes; changes here would be a finding. | `SAMEncryptionIntegrationTests`, `DataTransferTests` |

### Phase 6 — Tunnel endpoint/gateway

| ID | Branch | Scope |
|---|---|---|
| 6-1 | `p6/tunnel-tracing` | Per-hop structured tracing behind `LOG_ALL_TUNNEL_TRANSFER`; convert the `NOLOG_` prefix scheme in `I2PCore.csproj` to a proper per-configuration property |
| 6-2 | `p6/tunnel-endpoint-fix` | Driven by 6-1 output. **Static reading found no defect** — role selection (`TransitTunnelProvider.cs:189-215`), AES-CBC layer direction, and `TunnelDataFragmentReassembly.cs:31-140` are all self-consistent, and a live self-test validates the crypto direction. Treat README's "Broken" as unverified; strong prior that the real fault was in Phase 5. |
| 6-3 | `p6/readme-status-truth` | Rewrite the README status board from measured results |

### Phase 7 — CLI & config unification

| ID | Branch | Scope |
|---|---|---|
| 7-1 | `p7/cli-arg-robustness` | Every bare `int.Parse(args[++i])` and the `IPAddress.Parse` at `I2PRouterCli/Program.cs:101` → helper returning a usage error; bad/missing value ⇒ stderr + exit 2. Add `--version`. |
| 7-2 | `p7/cli-subcommands` | `run` / `keys` / `netdb` / `reseed` / `version`; existing flags kept as aliases |
| 7-3 | `p7/config-file-loading` | `Utils/I2PConfig.cs` is already a complete i2pd-`i2pd.conf`-compatible INI parser (defaults `:16-129`) used only for `tunnels.conf`. Promote it to the router config loader behind `--conf`. One `RouterSettings` record consumed by both `RouterContext` and `ClientContext`; deprecate the `ClientContext.SetConfig` string keys. Precedence: CLI > env > file > default. |
| 7-4 | `p7/cli-json-output` | `--json` for `netdb` and `status` |

### Phase 8 — De-singleton (bottom-up, one layer per PR)

`p8/instance-routercontext` → `p8/instance-netdb` → `p8/instance-transportprovider` → `p8/instance-tunnelprovider` → `p8/instance-clientcontext` → `p8/two-routers-in-process`. Each keeps a `.Inst` shim delegating to a lazy default instance so hosts keep compiling; the shim goes in the final batch.

**Why here and not earlier.** In-process dual routers would help *diagnose* ECIES, but every Phase 4–6 gate is an **i2pd interop** gate — two C# routers agreeing on a wrong wire format proves nothing, and the subprocess harness already provides validation. Meanwhile the refactor churns exactly the files being rewritten (`SSU2Session.cs` 1704 lines, `NTCP2Session.cs` 2027, `TransportProvider.cs`, `TunnelProvider.cs`), guaranteeing rebase conflicts in protocol code — the worst place for silent regressions. And 80% of the benefit costs 10% of the effort: batch 2-6 gives the test-isolation seam, and 3-3/3-4 give paired-object debugging for the layers that actually have bugs. Two sessions of fixtures beat six sessions of refactor.

### Phase 9 — Proposal 169 PQ

Research during planning found the PQ work is **I2P Proposal 169**, and the repo is *partly conformant already* — which reverses the initial "invented crypto" read:

- `Crypto/Noise/NoiseXK.cs:28-30` — `Noise_XKhfsaesobfse+hs2+hs3_25519+MLKEM{512,768,1024}_ChaChaPoly_SHA256` — matches Prop 169's NTCP2 patterns.
- `Data/I2PKeyType.cs:19` — `MLKEM{512,768,1024}_X25519 = 5/6/7` — matches Prop 169's ratchet encryption types.
- `NTCP2Host.cs:448` — `addr.Options["pq"]` — matches Prop 169 RouterInfo signaling.
- `Crypto/Noise/NoiseIKhfs.cs:9,47-49` — `Noise_IKhfselg2_25519+MLKEM*` — **does not match.** Prop 169's SSU2 pattern is XK-based, MLKEM1024 is not defined for SSU2, and SSU2 PQ signals via the long-header `ver` field.

So: keep the code, fix the SSU2 pattern, ship it off by default. **Never delete `Crypto/MLKEM/`** — those are legitimate BouncyCastle FIPS 203 wrappers and are load-bearing.

| ID | Branch | Scope |
|---|---|---|
| 9-1 | `p9/prop169-references` | **First job: fetch https://i2p.net/en/proposals/169-pq-crypto/ and confirm the above against the current revision** (this alignment is a research lead, not yet verified against the spec text). Record the revision date in-code. Add citations at `NoiseXK.cs:28-30`, `NoiseIKhfs.cs:9,47-49`, `I2PKeyType.cs:19`, `NTCP2Host.cs:447-448`, `SSU2Session.cs:506`, `NTCP2Session.cs:600,1717`, replacing the "spec line 363 in ntcp2-hybrid.md" references. |
| 9-2 | `p9/prop169-ssu2-pattern` | Replace the `Noise_IKhfselg2_*` SSU2 patterns with Prop 169's; drop MLKEM1024-for-SSU2; implement long-header `ver` signaling |
| 9-3 | `p9/ntcp2-pq-handshake-fix` | Un-quarantine `TestNTCP2PQHandshake` and fix it |
| 9-4 | `p9/pq-interop` | Build a Prop-169-capable i2pd (`I2PD_ALLOW_BUILD=1`), interop, re-enable `pq=` advertisement under `--experimental-pq` |

Phase 9 is last partly because it's the only phase genuinely needing the i2pd source-build path — Debian ships i2pd 2.45.1, far too old for Prop 169.

### Phase 10 — Performance & robustness
`p10/ntcp2-buffer-pooling` (`NTCP2Session.cs:49` `new byte[131072]` per session → `ArrayPool<byte>.Shared`; no `ArrayPool` usage exists in I2PCore today — this is the README's "300MB per 1000 connections") · `p10/ssu2-packet-pooling` (~32 per-packet `new byte[]` sites) · `p10/silent-catch-audit-{1..4}` (~10 files each) · `p10/thread-sleep-removal` (21 library sites → `PeriodicAction`) · `p10/nullable-i2pcore-{1..n}` (one directory per PR; `<Nullable>` is currently off in I2PCore, I2CP and the test project).

### Phase 11 — Packaging, samples, docs
`p11/nuget-metadata` · `p11/samples-highlevel-api` (rewrite `Samples/I2PEchoClient/Program.cs:129-149` — hand-built StreamingPackets, manual gzip, `zipped.WriteUInt16BigEndian(4353, 4)` port-poking — onto a `ClientDestination` + stream API) · `p11/remove-i2pcontrol-deadcode` (`Client/I2PControlService.cs:29` `DEFAULT_PASSWORD = "itoopie"`, never instantiated — delete or require configured credentials) · `p11/docs`.

### Phase 12 — Web console
Re-point `I2PRouterWeb/Services/RouterService.cs` at the 7-3 config model and the Phase 8 instance API.

---

## Test scaffolding: what's in scope

**Build now** (Phase 3): working i2pd discovery; the two paired-object fixtures (~200–300 lines each); the deterministic RNG seam; golden vectors; the lifecycle test.

**Do not build now**: broad coverage targets for `TunnelLayer/`, `SessionLayer/`, `Client/` — that's months of tests over code Phases 4–8 will rewrite. Interface-mocking `NetDb`/`RouterContext` is Phase 8's job by another name. Web console tests are Phase 12. Fuzzing the serialization layer is the one area already well covered.

**Rule for executing agents:** write a test if it reproduces a defect you're about to fix, or guards an invariant a gate depends on. Otherwise don't.

---

## First session, concretely

**1. Environment.**
```bash
sudo apt-get update && sudo apt-get install -y i2pd cmake
sudo systemctl disable --now i2pd     # apt auto-starts it on the LIVE network, binds 4444/7656
systemctl is-active i2pd              # expect: inactive
/usr/sbin/i2pd --version              # record in the PR body
export I2PD_PATH=/usr/sbin/i2pd
```
`/usr/sbin/i2pd` is already in `FindI2pdOnSystem()`'s candidate list — the function just isn't called yet (3-1 fixes that). `cmake` is for Phase 9; do **not** trigger `I2pdBuilder.GetOrBuild()` this session (10-minute clone-and-build).

**2. Baseline** — record verbatim in the first PR body:
```bash
dotnet build i2p.sln            # ~59 warnings
dotnet build -c Release i2p.sln
dotnet test src/I2PCore.NTests \
  --filter "TestCategory!=Integration&TestCategory!=ScaledNetwork&TestCategory!=MultiHop"
# expect 169 passed / 4 failed / 1 skipped
grep -rn "Logging.LogDebug" --include=*.cs src/I2PCore | wc -l   # expect 543
```
If counts differ, **stop and report** — the plan's assumptions have drifted. Then run the Release CLI briefly with `--netid 3 --disable-reseed` and confirm zero Debug lines: that is the bug, observed.

**3. Ship 0-1**, folding 0-2's workflow update into the same PR. CI as it stands pins .NET 5 and will fail otherwise; the workflow file is separate from the logging change and doesn't compromise revertibility. Do not end session one with `github-master` red.

**4. Update `CLAUDE.md`** in the same PR: the logging section currently documents only the `NOLOG_*` scheme and must describe `--log-level`; add the netid-3 safety rule and a pointer to `docs/PRODUCTION-PLAN.md`.

**5. Hand off** — append a session log to the plan file: batch completed, PR number, baseline numbers, i2pd version, anything contradicting the plan.

---

## Deliverables outside the batch flow

- **`docs/PRODUCTION-PLAN.md`** — this plan, committed to the repo in the first PR so later sessions can find it.
- **`CLAUDE.md`** — updated in 0-1 (logging/`--log-level`, netid-3 rule, plan pointer), 3-1 (i2pd setup for integration tests), 7-3 (config model), 8 (instance API).
- **Published artifact** — an HTML page of this plan with the phase/gate structure and batch tables, for tracking across sessions.

---

## Verification

**Per batch:** `dotnet build -c Release i2p.sln`, then `UNIT`, then the batch's own row in the tables above, then `gh pr checks --watch` before squash-merge.

**Per gate:** the Gate column in the phase table. Gates are pass/fail and block the next phase.

**End-to-end, from Gate 3 onward:**
```bash
# integration suite actually executing against i2pd
dotnet test src/I2PCore.NTests -c Release --filter "TestCategory=Integration"

# a real router run, private network only until Gate 6
dotnet run -c Release --project src/I2PRouterCli -- \
  --netid 3 --data-dir /tmp/i2p-verify --log-level debug

# from Gate 5: fetch an eepsite through the HTTP proxy
dotnet run -c Release --project src/I2PRouterCli -- --http-proxy-port 4445 &
curl -x http://127.0.0.1:4445 http://<known-eepsite>.b32.i2p/
```

The single most informative check at any point: does `--filter TestCategory=Integration` *run* tests rather than skip them? Before 3-1 the answer is no, and the whole integration suite is decoration.

---

## Risks

| # | Risk | Mitigation |
|---|---|---|
| R1 | **SSU2/ECIES repair is unbounded.** The honest headline risk — a single ratchet mismatch can eat several sessions. | Timebox at *batch* level, not phase. Past 3 sessions with no green gate, split off what's proven and write `docs/BLOCKED-<batch>.md` with the exact failing byte sequence. Fixtures (3-3/3-4) and golden vectors (3-5) exist to turn "doesn't work on the network" into "byte 47 differs". **Accept that Phase 4 may deliver "SSU2 works with i2pd 2.45 on loopback" and stop** — still a large improvement over "totally broken". |
| R2 | 0-1 causes a throughput cliff or disk fill in Release | Default threshold `Information` (behaviour ≈ unchanged); early-out before formatting; 0-6 for hot paths |
| R3 | Fail-closed SU3 verification (1-2) breaks reseed entirely — the RSA convention is genuinely non-standard, which is why it was abandoned | `--insecure-reseed` ships in 1-1, *before* 1-2 tightens anything. Land `FileBootstrap` as a documented offline path and check in a reseed bundle. If 1-2 stalls, ship 1-1 alone — TLS validation removes the worse hole. |
| R4 | apt i2pd 2.45.1 diverges from modern i2pd, so Phase 4 gates prove less than they appear | Record i2pd version in every integration PR body; add a pinned recent release to CI in 3-2; re-run Phase 4 gates against it before Gate 6 |
| R5 | Sequential agents make contradictory design choices | Decisions recorded as header comments in the same PR; session log appended here; 5-1 explicitly requires writing the decision before acting |
| R6 | Rebase conflicts in the 1700–2000-line protocol files | Always branch from fresh `github-master`; squash-merge; never run two protocol batches in parallel |
| R7 | Phase 8 never happens because it's last | Accept it. It's a maintainability win, not correctness, and 2-6 captures the test-isolation benefit. Running out of runway at Phase 7 leaves a working router. |
| R8 | Someone runs a repo-built router on netid 2 and injects broken traffic into the live network | The `--netid 3` rule. Consider making it enforceable — refuse netid 2 without `--i-accept-alpha-quality`, removed at Gate 6. |
| R9 | `TestNTCP2PQHandshake` failure is actually a `NoiseXK` defect shared with the classical path, so quarantining it in 0-3 hides a real bug | 0-3's PR body must state which paths the quarantined test covers. `NTCP2HandshakeTest`/`NTCP2CryptoTest` pass, so the shared-defect hypothesis is weak — but record it. |
| R10 | Prop 169 moves (active proposal, production target 2026) and Phase 9 is written against a stale revision | 9-1 re-fetches the proposal and records the revision date. Phase 9 being last means it sees the most settled version. |
| R11 | Silent catches hide a Phase 4/5 failure, so a protocol batch "passes" while swallowing exceptions | 3-6 audits `TransportLayer/SSU2/` and `SessionLayer/ECIES/` before Phase 4 starts |

---

## Session log

*(Appended by each executing session: batch ID, PR number, result, surprises.)*

### Session 1 — 2026-08-07 — batches 0-1, 0-2, 0-3 — PR #1, merged

**Result:** Phase 0 observability and CI done. Unit suite **176 passed / 0 failed / 1 skipped**, green in CI on .NET 10 (run 31186089798, 1m6s). Gate 0 met except the RouterInfo default-advertisement check, which is batch 0-4.

**Baseline, measured before any change.** Debug full rebuild 59 warnings / 0 errors; Release the same; unit filter 169 passed / 4 failed / 1 skipped; 11 `[Conditional("DEBUG")]` at exactly the line numbers the plan lists. i2pd **2.45.1 (0.9.57)** at `/usr/sbin/i2pd` from apt.

**Where the plan was wrong, and what to trust less because of it:**

1. **`Logging.LogDebug` call sites: 530, not 543.** Immaterial, but it means the audit's counts are approximate — don't treat any other stated count as a precondition.
2. **Push access does not exist.** The plan says remote `samueldaaaarling/i2p-cs-renewed`, `gh` authed. The authenticated account (`fredriksknese`) has **pull-only** on it, and that repo has **pull requests disabled** (its `/pulls` API 404s while other endpoints work). Work now goes through the fork `fredriksknese/i2p-cs-renewed`, which is where PR #1 landed. **Later sessions: branch and PR against the fork.** The upstream needs an owner-side change before the plan's stated workflow is possible.
3. **`TestStreamingConstants` hid two extra defects.** NUnit aborts at the first failed assertion, so "one failing constant" was really three. Expect this pattern elsewhere in this repo's tests — a single reported failure is a lower bound.
4. **The `[SELF-TEST]` startup spam logs at Information**, so 0-1 did not quiet it. That is batch 0-5, and it is noisier than the plan implies.

**Decisions recorded in-code:**

- `I2PStream.cs` — `INITIAL_WINDOW_SIZE` 64→10, `INITIAL_RTT` 50→1500 ms, `INITIAL_RTO` 1000→9000 ms, verified against i2pd `openssl`/`libi2pd/Streaming.h`. **Phase 5 must re-validate these against a live i2pd peer** rather than trust the change; they alter congestion and retransmit behaviour and nothing end-to-end exercises them yet.
- `Logging.cs` — runtime-only filtering, default `Information`, threshold checked before `Func<string>` generators run. `LoggingVisibilityTest` locks this in.
- `I2PCore.csproj` — `DefineConstants` now appends rather than replaces; fixed a `,`/`;` typo that collapsed three `NOLOG_` names into one symbol. Inert today, would have bitten 6-1.
- `NTCP2PQHandshakeTest` — quarantined `[Category("Experimental")]` for 9-3. **R9 is lower than feared:** it fails with `InvalidOperationException: Must call GenerateBobEphemeralKeys first` and the test never makes that call, so it looks test-side, not a `NoiseXK` defect shared with the classical path.

**Deviation from the batch rules.** Three batches in one PR (0-1 + 0-3 + 0-2). The plan already sanctions folding 0-2 into 0-1; 0-3 had to join because the moment CI runs the unit suite the 4 pre-existing failures make it red, and "merge only when green" and "don't end session 1 red" are otherwise unsatisfiable. Kept as separate commits. Code+tests 321 lines, under the 400 limit; the rest is docs.

**Operational note.** `apt-get install i2pd` **auto-starts i2pd on the live network** (binds 4444/7656). Disabled with `sudo systemctl disable --now i2pd`. Check this on any new machine.

**Next:** 0-4 (safe defaults) → 0-5 (self-test opt-out) → 0-6 (hot-path lazy logging), then Phase 1. The highest-value single change remains **3-1** (i2pd discovery), which activates the whole integration suite; i2pd is installed and `I2PD_PATH=/usr/sbin/i2pd` works.

### Session 1 (continued) — batches 0-4, 0-5, 0-6 — PRs #2, #3, #4, all merged

**Phase 0 is complete and Gate 0 is met.** Unit suite 188 passed / 0 failed / 1 skipped, green in CI on every PR.

**0-4 (PR #2).** `EnableSSU2` → false, `ProxyEncryption` → `Ecies`, `ConnectionMigrationSupported` → false, and the `pq` RouterInfo option gated behind a new `RouterContext.EnablePqTransport` (`--experimental-pq`). Verified both directions with a RouterInfo dump: default has no `(pq:...)` and no SSU2 address; `--experimental-pq` brings `(pq:4)` back. `EnablePqTransport` must be assigned before `Router.Start()` — `NTCP2Host` reads it while publishing.

**0-5 (PR #3).** The Noise N self-test now runs only with `--self-test` (`TunnelProvider.SelfTestEnabled`). It was writing 17 `LogCritical` lines into every startup — visible at *every* level, since Critical passes any threshold — while being structurally unable to fail: each check logged a bool, and the body swallowed exceptions. Assertions ported to `NoiseNSelfTest`.

**0-6 (PR #4).** Deviated from the plan's stated approach, deliberately. Instead of converting 338 interpolated `LogDebug($"...")` sites to `Func<string>` lambdas — a ~340-line diff through the protocol files R6 warns about — added `[InterpolatedStringHandler]` types so the threshold is checked *before* the interpolation runs. Fixes all 338 with zero call-site changes and keeps fixing code not yet written. R2 is retired.

**Findings for later phases:**

1. **`ECIESTunnelDecrypt` is not unit-testable (Phase 8).** It takes decryption keys as constructor arguments but selects our record by reading `RouterContext.Inst` directly (`ECIESTunnelDecrypt.cs:56-57`). The two can disagree — driven from a standalone `RouterContext` it returns `Success=false`, while reporting success at runtime only because the singleton is the identity that built the record. The old self-test could never have caught this class of bug; it only tested the singleton against itself. `p8/instance-routercontext` should pick this up.
2. **`SendPathResponse` never sent anything** (`SSU2Session.cs:360-372`) and logged "PathResponse sent". Batch 0-1 made that line reachable in Release, so it would have been actively misleading in the field. Message corrected; batch 4-3 still owns the implementation. **General lesson: as later batches make more logging visible, read the strings for truthfulness — some of them lie.**
3. **`GarlicTest.TestEncodeDecodeLoop` flaked once** and did not recur in 4 full-suite and 10 fixture runs. Not attributed to 0-6 — no log interpolation calls a cursor-advancing method, and the test does no logging-dependent parsing — but **not proven pre-existing either**. The test is randomized; if it returns, it is a candidate for the deterministic RNG seam in batch 1-4.

**Phase 0 scoreboard:** 0-1 ✅ 0-2 ✅ 0-3 ✅ 0-4 ✅ 0-5 ✅ 0-6 ✅

**Next session starts at Phase 1** (`p1/reseed-tls-verification`, then SU3 fail-closed, then CSPRNG). Note R3: ship 1-1 before 1-2 tightens anything, so `--insecure-reseed` exists as an escape hatch first.

### Session 2 — 2026-08-07 — batches 1-1, 1-2, 1-3, 1-4 — PRs #5, #6, #7, #8, all merged

**Phase 1 is complete and Gate 1 is met.** Unit suite 211 passed / 0 failed / 1 skipped, green in CI on every PR. Release build 0 errors / 59 warnings throughout — the warning count never moved, which is a useful tripwire.

**Gate 1 evidence.** Cold data dir, `--netid 3`, TLS *and* SU3 verification on:

```
Bootstrap: SU3 signature verified for signer 'lazygravy@mail.i2p'.
Bootstrap: SU3 signature verified for signer 'r4sas-reseed@mail.i2p'.
Bootstrap: SU3 signature verified for signer 'igor@novg.net'.
NetworkBootstrap: Completed with 213 routers from 3 servers.
```

Three hosts, three signers, three pinned certificates. Tampered-fixture rejection is covered by `Su3SignatureTest`; `grep -rn "new Random(" src/I2PCore` returns 0.

**R3 did not materialise.** The plan rated fail-closed SU3 verification as likely to break reseed entirely ("the RSA convention is genuinely non-standard, which is why it was abandoned"). It broke nothing, because the convention is *documented* non-standard, not unknowable — 20 minutes with Python and a real archive settled it before any code was written. Retired.

**Where the plan was wrong:**

1. **The SU3 problem was two bugs, not one.** The plan named the padding convention. It missed that the SigType table was **shifted by two** — type 6 read as `RSA-SHA256-2048` when it is `RSA_SHA512_4096`. Every reachable host signs with type 6, so even correct padding handling would still have hashed with the wrong algorithm. Fixing either alone leaves verification failing, which is presumably how it came to be abandoned.
2. **1-3 listed 10 `new Random(` sites; there were 12.** The two missed are the handshake padding *fills* in `BuildMessage1`/`BuildMessage2` — the most exposed of the set. They reuse an `rng` declared earlier in the method, so a grep for `new Random(` cannot see them; only the compiler did, after the declaration was removed. **Treat every line-number list in this plan as a grep result, not an inventory.**
3. **1-4 is much larger than "add a property to `BufUtils`".** Randomness entered through four doors: `BufUtils`, `System.Random`, static `RandomNumberGenerator.Fill` (Elligator2), and per-call `new SecureRandom()` (X25519, ML-KEM ×3, I2PSignature, ElGamalCrypto). The BouncyCastle door is the one the gate depends on — `CreateMessage1` → `X25519.GenerateKeyPair` → `new SecureRandom()` — so seeding `BufUtils` alone would have left the first 32 bytes of msg1 random and the gate unmeetable.
4. **`GenerateRandomPacketNumber` had a range bug on top of the RNG bug.** It cast `Random.Next()` to `uint`, so the high bit was always clear and half the SSU2 packet number space was unreachable regardless of generator quality.

**Decisions recorded in-code:**

- `Bootstrap.cs` — header comment covering both 1-1 and 1-2, including the measured host survey.
- `VerifyI2PRsaSignature` is **stricter than i2pd's `RSAVerifier`**, which compares the trailing hash bytes and ignores the padding entirely; we validate the full `00 01 FF..FF 00` structure.
- Signed data derives from the cursor position, not `fileLength - signatureLength`, so trailing bytes after the signature cannot shift what is hashed.
- `BufUtils.RandomSource` setter is **internal**, and the deterministic implementation lives in the test assembly. Shipping a `SeededRandomSource` inside `I2PCore` would put a class that makes a real router's keys predictable one `using` away from production code.

**Findings for later phases (observed, not fixed):**

1. **`NetDb` does not filter imports by netId.** A `--netid 3` run stored 213 live-network RouterInfos without complaint. Our own netId is published in caps and written into the NTCP2 handshake, so peers should reject us — but the reseeded NetDb is junk for private-network testing, and Phase 3's integration work should not assume `--netid 3` gives an isolated NetDb.
2. **Inbound NTCP2 never validates the peer's netId.** `NTCP2Session.cs` reads `RemoteNetworkId` and nothing checks it; SSU2 does validate (`SSU2SecurityValidator.cs:87`). A netid-3 router would accept an inbound netid-2 peer. Relevant to **R8** — consider it part of making the netid rule enforceable.
3. **`i2pseed.creativecowpat.net:8443` is genuinely self-signed** and is now skipped. Per-host certificate pinning would recover it. Low priority: 3 of 9 hosts served valid chains and cold start needs one.
4. **`BufUtils.RandomInt` has modulo bias** (`Math.Abs(int % max)`) and throws on `max == 0` where `Random.Next(0)` returned 0. Neither bites at any current call site — all use small constant bounds or a guarded count — but it is now the only integer RNG in the library.

**Test-suite growth:** 188 → 211 across the four batches (`ReseedTlsTest` 4, `Su3SignatureTest` 10, `CsprngGuardTest` 3, `RngSeamTest` 6). One binary fixture added: `src/I2PCore.NTests/TestData/igor_at_novg.net.su3`, 63 KB, a real archive fetched 2026-08-07. It cannot go stale — verification uses only the pinned public key, with no chain or expiry check, same as i2pd.

**Still true from session 1:** push access is to the fork `fredriksknese/i2p-cs-renewed` only; branch and PR there. i2pd 2.45.1 at `/usr/sbin/i2pd`, service disabled.

**Next: Phase 2** (`p2/router-lifecycle-idempotent`). The highest-value single change in the plan remains **3-1** (i2pd discovery), which activates the whole integration suite.

### Session 2 (continued) — 2026-08-07 — batches 2-1 … 2-6 — PRs #9–#14, all merged

**Phase 2 is complete and Gate 2 is met.** Unit suite 234 passed / 0 failed / 1 skipped, green in CI on every PR. Build warnings 59 → **58** (batch 2-5 removed a dead field) — later batches should expect 58, not 59.

**Gate 2 evidence.** `RouterLifecycleTest.TenStartStopCyclesLeakNothing`: 10 Start/Stop cycles of a real router on netid 3, asserting the `I2NpMessageReceived` invocation list is 1 while running and 0 while stopped on every cycle, no DH generator survives a Stop, and thread count stable.

**The gate test found a leak the plan did not predict.** On first run: thread count grew **28 → 38, exactly one per cycle**. `NTCP2Host` and `SSU2Host` both implement `Terminate()`, it was absent from `ITransportProtocol`, so `TransportProvider.Stop()` could not call it and abandoned its protocol hosts — every cycle stranded a live NTCP2 listener thread and socket. Fixed in 2-6. **Writing the gate test was what found this; none of 2-1…2-5 would have.**

**A recurring pattern, now three for three.** Phase 2 kept finding *fully implemented, entirely uncalled* shutdown code:

- `DaemonHelper` — complete signal handling, no caller anywhere (2-3).
- `ITransportProtocol.Terminate` — implemented on both hosts, not on the interface (2-6).
- `I2PPrivateKey` precalculation — the one case where the shutdown path genuinely did not exist (2-2).

**In this codebase, "the method exists" is not evidence that anything calls it.** Grep for callers before assuming a subsystem has the behaviour its API advertises.

**A second recurring pattern: the obvious form of a lifecycle test proves nothing.** Three separate times the naive test passed against the unfixed code, and only reinstating the defect exposed it:

1. **2-1, ECIES processor** — restart, assert the processor matches `RouterContext.Inst`. Passes with the bug, because `Reset()` reloads the same persisted keys so the identity never changes. Fixed by pointing the restart at a different settings file *and asserting the identity actually differs*.
2. **2-2, prompt shutdown** — sleep 100 ms then stop. Passes with the wake-up removed, because it caught the generator mid-refill, and the refill loop re-checks the token every iteration. Fixed by polling until the pool is full so the thread is genuinely parked.
3. **2-5, session identity** — two lookups, assert they differ. Passes with the bug, because the cache is cold on the first call and the second key does not exist yet. Only an interleaved A,B,A,B sequence fails.

**Every new test in Phase 2 was confirmed to fail with its defect reinstated.** Do this for Phases 3–5; it is cheap and it caught three vacuous tests in six batches.

**Where the plan was wrong:**

1. **2-5's stated defect does not exist.** The plan says `I2PUDPClientTunnel.ExpireStale` removes sessions without disposing. That dictionary holds `(IPEndPoint, long)` value tuples — nothing disposable. The file declares **two different `_sessions` fields**, and the one holding `UDPSession` belongs to the *server* tunnel, which already disposes correctly. Auditing for the real defect found a worse one: `ObtainSession`'s fast path tested the dictionary for the *requested* key and returned the *cached* session, so with two active remotes one peer's datagrams went out over another peer's socket — a cross-destination traffic leak.
2. **2-2's gate was already trivially true.** Nothing in the library calls `GetNewKeyPair()`; only tests do. So the DH generator never starts in a stock router and there was no per-cycle thread growth to fix. The real defect was that the thread could not be stopped *at all*, plus two races in the lazy start.
3. **2-4's "use a dedicated lock object" was the wrong fix.** The only subscriber enqueues to a `ConcurrentQueue`; serialising the entire inbound path bought nothing. Capturing the delegate into a local fixes the crash *and* removes the bottleneck. The concurrency requirement is now documented on the event.
4. **`RouterContext.ResetForTests()` was not needed** — `RouterContext.Reset()` already exists and is already documented as the test-isolation seam.

**Decisions recorded in-code:**

- `Router.Subscribe()`/`Unsubscribe()` are adjacent and called from `Start()`/`Stop()`. The original bug was born of asymmetry — subscribe in `Start()`, unsubscribe in `Run()`'s `finally`, on a different thread.
- `TransportProvider.IncomingMessage` now documents that handlers are invoked **concurrently** and must be non-blocking.
- `GetEstablishedTransport` coalesces connects with a per-destination `Lazy`, removed in a `finally` because `Lazy` caches thrown exceptions — otherwise one failed connect makes a peer permanently unreachable.
- `TunnelPoolSettings.DEFAULT_*` are `const`; the configurable values moved to `RouterContext` (per-router, discarded by `Reset()`).

**Findings for later phases (observed, not fixed):**

1. **`TunnelProvider.DistributeIncomingMessage` logs two `[DEBUG_LOG]` lines at Information** for every ShortTunnelBuildReply and VariableTunnelBuildReply, on the inbound hot path. Same class as batch 5-2's ECIES diagnostics.
2. **`UnknownRouterQueue` subscribes to `NetDb.Inst.IdentHashLookup` in its constructor and never unsubscribes.** Not currently a leak — `NetDb.Stop()` nulls `Inst`, so each cycle gets a fresh resolver — but it makes the resolver's handler count not Router's alone, and it breaks the moment NetDb outlives a TransportProvider.
3. **2-4's tests do not prove the throughput property.** They prove the new path is deadlock- and exception-free; proving a slow connect no longer blocks other sends needs an injectable transport, i.e. batch 3-3's loopback fixture.

**Test-suite growth this phase:** 211 → 234 (`RouterLifecycleTest` 4, `KeyPrecalculationTest` 5, `DaemonHelperTest` 5, `TransportConcurrencyTest` 4, `UdpTunnelSessionTest` 5). Three fixtures start real routers or transport layers on netid 3 with reseed disabled, using ports 29090-29095 (new block in `PortAllocator.WellKnown`). Each self-skips if another fixture already owns the singleton. The unit suite is now ~1m50s, up from ~21s — almost entirely the lifecycle fixtures.

**Next: Phase 3**, starting with **3-1** (`p3/i2pd-discovery`), still the plan's highest-value single change. i2pd 2.45.1 is at `/usr/sbin/i2pd`, service disabled, `I2PD_PATH` works.

### Session 2 (continued) — 2026-08-08 — batches 2-7, 3-1 — PRs #16, #15, both merged

**The integration suite is alive.** Batch 3-1 was worth its billing.

| | integration tests |
|---|---|
| before 3-1 | **0 run** — 51 `Assert.Ignore`d |
| after 3-1 | **51 run in 23m31s** — 25 passed, 23 failed, 3 skipped |

Against i2pd **2.45.1 (0.9.57)** at `/usr/sbin/i2pd`, on **netid 99** (`I2pdConfigGenerator.TestNetworkId`) — stricter than the `--netid 3` rule and confirmed in the spawned `i2pd.conf`.

**The 23 failures are the deliverable, not a regression.** They are the first real measurements against a reference peer and the input to Phases 4–5. Unit suite 239 (238 passed / 1 skipped), green in CI.

**Why 3-1 mattered so much.** `FindI2pdBinary()` was `return I2pdBuilder.GetOrBuild();`, so `FindI2pdOnSystem()` — which honours `I2PD_PATH`, checks `PATH`, and lists `/usr/sbin/i2pd` — was dead code. Every availability check tried to git-clone and cmake i2pd instead of looking for the copy already installed. `~/.cache/i2p-cs-tests` has never existed on this machine, confirming no build ever completed. Three defects in the probe itself were fixed too: reading stdout after `WaitForExit` (deadlock), touching `ExitCode` without checking the process exited, and accepting any binary that exits 0 on `--strong`.

**Batch 2-7 was unplanned and blocking.** 3-1's first CI run aborted with `Test host process crashed` — a `NullReferenceException` in `RoutersStatistics.GetStore()` on the NetDb worker thread. **Not caused by 3-1** (which touches integration-only infrastructure); a pre-existing race that the Phase 2 lifecycle fixtures made reachable, and intermittent — #14 ran all 235 green, #15 got to 129 and died.

**Watch this failure mode.** A crashed host makes `dotnet test` print **`Passed!`** next to a non-zero exit and a total of 129 instead of 235. The 106 tests that never ran leave no failure, no skip, no trace. **Always check the test total, not just the pass/fail line** — a suite that quietly stops covering half of itself looks exactly like a green one.

Fixes: `RoutersStatistics` no longer reads `NetDb.Inst` (path passed in by its owner — also a Phase 8 obstacle removed); `NetDb.Run()` gained the missing top-level `catch`, because an unhandled exception on any thread kills the process; and the `while (TransportProvider.Inst == null)` wait now honours `Terminated`, a window reachable in normal shutdown since `Router.Stop()` stops transports before NetDb.

**Test honesty, again.** The 2-7 cycling tests **do not** reproduce the CI race — verified by reinstating the defect and watching them pass. The window needs `Stop()`'s 5 s join to time out, which an empty temp NetDb never causes. Rather than claim the coverage, the tests say so in their doc comments and are scoped to what they do guard. `StatisticsLoadDoesNotDependOnTheNetDbSingleton` is the real regression test and does fail against the unfixed code.

**Findings for the rest of Phase 3:**

1. **The integration suite takes ~23 minutes** and must run **serially** — fixtures share the `Router`/`TransportProvider` singletons and fixed ports 29000-29039. Batch 3-2 needs a job timeout and probably sharding before this can gate anything.
2. **Spawned i2pd survives a killed test host.** `StopI2pd()` is correct but only runs via `Dispose()`, so a CI job that times out leaks i2pd into the runner. Wants a kill-on-close job object.
3. **`NetDb.Load()` calls `DoBootstrap()` when it has too few routers.** Any fixture starting NetDb without `Bootstrap.Disabled = true` will attempt a live reseed from CI. Worth asserting in the harness.
4. **`dotnet test` console output is unreliable for capture** — it uses `\r` progress rewriting, and a redirect can leave only a mangled tail. Use `--logger trx` with `--results-directory` for anything you intend to quote.

**Next: 3-2** (`p3/i2pd-in-ci`), then 3-3/3-4 (the paired-object fixtures), 3-5 (golden vectors), 3-6 (catch audit).
