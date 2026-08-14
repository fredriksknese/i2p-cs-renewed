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
| 3-3 | `p3/loopback-transport-fixture` | ✅ **Done** (PR #18), SSU2 only. In-memory `LossyChannel` (drop%, reorder, delay, MTU) pairing two `SSU2Session` objects — no sockets, no NetDb. NTCP2 half deferred to 3-3b. | Gate **not met, by design** — the handshake itself fails, so there is no data phase to measure. Four quarantined red tests, owner Phase 4. See session 3. |
| 3-3b | `p3/ntcp2-loopback-fixture` | *Optional, low priority.* Pair two `NTCP2Session` objects over a real `TcpListener` pair on 127.0.0.1 — framing and handshake only, no loss injection. Deferred from 3-3 because `NTCP2Session` reaches for `TcpClient.GetStream()` in ~10 places across 2019 lines, so a socket-free version needs a `Stream` seam through a file Phases 4 and 9 rewrite (R6), and TCP makes a lossy channel meaningless. Do this only if an NTCP2 defect actually needs it. | Handshake completes; frames round-trip |
| 3-4 | `p3/ecies-pump-fixture` | Pair two `ECIESSessionKeyManager` instances over a direct message pump | N=5001 currently throws "No available outbound tags" (`ECIESSessions.cs:428-429`) — the 5-3 defect, documented |
| 3-5 | `p3/i2pd-golden-vectors` | ✅ **Done** (PR #21), one SSU2 vector. Reusable capture harness + a checked-in i2pd **TokenRequest**. SessionRequest/Retry/Data and the ECIES vectors are blocked, not skipped — see session 3. | Gate met: the byte diff is the deliverable. Found the ChaCha20 block-counter divergence and that i2pd opens with TokenRequest. |
| 3-6 | `p3/catch-audit-protocol-scope` | ✅ **Done** (PR #22). All 31 catch sites audited; rule recorded on `ProtocolCatchAuditTest` and enforced there. Also added `Logging.LogError` — the level existed and was selectable but no helper emitted at it. | ✅ Zero bare catches in those two directories, guarded by a test confirmed to fail with the defect reinstated |

| 3-7 | `p3/sam-accept-destination-line` | ✅ **Done.** SAM v3 STREAM ACCEPT, both sides. `SAMHelper.StreamAcceptAsync` read only `STREAM STATUS` and left the peer-destination line — which a non-silent bridge writes as the first bytes of the *data* stream — to be consumed as payload; since the callers read a fixed byte count, that is a byte-exact transfer with a shifted body. `SAMBridge` never wrote that line at all, and deferred `STREAM STATUS` until a peer connected. | `SamAcceptDestinationLineTest` (unit, fake bridge on loopback — red before, green after); integration `TestSend5MB_I2pd2_To_I2pd3` in CI |
| 3-8 | `p3/sam-session-destination-keys` | ✅ **Done.** `SESSION STATUS ... DESTINATION=` carries the session's **private keys**, destination-first — i2pd sends 884 base64 characters where a bare destination is 524. Two NetDb tests took `SHA256` over the whole decoded string and asserted the network could find a LeaseSet for the result; every floodfill answered "Requested LeaseSet not found", correctly. `SAMBridge` sent the bare destination instead of the keys, discarding a `privKeyBase64` it had already computed. | `SamSessionDestinationTest` (unit); integration `LeaseSetLookupAndEncryptionVerification` and `SamDataTransferWithLeaseSetLookup` in CI |
| 3-9 | `p3/floodfill-selection-honesty` | ✅ **Done.** A request for a floodfill could be answered with a router that is not one. `GetRandomRouter`'s `exploratory` branch ignored the roulette it was handed and drew from every known router; both fallbacks did the same when the roulette was empty. `FloodfillUpdater` asks with `exploratory: true`, so a router knowing no floodfills published its LeaseSets to arbitrary peers that discard them — while logging "Publishing LS to ECIES FF". Also: an empty roulette threw `NullReferenceException` out of `GetWeightedRandom`, and `GetRandomRouter` NRE'd before the transport layer started. | `FloodfillSelectionTest` (unit, isolated NetDb — red before, green after); `FloodfillRecognitionTest` against a real i2pd floodfill RouterInfo |
| 3-10 | `p3/inactivity-visibility` | ✅ **Done.** The inactivity sweep empties the floodfill index, and a Release build could not say why: five `#if DEBUG` blocks in `RoutersStatistics` held the reason breakdown, so `NodeInactiveReason` was never even populated outside a Debug build. Also `InformationFaulty` short-circuited before any reason was recorded, the NetDb report printed roulette headers with no counts, and two further `#if DEBUG` diagnostics sat in `NetDb.cs` / `NetDb.Reports.cs`. | `NetDbDiagnosticsVisibilityTest` (source scan over `src/I2PCore/NetDb`, verified to bite); reason breakdown visible in the next CI run |
| 3-11 | `p3/routerinfo-publish-ecies` | ✅ **Done.** **Why the floodfill index empties: we publish our RouterInfo in a form no modern floodfill can decrypt.** `SendUpdate` called `Garlic.EgEncryptGarlic` unconditionally, and so did both retry paths — three of the four garlic sends in `FloodfillUpdater`. Every i2pd since 2.36 has an X25519 identity, which reads an ElGamal block as a 32-byte Noise ephemeral key that is not a curve point: both scaled-fixture floodfills logged `Garlic: Incorrect N ephemeral public key` at the exact second of each of our publishes, 20 sends and 0 delivery statuses. The unanswered publishes are then charged to the floodfill as `FloodfillUpdateTimeout` — 3-10's reason breakdown says that is **100%** of why anything was swept. Encryption is now chosen in one place, from `GetECIESPublicKey()`, which is also the only accessor that takes the X25519 *trailing* 32 bytes of a hybrid key where the LeaseSet path handed Noise N the whole thing. The ECIES wrap is now `Garlic.EciesEncryptGarlic`, beside its ElGamal counterpart, replacing two copies. | `FloodfillPublishEncryptionTest` (unit, 4 tests, confirmed red with the defect reinstated): a published RouterInfo opens with the floodfill's own Noise N responder, an ElGamal identity still gets ElGamal, and the publisher decides its encryption in exactly one place |
| 3-12 | `p3/publish-timeout-accounting` | ✅ **Done** (PR #47), confirmed in CI: no `NullReferenceException`, and the sweep's reason breakdown is no longer `FloodfillUpdateTimeout`. `TimeoutRegenerateRiUpdate` dereferences `list.Random()` for a log message (`FloodfillUpdater.cs:406`) and 3-9 made an empty floodfill list legitimate, so with no floodfill known it throws `NullReferenceException` out of `CheckTimeouts` every 5 s — the sibling LeaseSet path already guards with `if (ff is null) continue`. Two consequences, both on the statistic the sweep trusts: the LeaseSet retries after it never run, and the requests it never reached keep `TimedOut == false`, so `CheckTimeouts` charges the same unanswered publish to the same floodfill on every pass until the 80 s window drops it — up to twelve charges against a threshold of five. Mark `TimedOut` where the timeout is *detected*, so the count cannot depend on whether the retry succeeded. | A floodfill that fails to answer one publish is charged exactly one `FloodfillUpdateTimeout`; a sweep with no floodfills known does not throw |
| 3-13 | `p3/obep-build-reply-framing` | ✅ **Done.** **Why i2pd never completes a tunnel through us: it discards every build reply we send as outbound endpoint.** Two defects in the same ten lines, both settled from i2pd's source. (1) A one-time symmetric garlic has no session to parse blocks against, so `SymmetricKeyTagSet::HandleNextMessage` reads **exactly one** block and requires it to be the clove; we led with a DateTime block, which is why the 3-12 run logged `Garlic: Symmetric key tagset unexpected block 0` **370 times**, once per reply, beside **689** `Pending build request timeout, deleted` and **zero** tunnels built. i2pd's own symmetric wrap passes `datetime=false`; only the Noise N wrap passes true. (2) The reply's I2NP message ID was copied from the arriving request instead of the endpoint record's send-message-ID field — the same value only because *our* creator sets `stbm.MessageId = replymessageid`, where i2pd's `Tunnel::Build` leaves it to `RAND_bytes`. So the reply would have been dropped as an unknown pending tunnel even once it could be read. The AEAD itself was always right: i2pd decrypted our garlic and rejected what was inside it. | `ObepBuildReplyFramingTest` (unit, 3 tests, decoding the reply by hand against i2pd's layout rather than through our own parser — confirmed red with each defect reinstated separately: 3/3 fail for the DateTime block, 1/3 for the message ID) |
| 3-14 | `p3/next-hop-filter` | ✅ **Done.** Two defects, and the filter was a latch rather than a rate limit. `ItemFilterWindow.Update` counted **every entry ever recorded** for a key where its own `Test` and `Count` count the memory span, and entries leave only via a `Cleanup` that runs at most every 240 s — so a key under sustained load never fell back below its limit, each refusal appending another entry. On top of that the limit was a constant 2 per 5 minutes: **i2pd has no per-hop throttle at all** (congestion only, `CONGESTION_LEVEL_MEDIUM = 70` against 5000 transit tunnels), and Java I2P's `ParticipatingThrottler` uses `max(12/3, min(66/3, participating/100))` per `11 min / 3` — a floor of 4 for an idle router, 22 for a busy one. Ours now uses Java's window and curve — and counts tunnels **accepted** toward a hop rather than requests received, because the first CI run for this batch showed Java's increment-before-check starving a peer that retries: 9 of 1166 answered, 99.2% refused by this filter. The filter stays because a router relaying unlimited tunnels toward one peer is an amplifier pointed at that peer. Every decision is now counted by reason and reported at `Information` with the periodic transit status, `RejectCapacity` split from `RejectOwnTunnelsDown`, and `LogStatus`'s `#if DEBUG` 30 s / `#else` 2 min pair — which declared two fields of the same name — collapsed to one. | `NextHopThrottleTest` (unit, 9 tests, each defect confirmed red separately): the window expires, keys count independently, an idle router answers at least three requests for its only next hop, the curve matches Java's floor/percentage/ceiling, and the report names the dominant reason with its share |
| 3-15 | `p3/next-hop-budget-scale` | ✅ **Done.** With one next hop, Java's floor of 4 per 220 s *is* the router's entire relaying capability: the integration fixture spent its budget 21 s after start, refused 1702 of 1722 requests all naming the same peer, and i2pd built 7 outbound and **0 inbound** tunnels — so it never got a lease, dropped its own LeaseSet, and all 17 integration failures are `LeaseSet not found`. Java's floor assumes hundreds of possible next hops; i2pd has no per-hop cap at all and gates on congestion. The per-hop cap's job is diversity, not an absolute bound — `MaxTransitTunnels` is the absolute bound and is enforced separately — so the budget becomes the larger of Java's curve and this router's fair share of its own capacity, `MaxTransitTunnels / usable next hops`, converted to accepts-per-window by `NextHopWindow / Tunnel.TunnelLifetime`. Degenerates to Java's rule unchanged when thousands of routers are known, and to i2pd's capacity-only behaviour when one is. Plus: the periodic transit report states the budget in force and the router count it came from, which 3-14's evidence needed a debug build to read. | Unit: the limit is Java's exactly at live-network peer counts, lifts to sustain i2pd's demand at fixture peer counts, is monotonic in the peer count, and never authorises more than `MaxTransitTunnels`. CI: `Transit build requests` accept share in the **integration** fixture, and whether i2pd builds an inbound tunnel through us |

| 3-16 | `p3/floodfill-reply-encryption` | ⏳ **Implemented, awaiting CI.** **The two-router fixture has exactly one floodfill and it is i2pd itself**, so `FloodfillServer` has never executed in any integration run and the LeaseSet round trip was never actually attempted. Settled from i2pd's source, not inferred: `NetDb::Start` inserts i2pd's own RouterInfo into `m_Floodfills`, so it publishes to itself; `RequestedDestination`'s constructor excludes self when floodfill, which is the `NetDbReq: No more floodfills` warning in every run. Two production defects found on the way, both the plan's signature shape. (1) `CreateLeaseSetDatabaseLookupMsg` sets flags `0x15` — delivery, LeaseSet, ECIES, with the encryption bit **clear** — then writes `replyKey(32) ‖ numTags(1) ‖ tag(8)` anyway, and i2pd's own floodfill reads the group on **either** flag; our parser gated the tag count on the clear bit, so every LeaseSet lookup i2pd sends parsed with zero tags. Our writer set both flags, so reader and writer agreed and neither agreed with the network. (2) `FloodfillServer` then answered in the clear whatever it was asked, where i2pd wraps the reply with `WrapECIESX25519Message` — byte-for-byte the one-time garlic 3-13 already proved correct, now shared. | Unit: `FloodfillReplyEncryptionTest`, 8 tests, each defect confirmed red separately (3/8 for the parser, 1/8 for the wrap); the lookup is built to i2pd's byte layout, not by our own writer, and the reply is decrypted the way i2pd decrypts it. CI: whether `FloodfillServer` appears in the log at all, and whether i2pd finds our destination |

3-6 runs last in Phase 3. It is the difference between debugging SSU2 and debugging it blindfolded.

### Phase 4 — SSU2 classical parity

| ID | Branch | Scope | Verify |
|---|---|---|---|
| 4-0 | `p4/ssu2-header-chacha-block` | ✅ **Done** (PR #23). Keystream now starts at ChaCha20 block 1, matching i2pd's `Crypto.cpp ChaCha20()` (`iv[0] = htole32(1)`). Citations re-derived from i2pd symbols, replacing the "spec lines 761-798" references to an absent document. | ✅ `OurHeaderDecryptionCanReadI2pdsHeader` un-quarantined and green against the checked-in vector; `I2pdHeaderMaskComesFromChaCha20BlockOne` still green |
| 4-0b | `p4/ssu2-header-48-byte-pass` | ✅ **Done** (PR #34), and it was batch 3-3's unexplained AEAD failure too — one defect, not two. i2pd covers packet bytes 16..64 in a **single 48-byte ChaCha20 pass** for Session Request and Session Created; we restarted the keystream, XORing the ephemeral key with bytes 0..32 where i2pd uses 16..48, and the send paths called `EncryptLongHeaderInPacket`, which stops at byte 16 — so the source connection ID and token went out **in the clear** and the receiver (always unmasking 0-31) hashed a header the sender never built. `ObfuscateEphemeralKey` now takes the continuation of the pass; the four Session Request/Created send and parse paths use `EncryptLongHeaderComplete`. **The 16-byte form is untouched**, so TokenRequest, Retry and PeerTest are unaffected. | ✅ `Ssu2SessionRequestVectorTest`: i2pd's real Session Request authenticates through the production path — a verifying Noise tag, which no wrong byte survives. `Ssu2HeaderLayoutTest` un-quarantined. 3-3 loopback goes `sent=1` → `sent=2` |
| 4-0h | `p4/ssu2-sessioncreated-header-key` | ✅ **Done** (PR #35) — **the SSU2 handshake now completes**, C#-to-C#, for the first time. Three defects, all of the same shape: the two halves of a message disagreeing about a key or a hash. (1) The type peek trial-decrypted with the intro key, which cannot read a Session Created; it now picks the key from session state and requires the type byte to agree. (2) Alice derived the Session Confirmed header key **after** `CreateMessage3Part2` mixed `se` into the chaining key and split, so Bob could never derive the same key — moved before message 3 is built. (3) Bob hashed the header as received where Alice hashes the canonical `flags[0] = 0x01` form; identical unfragmented, different fragmented, and it always fragments here. Also fixes the fixture: it watched only `Host.ConnectionCreated`, which fires for inbound sessions only, so the dialling peer's `Established` could never fill. **Original scope below.** **Found by 4-0b, and it was the thing blocking the loopback handshake.** `SSU2Session.ProcessReceivedPacket` peeks the message type by trial-decrypting the long header with `k_header_2 = k_header_1 =` the intro key. That is correct for a Session Request and wrong for a **Session Created**, whose k_header_2 is `HKDF(chainKey, "SessCreateHeader")` — the derivation `ProcessSessionCreated` itself performs correctly, two calls later. The type byte sits at offset 12, inside the group k_header_2 masks, so Alice reads garbage (`Unknown packet type 160` on the 3-3 fixture) and drops the reply she is waiting for in the `default` arm. Same shape as 4-0b: the *dispatcher* uses one convention and the *handler* another. Check the Session Confirmed and Data arms for the same assumption while there. | `HandshakeCompletesOnACleanChannel` un-quarantines; a Session Created built by `SendSessionCreated` is typed correctly by the peek, confirmed red first |
| 4-0i | `p4/ssu2-handshake-payload-blocks` | **Found by 4-0b, from i2pd's own bytes.** The authenticated plaintext of i2pd's Session Request is `00 0004 6a77a32d | fe 001a 00…` — SSU2 **blocks**: type, 2-byte big-endian length, data; a DateTime block (type 0) then a Padding block (type 254). Ours is neither written nor read that way: `SSU2Session.BuildRequestPayload` writes a bare timestamp and padding length, and `ProcessSessionRequest`/`ProcessSessionCreated` read them back the same way, so the two agree with each other and disagree with the network. i2pd will reject our handshake payload, and we would misparse its DateTime block as a timestamp of `0x00000406`. Same failure shape as 4-0b and 4-1a; the vector is the reference. | The captured payload parses as blocks through production code, and a payload we build re-parses as the blocks i2pd expects |
| 4-0k | `p4/ssu2-dest-connection-id` | ✅ **Done** (PR #40). **Why i2pd never answers our Session Request — found by capturing our own packet and decoding it independently, not by guessing.** Our outbound Session Request carries `destConnId = 0000000000000000`. `RemoteConnectionId` is assigned only in `ProcessSessionRequest` (`:960`, responder) and `ProcessSessionCreated` (`:1092`, initiator), so the *first* packet an initiator sends always addresses session zero. A responder looks sessions up by that ID; i2pd has no reason to answer. **C#-to-C# it works perfectly because both sides agree on zero** — the loopback even logs `Got remote connection ID: 0000000000000000` — which makes it the sixth instance of this plan's signature defect. The rest of the packet is correct: decoded with i2pd's published intro key it reads `type=0 version=2 netid=99`, source connection ID properly random, so 4-0b/4-0h/4-0i all hold. Reference for the fix: i2pd's own Session Request (4-2c's vector) carries `destConnId=348a6a64213c6856` and `srcConnId=d8116fb78ecaa4db` — **both non-zero and unrelated**, so this is not a derived value. `token` is also zero, which is separate and expected to draw a Retry once the packet is addressed to a session that exists. | The captured outbound Session Request carries a non-zero destination connection ID; `CSharpEstablishesAnSSU2SessionWithI2pd` gets *something* back from i2pd rather than silence |
| 4-0j | `p4/ssu2-holepunch-keys` | **Verified, and worse than first recorded — the HolePunch is non-functional in both directions.** (1) `SendHolePunch` encrypts payload *and* header with `Host.GetMyStaticKey()`, a variable it calls `introKey`: it is the **static** key, and it is **ours**, where Alice's **intro** key belongs — so Alice can never decrypt what Charlie sends. (2) It masks bytes 0-15 with `EncryptLongHeaderInPacket` while every receive path unmasks 0-31, the same asymmetry 4-0b removed from Session Request. (3) **There is no receive path for type 11 at all** — `TYPE_HOLE_PUNCH` appears only in the constant and that one send site, so an arriving HolePunch falls through `DispatchPacket`'s final `else`. Fixing this means plumbing Alice's intro key in from the RelayIntro and writing the receiver; **it is a batch, not a patch**, and per the plan's own rule the masking must not be 'fixed' first behind a test with no peer to check it against. | A HolePunch built by production decrypts through a production receive path, with the key the receiver actually holds |
| 4-0i | `p4/ssu2-handshake-payload-blocks` | ✅ **Done** (PR #38). The handshake payload is SSU2 **blocks**, not a bare timestamp. i2pd's captured Session Request carries `00 0004 6a77a32d | fe 001a 00…` — a DateTime block then Padding — while `BuildRequestPayload` wrote 4 bytes of timestamp, 2 of padding length and 2 reserved, and both handlers read that back. Read the old way, i2pd's DateTime block decodes as `0x00000406`: a router forty years in the past, which the clock-skew check rejects on its own. New `SSU2HandshakePayload` builds and parses; unknown block types are skipped rather than rejected, which is what block lengths are for. **The PQ appendix was deliberately not reframed** — it is a bespoke version byte plus raw key with no block header, and giving it a real type is a Phase 9 protocol decision. | ✅ `I2pdsHandshakePayloadParsesAsBlocks` reads i2pd's own payload through the production parser and gets its timestamp; `OurHandshakePayloadIsBlockFramed` for the send side |
| 4-0j | `p4/ssu2-holepunch-keys` | Read during 4-0b, **not yet verified — confirm before fixing.** `SSU2RelayHandler.SendHolePunch` names its key `introKey` but takes `Host.GetMyStaticKey()`, the Noise static key, and a HolePunch goes to *Alice* so it should use *Alice's* intro key; it also masks its long header with `EncryptLongHeaderInPacket` (bytes 0-15) while every receive path unmasks 0-31, which is exactly the asymmetry 4-0b removed from the Session Request path. Nothing exercises HolePunch, so neither would be noticed. Audit the PeerTest path alongside it — that one already uses the 0-31 form, and it **also shares `ObfuscateEphemeralKey`**, so 4-0b moved its bytes 32-63 too. That is not a regression: `SendPeerTest` writes an obfuscated key there while `HandleIncomingPeerTestPacket` reads the same offset as the start of the AEAD ciphertext, so the two never agreed and nothing tests the pair. Decide what a type-7 packet actually carries before repairing either end. | A HolePunch built by production code decrypts through the production receive path with the key the receiver actually holds |
| 4-0c | `p4/integration-fixture-ordering` | **Test infrastructure, not SSU2** — the `4-0x` numbering only means "runs before 4-1". Three `[SetUpFixture]`s decide whether to reuse the shared C# router by testing `TestNetworkFixture.CSharpRouter != null`. That stays true after teardown disposes it, and `NetDb.Stop()` nulls `NetDb.Inst`, so the reused router is dead: 11 tests NRE'd inside `NetDb.Inst.AddRouterInfo` and the SAM-bridge cluster lost its listener. Fix: `CSharpRouterHarness.IsRunning` (asks the singletons), null the static on teardown, and stop `Stop()` restoring `I2PNetworkId = 0x02` + `Bootstrap.Disabled = false` — a rule-5 breach. Also make `summarise_trx.py` print stack frames; the traces were in the `.trx` all along. | Integration failures drop from 23; `IntegrationFixtureLifecycleTest` green and confirmed red with each defect reinstated |
| 4-0d | `p4/ssu2-netid-from-config` | **Blocks every other SSU2 batch.** Outgoing headers hardcode `NetId = 2` while `SSU2SecurityValidator.cs:87` and `SSU2Helpers.cs:136` validate against `I2PConstants.I2PNetworkId` — the send path is pinned to the live network while the receive path honours configuration, so **SSU2 rejects its own traffic on netid 3 or 99**. Integration runs on 99 and rule 5 mandates 3, so no SSU2 handshake can complete on any netid this project may use. **Five sites, not the two 3-3 recorded:** `SSU2Session.cs:496`, `:1382`, `SSU2RelayHandler.cs:990`, `Messages/SessionRequest.cs:27` (commented `// I2P mainnet`), `Messages/SessionCreated.cs:25`. | `Ssu2NetIdTest`: headers announce the configured netid, what we send passes our own validator on 2/3/99, and a scan keeps the literal out |
| 4-0d-fix | `p4/guards-catch-what-they-claim` | ✅ **Done** (PR #32). Removed `SSU2Constants.NETWORK_ID = 2` (written raw as `header[14]` in `SSU2RelayHandler`) and the unreferenced `NTCP2Constants.NETWORK_ID = 2`, plus an `SSU2ProtocolTest` assertion that *enforced* the defect ("Network ID must be 2 for mainnet"). Widened `Ssu2NetIdTest` to match a constant and a raw indexed write, not only `NetId = 2`; made the CSPRNG scan strip comments, so prose describing the rule no longer trips it. Both widenings confirmed against the reinstated defects. | ✅ Guard flags `SSU2Constants.cs` and `SSU2RelayHandler.cs` when either spelling returns; a comment naming the banned constructor no longer fails the build |
| 4-0e | `p4/clientcontext-config-before-start` | **Production defect, found by 4-0d.** `Router.cs:125` starts `ClientContext` before any host configures it, and `ClientContext.Start()` returns early on `IsRunning` — so every `SetConfig` a host makes afterwards is silently discarded. SAM/HTTP/SOCKS all default to enabled, so a router binds **7656/4444/4447** whatever the flags say, `--sam-port 0` does not disable SAM, and the CLI prints ports it never bound. Costs 13 integration tests too. Fix the silent discarding, not only the call order. | `--sam-port`/`--http-proxy-port` bind what was asked; `--sam-port 0` leaves nothing on 7656; SAM tests reach the configured port |
| 4-0f | `p4/port-sweep-kills-test-host` | ✅ **Root cause found and reproduced on demand.** The sweep ran `fuser -k {port}/tcp`, which SIGKILLs **every** holder of the port with no way to spare the caller. `ScaledNetworkFixture:111` sweeps 29000-29299 as its first action; while the SAM bridge was wrongly on its default 7656 the ranges never overlapped, and 4-0e moving it to the configured **29002** — the third port swept — made the fixture kill its own test host. Fixed by enumerating holders with `lsof -t` and killing by PID, skipping `Environment.ProcessId`; missing `lsof` now declines to kill rather than falling back to a blind `fuser`. CI also collects `/tmp/i2p_scaled_test.log`, whose absence is why this looked like "ScaledNetworkFixture never ran". | ✅ `PortSweepSafetyTest`; reinstating `fuser -k` reproduces `"Test host process crashed"` exactly |
| 4-1a | `p4/ssu2-data-packet-header` | ✅ **Done** (PR #28). `BuildEncryptedPacket` and `Parse` both hand-rolled a header that is not an SSU2 short header — 2 bytes of connection ID at 0-1, packet number at 4, type at 2, while every reader takes type from 12 — and agreed with each other, so it round-tripped and no test noticed. The 64-bit connection ID was truncated to its top 16 bits. Both now use `SSU2Header`, the one definition of the format. `BuildWithBlock` took a data key and a header key and used neither, so every relay-tag request and peer test went out unframed and in the clear. `ProcessReceivedPacket`'s type peek handed a whole packet to `DecryptShortHeader`, which throws for anything but 16 bytes, dropping every data packet. **Not verified against i2pd** — a Data vector needs a completed handshake (4-0b, 4-2). | ✅ `Ssu2DataPacketHeaderTest`, asserted against `SSU2Header` and hand-computed offsets rather than its own round trip; 4 of 5 confirmed red with the defects reinstated |
| 4-0d-fix2 | `p1/random-scan-strips-comments` | Tiny. Batch 1-3's `NoSystemRandomUnderI2PCore` scan does not strip comments, so prose *describing* the banned constructor trips it — it flagged `SSU2TokenCache.cs` for a doc comment explaining the rule. 4-2a reworded around it rather than widening scope. Strip line comments before matching, as `Ssu2NetIdTest` and `ClientContextConfigTest` already do. Fold into any Phase 1 touch-up. | The scan still fails on real usage, and stops failing on comments |
| 4-0g | `p4/integration-five-minute-cap` | ✅ **Done** (PR #33). Every integration test capped at ~5 minutes. Measured from a real run: 37.7 min of test time, of which `TestBidirectional5MB` alone was **946s — and it failed**, despite carrying `[CancelAfter(300000)]`. The slowest *passing* test is 120s, so the cap costs no coverage. Cut the internal waits (`SAMHelper.CreateAndHelloAsync` 120s → 45s, transfer 900s/600s/300s → 240s, stream connect 300s → 60s) because **those are the only thing that actually bounds a test** — `CancelAfter` cancels a token none of these tests declares, so it reports a timeout without stopping the work (4-0f cause 2). `NUnit.DefaultTimeout=300000` added as a declared backstop; job timeout 60 → 45 min. | Integration wall-clock drops from ~45 min; no currently-passing test regresses |
| 4-1b | `p4/ssu2-data-packet-mistyped` | ✅ **Done** (PR #36). **About 1.2% of every SSU2 data packet was silently discarded**, and only 4-0h made it reachable enough to see. In `Established` the type peek fell through to a long-header trial decrypt under the **intro key**, which no data packet is masked with, so the type byte it read was uniformly random; the three long-header values (0, 1, 2) bypassed the short-header path and went to a handshake handler, which dropped them — `Received SessionCreated in state Established`. Fixed by giving `Established` its own branch that tries the data header key first and requires the type to be `DATA`, the same state-ordered rule the rest of the peek uses. | ✅ `EveryDataPacketIsTypedAsDataWhateverTheIntroKeyWouldSay` — 1000 messages, so P(passing by luck) ≈ 8e-6; confirmed red at 994/1000. **`CleanChannelDeliversEveryMessage` un-quarantines: the 3-3 gate of 100/100 at 0% loss is met** |
| 4-1 | `p4/ssu2-ack-wiring` | ✅ **Done** (PR #37). `SSU2AckManager` was a complete, unit-tested class that **nothing instantiated**, and the ACK block case in `SSU2Session` was an empty `break` — so a sender kept no record of what it sent and a receiver acknowledged nothing. Now: one manager per session, `RecordSent` in `BuildDataPacket` (I2NP traffic only — an ACK held for retransmission would ACK an ACK forever), `RecordReceived` in `ProcessDataPacket`, real `ProcessAck`, and `Tick()` both emits the delayed ACK and re-sends what is unacknowledged. **Retransmission makes duplicates normal**, so a repeat packet number is re-acked and not delivered twice. | ✅ `LossAtFivePercentStillDeliversEveryMessage` un-quarantined and green — 100/100 at 5% loss, batch 3-3's second gate; confirmed red at 94/100. Plus `AcknowledgedPacketsStopBeingHeldForRetransmission` |
| 4-2a | `p4/ssu2-retry-token-responder` | ✅ **Done** (PR #29), responder half. i2pd's first packet to a peer it holds no token for is a **TokenRequest** (type 10); it fell through `SSU2Host.DispatchPacket`'s final `else`, so an inbound SSU2 session from i2pd could not begin. Adds `SSU2TokenCache` (per host, `TickCounter` expiry, issued/received kept separate, size-capped) and `Messages/Retry.cs`, and answers a TokenRequest with a Retry. Creates no session — a TokenRequest is stateless anti-DoS. Header length guard raised 32 → 64, which the trial decrypt always needed. | ✅ `Ssu2RetryTokenTest`, 9 tests: the real i2pd TokenRequest authenticates through the production path, and an inbound TokenRequest is answered end-to-end over the 3-3 loopback channel |
| 4-2c | `p4/ssu2-sessionrequest-capture` | ✅ **Done** (PR #30). ⚠️ **Known flaky in CI** — it passed on #30, failed on #34 and passed again on #35, and the run it failed on had 4-0b in the tree exactly as the run it passed on did. Its failing assertion is `Retry.TryOpen` on **i2pd's first datagram, before we transmit anything**, so no change of ours can reach it; the precondition is that i2pd dials within the window and opens with a TokenRequest. Treat a lone failure of this test as noise, and make it say *why* before treating it as signal. **Unblocked 4-0b.** Extends `SSU2GoldenVectorCapture` to answer i2pd's TokenRequest with a Retry built by production code and capture what it sends next. **The captured file is itself the assertion**: i2pd only proceeds to a Session Request if the Retry authenticated and carried a token it accepted, so a Session Request arriving is end-to-end proof that 4-2a is correct against the real peer rather than against ourselves. The captured packet carries the ephemeral key and is the only thing that can settle 4-0b's 48-byte question — the TokenRequest vector has no ephemeral key at all. **Cannot be run against i2pd 2.45.1**: neither this nor its sibling elicits a dial there, so CI (2.61.0) is the only place it can pass. | The vector file appears; `Retry.TryOpen` reads i2pd's TokenRequest in the live exchange, not just from the checked-in bytes |
| 4-2b | `p4/ssu2-retry-token-initiator` | ✅ **Done** (PR #31). Dispatches `TYPE_RETRY` (previously "Unknown packet type 9", so a token-enforcing peer — i2pd's normal configuration — could never be dialled), consumes the token, presents it in `SendSessionRequest`, keeps the `NewToken` block that was parsed and dropped, and requires a token as responder. Rejection sends a Retry and **does not** `Terminate()`: a terminated session lingers in `Sessions` until the worker tick reaps it, so the re-sent request would be routed into a dead one. Retry handling capped at one re-send. | ✅ `Ssu2TokenExchangeTest`, 4 tests over the 3-3 loopback channel, asserting on the token exchange rather than establishment (still blocked by 4-0b) |
| 4-3a | `p4/ssu2-path-response` | ✅ **Done** (PR #53). `SendPathResponse` built the block and dropped it while `caps` published `p`, so we invited a challenge and answered with silence. Now sent via `SendBlock`, bounded by one datagram, and the hand-rolled framing (which `BuildWithBlock` also writes) is gone. | `Ssu2PathResponseTest` |
| 4-3b | `p4/ssu2-session-migration` | **Blocked on the k_header_1 question — see session 12.** Split out of 4-3 by 4-3a. `SSU2Host.Sessions` is keyed by `IPEndPoint`, so a packet from a moved peer matches no session and `DispatchPacket` drops it before any block is read. Key by connection id, challenge the new address, migrate only on a matching PathResponse, then publish `m`. | Source-port migration mid-session survives |
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
| 6-1 | `p6/tunnel-tracing` | ✅ **Done** (PR #52). The `NOLOG_` `#if` scheme is gone: categories are runtime flags (`TraceCategories`, `--log-trace`) behind an interpolated-string handler, so an off category costs a mask. `TransitTunnel` traces both sides of its layer crypto with a digest, so a message is followable between two routers logs. Found two guarded lines that could never have compiled, one category with no call sites, and one that no build ever defined. |
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
# Experimental is excluded here as it is in the unit filter (batch 4-0e): a quarantined
# integration test is quarantined because of *how* it fails, and one that hangs takes the
# test host down and erases every test scheduled after it.
dotnet test src/I2PCore.NTests -c Release \
  --filter "TestCategory=Integration&TestCategory!=Experimental"

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

### Session 3 — 2026-08-08 — batch 3-2 — PR #17, merged

**Integration tests now run in CI.** A second job in `.github/workflows/dotnet.yml` installs a pinned i2pd and runs `--filter TestCategory=Integration`. Unit job 2m51s, integration job **23m17s**, both green.

| | total | executed | passed | failed | skipped |
|---|---|---|---|---|---|
| CI, i2pd 2.61.0 | 51 | 48 | 25 | 23 | 3 |
| local, i2pd 2.61.0 | 51 | 48 | 25 | 23 | 3 |
| local, i2pd 2.45.1 (session 2) | 51 | 48 | 25 | 23 | 3 |

**R4 is substantially retired.** The risk was that gates passed against Debian's ancient i2pd 2.45.1 prove less than they appear. Against **2.61.0 (0.9.70)**, the current upstream release, the suite produces not just the same counts but the same six failure signatures with the same multiplicities. Whatever is broken is not a 2.45.1 artifact. Keep recording the version in integration PR bodies, but the concern no longer needs to shape the schedule.

**The "23 failures" are not 23 defects — they are six, and mostly not protocol defects at all.** This corrects the session-2 framing that they are "the measured input to Phases 4–5":

| count | signature |
|---|---|
| 11 | `OneTimeSetUp: SetUp : NullReferenceException` — a fixture never initialises, so 11 tests exercise nothing |
| 8 | `Failed to connect to SAM bridge at 127.0.0.1:29002` — the C# router's SAM bridge never came up |
| 1 | `SAM STREAM CONNECT failed: CANT_REACH_PEER "LeaseSet not found"` |
| 1 | `i2pd RouterInfo should be in our NetDb after NTCP2 handshake` |
| 1 | `Expected SESSION STATUS, got: ` |
| 1 | `Datagram session should succeed or report status: ` |

Only the last four reach a protocol-level measurement. **Whoever starts Phase 4 should fix the fixture NRE and the SAM bridge startup first** — 19 of 23 failures are downstream of those two, and until they are fixed the suite cannot report on SSU2 or ECIES at all. Note also that these fixtures share the `Router`/`TransportProvider` singletons, so it is plausible the SAM-bridge cluster is collateral from the fixture that crashed earlier in the run; that ordering dependency is worth confirming before treating them as two separate causes.

**Two hazards in the i2pd Debian package, both of which would have failed only in CI:**

1. **The `postinst` starts i2pd as a systemd service** — `invoke-rc.d ... start` and `deb-systemd-invoke start i2pd.service`. On netid 2, the live network, on every runner.
2. **The package ships an AppArmor profile** attached to `/{usr/,}bin/i2pd` that restricts writes to `/var/lib/i2pd/**` and `~/.i2pd/**`. Our fixtures run i2pd with `--datadir=/tmp/i2pd_test_*` and `logfile=/tmp/...`, which that profile denies. This never bites locally because apt on Debian installs to `/usr/sbin/i2pd`, which the attachment glob does not match — but the upstream deb puts the binary at `/usr/bin/i2pd`, which it does.

Both are avoided by unpacking with `dpkg-deb -x` into `/opt/i2pd` instead of installing: no maintainer scripts run at all, and the path falls outside the profile's glob. A verify step then asserts no i2pd service is active and no stray i2pd process exists. **If a later batch switches to `apt install`, both hazards come back.**

**Deviation from the batch spec, deliberately.** The plan says `continue-on-error: true`. Applying that to the *job* would also excuse the two failure modes this project has already hit — a suite that skips itself (the entire pre-3-1 state) and a test host that dies mid-run (the crash that forced batch 2-7). It sits on the *test step* instead, and a following step parses the `.trx` and fails the job if fewer than `MIN_INTEGRATION_TESTS` executed. So CI gates on the suite *running* while staying lenient about results. Gate 3 removes one line and starts gating on results too.

`MIN_INTEGRATION_TESTS` is **40**, set from the measured 48 rather than guessed: low enough that adding or skipping a few tests will not trip it, high enough to catch the ~55% partial run that the observed test-host crash produced.

**Findings for later phases:**

1. **i2pd 2.61.0 still does not advertise ML-KEM.** The 3 skips are the PQ tests, self-skipping with "i2pd does not advertise ML-KEM support" — on the current release, not just on 2.45.1. Phase 9's note frames the source build as necessary because *Debian* ships something old; it is necessary regardless. **Batch 9-4's `I2PD_ALLOW_BUILD=1` path is not optional.**
2. **Phase 3 finding 3 does not bite — verified, not assumed.** Every integration fixture already disables reseed: `CSharpRouterHarness.cs:92` sets `Bootstrap.Disabled = true`, and `CSharpProcessManager.cs:113` passes `--disable-reseed` alongside `--netid 99`. CI therefore makes no live-network contact. Worth re-checking if a new fixture is added.
3. **Phase 3 finding 2 is mitigated in CI but not fixed in code.** A `pkill -x i2pd` step with `if: always()` cleans up after a timed-out or crashed host, and the runner is ephemeral besides. The kill-on-close job object is still wanted for local runs, where a leaked i2pd holds test ports across sessions.
4. **`.github/scripts/summarise_trx.py` is the reusable half of this batch.** It turns a `.trx` into a job summary and exits non-zero when too few tests executed. Point it at any results directory; `MIN_INTEGRATION_TESTS` sets the floor.

**No production code changed** — this batch is CI configuration only, so the unit suite and the 58-warning Release build are unmoved.

**Next: 3-3** (`p3/loopback-transport-fixture`), then 3-4 (ECIES pump fixture), 3-5 (golden vectors), 3-6 (catch audit, last in the phase).

### Session 3 (continued) — 2026-08-08 — batch 3-3 — PR #18, merged

**The fixture exists and works. SSU2 does not.** Unit suite **243 passed / 0 failed / 1 skipped** (was 239), Release build 0 errors / 58 warnings, both CI jobs green, integration unchanged at 51/48/25/23/3.

**Scope call, agreed with the requester: SSU2 only.** The batch said "same for `NTCP2Session`". `NTCP2Session` calls `TcpClient.GetStream()` in ~10 places across 2019 lines, so a socket-free version needs an injectable `Stream` seam through a file Phases 4 and 9 rewrite — R6 exactly — and it buys little, because NTCP2 runs over TCP and a *lossy* channel is meaningless there. The batch's own verification is entirely about the SSU2 ACK defect. Recorded as optional batch **3-3b**; do it only if an NTCP2 defect actually needs it.

**Gate 3-3 cannot be met, and that is the finding.** The stated gate — "0% loss delivers 100/100; 5% loss currently loses messages" — assumes a working handshake and a data phase to measure. There is neither.

**1. The SSU2 handshake does not complete between two of our own sessions on a lossless in-memory channel.** Bob's host trial-decrypts the header correctly and creates an inbound session — intro keys, header obfuscation and dispatch all work — and then `ProcessSessionRequest` throws `AEAD authentication failed`.

**This is the first thing in the repository to exercise the SSU2 handshake.** `SSU2ProtocolTest`'s 20 tests are constants, header round-trips, fragmentation and ACK bookkeeping; none runs a handshake. The integration suite does not either — SSU2 has been off by default since 0-4, and there is no SSU2 traffic anywhere in the 3-2 integration log. **Treat every "SSU2 works / does not work" claim in this repo's history as untested rather than as evidence.**

**Narrowed, not merely observed.** `NoiseXkWithHeaderTest` pairs the SSU2-only `CreateMessage1WithHeader` / `ProcessMessage1WithHeader` entry points directly: they round-trip, and a one-byte header difference presents as exactly this AEAD error. NTCP2 uses the header-less variants, which is why its passing tests never covered this. So the fault is in `SSU2Session`'s header handling — Alice hashes the plaintext header she built and then encrypts it in place (`SendSessionRequest`), Bob hashes what `DecryptLongHeaderComplete` returns. **Phase 4 should start by diffing those two byte arrays**; the fixture makes that a 280 ms loop instead of a 24-minute one.

**2. SSU2 announces netid 2 regardless of configuration.** `SSU2Session.cs:488` (`SendSessionRequest`) and `:1369` (`SendSessionCreated`) build headers with a literal `NetId = 2`, while `SSU2SecurityValidator.ValidateVersionAndNetId` correctly compares the *received* value against `I2PConstants.I2PNetworkId`. They disagree on every network except the default, so **SSU2 cannot establish a session on any non-default netid**: the responder rejects the initiator's first packet. That includes netid 3, which the safety rule mandates, and netid 99, which the integration suite uses. Any Phase 4 measurement taken on a private network hits this before it reaches ACKs, Retry or anything else. Related: session 2 found inbound NTCP2 never validates the peer's netId at all — netid handling wants one audit across both transports.

**3. SSU2 has no periodic per-session work of any kind.** `SSU2Host.ProcessSessions` only reaps terminated sessions, and the worker loop calls nothing else per session. **Batch 4-1's scope is written against a session tick that does not exist** ("GenerateAck() on session tick; drive retransmit from GetPacketsNeedingRetransmit()"). 4-1 has to add the tick, and the loopback fixture then has to drive it between pumps.

**Production seams added to `SSU2Host` (48 lines, mostly comment).** An `internal` constructor that binds no socket and starts no thread, taking `RouterContext` and static keys per instance; `SendPacket` made `virtual`; `DispatchPacket` made `internal`. The key injection is load-bearing, not convenience: `InitializeStaticKeys` loads **one SSU2 keypair for the whole process**, so two hosts built the normal way are the same peer and cannot hand-shake at all. `DispatchPacket` is used rather than hand-building an inbound session so the fixture exercises real trial decryption and session creation instead of its own wiring.

**Design notes worth keeping:**

- `LossyChannel` is **thread-free and seeded**. `Send` enqueues, `Pump` delivers, impairments come from a seeded `Random`. A protocol test that flakes trains people to re-run it; this one cannot. Preferring it to a real socket pair on 127.0.0.1 is deliberate — loopback UDP essentially never drops, so it cannot exercise retransmission at all.
- `FixtureDeliversTheSessionRequestToAnInboundSession` is green **on purpose**: it proves the red tests fail on the handshake rather than on the harness. Phase 2's lesson was that the obvious lifecycle test passes against unfixed code; the counterpart here is a fixture that fails for its own reasons and gets blamed on the protocol.
- The four red tests are `[Category(Experimental)]` naming Phase 4 as owner, per the `TestCategories.Experimental` convention. The unit suite stays green.

**Size:** ~700 lines of test code against the 400-line rule, with 48 lines of production code. Not split — the channel, the peer harness and the tests cannot be verified separately, and much of the bulk is doc comments carrying the three findings above.

**Next: 3-4** (`p3/ecies-pump-fixture`), then 3-5 (golden vectors) and 3-6 (catch audit, last in the phase). Given finding 1, **3-5's SSU2 golden vectors just became more valuable than planned** — a captured i2pd SessionRequest is the reference that says whether our header construction or our header hashing is the wrong one.

### Session 3 (continued) — 2026-08-08 — batches 3-4 and an unplanned key-padding fix — PRs #19, #20, both merged

**Unit suite 249 passed / 0 failed / 1 skipped** (was 243), Release build 0 errors / 58 warnings, both CI jobs green.

#### 3-4 — ECIES pump fixture (PR #19)

**ECIES works.** In sharp contrast to SSU2 in 3-3: New Session and New Session Reply both complete, both carry their payloads, and traffic flows in both directions. **No production code needed changing** — `ECIESSessionKeyManager`'s public API was already sufficient. Worth saying plainly against the README's blanket pessimism: the ECIES handshake is not one of this project's broken parts.

**The 5-3 defect reproduces exactly as the plan predicted:**

```
delivered 5000 of 100000 before stopping: InvalidOperationException: No available outbound tags
```

`ECIESSession.InitializeBiDirectionalTags` pre-generates exactly `TagsPerDirection` = 5000 tags per direction at handshake time and never generates another. At 1 KB per message that is roughly **5 MB before a destination stops being able to speak** — under half of Gate 5's ">10 MB sustained, no session reset".

**What the plan does not say, and what it cost.** A responder does **not** reply inside `ProcessMessage`. That call only decrypts the payload and records a pending handshake; the reply is a separate explicit `CreateHandshakeReply(remoteHash, originalNewSessionBytes, replyPayload)` that `Session.cs:257` makes when it next has something to send. A fixture that skips it sees `success=True` on the New Session, no reply bytes, and **no session tags ever created** — and would file that as a tag-generation bug. The first spike did exactly that. Anyone driving ECIES by hand needs the three-step exchange.

Related asymmetry, kept rather than hidden: the initiator addresses the responder by its real `I2PIdentHash`, but the responder identifies the initiator by `SHA256(static key)`, because a New Session carries a static key and not a destination. Production reconciles it later via `ConfirmRemoteHash`.

Two deliberate test choices. The exhaustion test runs to **100000**, not the plan's 5001, so a "fix" that merely enlarges the fixed block rather than making a real sliding window still fails. And `TheTagWindowIsExactlyTheGeneratedTagCount` asserts today's buggy boundary on purpose — **it is meant to go red when batch 5-3 lands**, turning that change from silent into deliberate. Updating one assertion is the intended cost; do not just delete it.

#### Unplanned: derived public keys were not padded to fixed width (PR #20)

**The `GarlicTest.TestEncodeDecodeLoop` flake was never a flake.** Session 1 saw it once, could not reproduce it in fourteen runs, and left it open. It failed CI again on PR #19, and the cause is a real defect in key derivation.

`I2PPublicKey` derived ElGamal keys with `BigInteger.ToByteArrayUnsigned()`, which drops leading zero bytes. A key whose most significant byte happens to be zero comes out **255 bytes instead of 256**. I2P public keys are fixed width, so a short key shifts every field after it in the serialised `Destination` and the reader recovers a corrupt group element — `"y value does not appear to be in correct group"`.

| derivation | short keys, unfixed |
|---|---|
| ElGamal2048 public | 8 of 3000 |
| DsaSha1 signing public | 13 of 3000 |

About **one in 256**. Every destination made with the default key type is affected — `I2PDestinationInfo(signkeytype)` defaults to ElGamal2048 — so this was a live router defect, not a test problem.

Three sites fixed, all switched to the existing `BufUtils.ToByteArray(bi, length)`, which already left-pads: `I2PPublicKey.cs:19` (ElGamal derivation), `I2PPublicKey.cs:92` (`I2PPublicKey(BigInteger, I2PCertificate)`), `I2PSigningPublicKey.cs:20` (DSA derivation).

**The asymmetry that hid it:** the codebase already knew. `I2PSigningKey(BigInteger, I2PCertificate)` — the direct counterpart of the second site — has always padded, and `I2PSignature` pads `r` and `s` with a comment quoting the spec. Only the derivation paths were missing it, so nothing read as obviously wrong.

**Lessons worth carrying:**

1. **"Rare, randomised, unreproducible" is a hypothesis, not a diagnosis.** Session 1 ran the failing test 14 more times and concluded little. What settled it in minutes was generating 3000 keys and *counting* — testing the suspected mechanism directly instead of re-rolling the dice. Do that with the next intermittent failure.
2. **Population tests, not repeat runs.** The regression tests generate 2000 keys each; a single run catches a one-in-256 defect 0.4% of the time, which is exactly how it survived two sessions.
3. **A round-trip test was written and then deleted** — it passed with the defect reinstated, so it guarded nothing. Both surviving tests were confirmed to fail against the unfixed code. Phase 2's vacuous-test lesson still applies to every batch.
4. **Grep for the pattern, not the symptom.** `ToByteArrayUnsigned()` appears at ~17 sites. The signature ones already pad; `Elligator2.cs:179`, `BlindedPublicKey.cs:590,600` and `ElGamalCrypto.cs:94` were not audited here and are worth a look in Phase 10.

**CI note.** This is the first time the trx artifact from the `build` job was used to diagnose a failure — `gh run download -n unit-test-results` plus `.github/scripts/summarise_trx.py` names the failing test and its message without reading the log. Batch 3-2 built that for the integration job; it works for the unit job too.

**Next: 3-5** (`p3/i2pd-golden-vectors`), then 3-6 (catch audit, last in the phase). 3-5 matters more than the plan implies now: 3-3 showed our SSU2 SessionRequest cannot be read by our own responder, and a captured i2pd SessionRequest is the reference that says whether our header *construction* or our header *hashing* is the wrong side.

### Session 3 (continued) — 2026-08-08 — batch 3-5 — PR #21, merged

**Unit suite 251 passed / 0 failed / 1 skipped** (was 249), Release build 0 errors / 58 warnings, both CI jobs green. Integration **52 total / 49 executed / 26 passed / 23 failed / 3 skipped** — one test added (the capture producer, passing), the 23 failures and their signatures unchanged from 3-2.

The batch's own verification says *"round-trips pass, or fail with a byte diff — either is information."* It produced two findings, and **neither is the one it went looking for.** It set out to adjudicate the 3-3 handshake failure; it instead found a defect 3-3 could not have seen, and did not explain the one it was sent to explain.

#### 1. Our SSU2 header encryption uses the wrong ChaCha20 block

Production decryption run against a header i2pd really sent recovers **version 27, netid 27** where 2 and 99 are correct. Scanning 128 bytes of key stream for the offset that decodes correctly finds **exactly one match, at byte 64** — the start of the second ChaCha20 block.

i2pd's `ChaCha20()` helper calls `Chacha20Init(state, nonce, key, 1)`, i.e. **counter 1**. `SSU2HeaderEncryption.GenerateChaCha20Mask` uses BouncyCastle's `ChaCha7539Engine` from its initial state, which is counter 0. The nonce agrees; only the block differs.

**No SSU2 header we produce can be read by i2pd, and none of i2pd's can be read by us.** That is an outright interop blocker for all of Phase 4, so it is now batch **4-0** and runs before 4-1.

**Why nothing caught it.** Both ends of a C#-only exchange use block 0, so it is perfectly self-consistent: every existing test passes, and 3-3's loopback fixture gets all the way to the Noise layer before failing. **A protocol implementation cannot detect a convention error by talking to itself** — this is the concrete cost of having had no reference peer until 3-1, and the clearest argument yet for golden vectors over more fixtures.

It is also **separate from the 3-3 AEAD failure**, which is C#-to-C# and this does not explain. 3-3's "diff the two byte arrays" lead still stands, untouched. Two SSU2 defects, not one.

#### 2. i2pd opens with a TokenRequest, not a SessionRequest

The first packet is 69 bytes (73 on another run — padding varies), decoding to type **10**, version 2, netid 99. Nothing in this repository handles that message type. A C# router must answer a TokenRequest with a Retry before i2pd will ever send a SessionRequest, so an *inbound* SSU2 session from i2pd cannot begin at all. Batch 4-2's scope is widened accordingly — it was written as though we only need to *receive* Retry as an initiator.

#### Scope: SSU2 only, and the rest is blocked rather than skipped

The batch also lists SessionRequest, Retry, Data-with-ACK and ECIES NS/NSR/ES. Retry and Data cannot be captured until we can answer a TokenRequest (finding 2) — the capture harness never gets a second packet out of i2pd. ECIES vectors need a destination, tunnels and a LeaseSet driven through i2pd, which the integration suite cannot currently do (19 of its 23 failures are fixture-level, per 3-2). The harness is reusable for all of them once those unblock; **capture them as the batches that unblock them land, not as a later catch-up batch.**

#### Decisions recorded in-code

- **Vectors are `key=HEX` text, not a binary container.** They diff readably in review, they grep, and the parser is twenty lines. A binary format brings its own bugs to a file whose entire purpose is being trusted.
- **The vector is checked in, so the tests over it are ordinary unit tests** — no i2pd, no network, no ports. `SSU2GoldenVectorCapture` is a separate Integration-category *producer* that refreshes it. This is the pattern to copy: capture is expensive and flaky, reading a captured byte string is neither.
- **`I2pdHeaderMaskComesFromChaCha20BlockOne` is the durable test, not the red one.** It asserts a fact about i2pd, so it stays green after 4-0 corrects `SSU2HeaderEncryption` — a later regression moves it rather than silently passing. The red `OurHeaderDecryptionCanReadI2pdsHeader` is quarantined `[Category(Experimental)]`, owner Phase 4, and is the one 4-0 flips.
- Capture keys are throwaway, generated for the capture and committed alongside it, so the vector is self-contained and decodable by anyone.

#### Note for whoever fixes 4-0

`SSU2HeaderEncryption` cites "SSU2 spec lines 761-798" of a document **not in this repository**. Re-derive from the published spec and i2pd's source; do not trust those line references. Batch 9-1 already carries the same problem with its "ntcp2-hybrid.md line 363" citations — this is a repo-wide habit, and a citation to a file nobody has is worse than none.

**Next: 3-6** (`p3/catch-audit-protocol-scope`), last in the phase, and then Gate 3. Phase 4 starts at the new **4-0**, then the fixture NRE and SAM-bridge startup that 3-2 flagged (19 of 23 integration failures are downstream of those two), then 4-1.

### Session 3 (continued) — 2026-08-08 — batch 3-6 — PR #22, merged — **Phase 3 complete**

**Unit suite 254 passed / 0 failed / 1 skipped** (was 251), Release build 0 errors / 58 warnings, both CI jobs green, integration unchanged at 52/49/26/23/3.

All 31 catch sites in `TransportLayer/SSU2/` and `SessionLayer/ECIES/` audited against one rule, which is written out on `ProtocolCatchAuditTest` rather than left implicit in the diff: a catch must **log at Warning+ passing the whole exception**, **propagate to a caller that logs it** (with the exception type in the propagated string and a comment naming that caller), or **be an expected outcome** — Debug, still carrying the exception, with a comment saying why it is expected and what recovers.

**Two catches were silent by construction, and both sit on defects this plan already tracks.**

1. `ECIESRouterProcessor.SendMessage` swallowed `InvalidOperationException` under the comment "No tags available or session expired". That is batch **5-3**'s tag exhaustion — the thing 3-4 measured as `delivered 5000 of 100000`. Swallowed, it presents as nothing worse than "this peer re-handshakes a lot", which is a plausible-looking symptom nobody would chase.
2. `ECIESRouterProcessor.ProcessMessage` returned `Success = false, Error = ex.Message`, and its only caller (`Router.HandleGarlic:771`) checks `Payload == null` and **never reads `Error`**. The exception had nowhere to go at all.

**Checking the caller is what made the difference.** Six catches in ECIES return a structured error instead of logging, and that is a legitimate pattern — but only if someone reads it. Four of them are read (by `SessionManager.DecryptMessage`) and two were not. The two are indistinguishable from the four by looking at the catch alone. **Verify propagation by reading the consumer; do not accept "it returns an error object" as evidence that the error surfaces.**

**Other changes worth naming:**

- `ECIESRouterSKM.ExtractTag` logged at Debug and then silently used the **unparsed bytes as the payload**, so a parse failure produced garbage one layer further on with the cause already gone. Now Warning with the exception.
- `SessionConfirmed.ParsePart2Payload` logged at Debug, leaving `RouterInfo` null and the handshake proceeding without ever learning who the peer is. Downstream that reads as "the peer sent none" rather than "we could not read the one it sent" — the exact ambiguity behind the integration suite's `i2pd RouterInfo should be in our NetDb` failure.
- `SSU2Host.ProcessIncomingPackets`'s `catch (SocketException)` → "ignore" sits **outside** the receive loop, so it abandons every pending datagram. Now Debug when `Terminated` (shutdown closes the socket, which is routine) and Warning otherwise.
- `SSU2Host.Run` logged "Fatal error" at **Warning**. Reaching it ends SSU2 for the life of the process and nothing restarts it. "Fatal" was accurate; the level was not.

**Unplanned: `Logging.LogError` did not exist.** `LogLevels.Error` has been in the enum throughout and is selectable as `--log-level error`, but no helper ever emitted at it — so the level was unreachable from library code and that setting showed Critical only. Added, because Warning understates "this transport is now dead" and Critical passes *every* threshold including `Nothing`. **Worth checking whether other advertised levels are equally unreachable.**

**`ECIESGarlicProcessor` is confirmed dead** — the type name appears nowhere outside its own file, in library or tests. Its two catches breach the rule and were left alone with a header note saying so, because 5-1 deletes the file and tidying an unreachable path only makes it look maintained. **If 5-1 decides to keep the class, its error handling has to be brought up to the directory standard first.**

**Test honesty.** Both guards were confirmed to fail with the defect reinstated (a bare catch → `SSU2Session.cs:297`; a bound-but-unused `ex` → `SSU2Session.cs:212`). The second guard exists because `EveryCaughtExceptionIsUsed` is the loophole the first one pushes people towards. A third, `TheAuditActuallyScansSomething`, asserts the scan finds >15 files and >20 catch sites — without it, a moved directory would make both checks pass by scanning nothing, which is batch 2-7's "green suite that covers half of itself" at fixture scale.

#### Gate 3 — met, with one part of batch 3-2's promise deferred

| Gate 3 clause | status |
|---|---|
| `TestCategory=Integration` *runs* in CI against real i2pd | ✅ 3-1 + 3-2 — 49 of 52 executing, ~23 min, pinned i2pd 2.61.0 |
| Fixtures reproduce the SSU2/ECIES defects as red tests | ✅ 3-3 (4 red SSU2), 3-4 (ECIES tag exhaustion), 3-5 (1 red header-encryption) |

**What is *not* done, and should not be done yet.** `.github/workflows/dotnet.yml:57` says "Gate 3 removes the continue-on-error and starts gating on results too". **Do not do that now.** 23 integration tests still fail, so removing that line makes `github-master` permanently red and breaks the plan's own "merge only when green" rule for every subsequent batch. Gating on results becomes possible when Phase 4 has fixed the fixture NRE and the SAM-bridge cluster — i.e. after **4-1**, not before. The comment in the workflow now overstates what Gate 3 can deliver; treat that line as belonging to Phase 4.

**Phase 3 scoreboard:** 3-1 ✅ 3-2 ✅ 3-3 ✅ (3-3b deferred, optional) 3-4 ✅ 3-5 ✅ 3-6 ✅

**Next: Phase 4, starting at 4-0** (`p4/ssu2-header-chacha-block`) — the ChaCha20 block-counter fix from 3-5, which blocks every SSU2 interop measurement. Then the fixture NRE and SAM-bridge startup (19 of 23 integration failures are downstream of those two, and until they are fixed the suite cannot report on SSU2 or ECIES at all), then 4-1's ACK wiring — which per 3-3 must also **add the per-session tick it is written against**, because `SSU2Host.ProcessSessions` only reaps terminated sessions today.

Two independent SSU2 defects are on the table for Phase 4 and neither explains the other: the **header block counter** (3-5, C#-to-i2pd) and the **SessionRequest AEAD failure** (3-3, C#-to-C#). Also still open from 3-3: `SSU2Session.cs:488` and `:1369` build headers with a literal `NetId = 2`, so SSU2 cannot establish on netid 3 or 99 at all.

### Session 4 — 2026-08-08 — batch 4-0 — PR #23, merged

**Unit suite 256 passed / 0 failed / 1 skipped** (was 254), Release build 0 errors / 58 warnings, both CI jobs green. Integration **52 total / 49 executed / 26 passed / 23 failed / 3 skipped** — unchanged from 3-5/3-6, and expected to be: 4-0 fixes a C#-to-i2pd convention, and no integration test exercises SSU2 against i2pd today.

The batch itself is small and its reasoning is in the file: `GenerateChaCha20Mask` discards one 64-byte block so the keystream starts at block 1, matching i2pd. The two findings below are what the session added on top.

#### 1. Batch 3-3's AEAD failure and the i2pd header divergence are the same defect

Session 3 signed off saying "two independent SSU2 defects are on the table for Phase 4 and neither explains the other." **That is now wrong, and it is recorded as batch 4-0b.** Re-deriving the header convention from i2pd source to fix the block counter surfaced the wider divergence, and it accounts for both symptoms:

- i2pd encrypts packet bytes 16..64 as **one 48-byte ChaCha20 pass** for Session Request and Session Created. We use two restarted keystreams, so the ephemeral key gets keystream bytes 0..32 where i2pd uses 16..48.
- `SessionRequest.ToByteArray` calls `EncryptLongHeaderInPacket`, which stops at byte 16 — so header bytes 16-31 (source connection ID, token) are **transmitted in the clear**.
- The sender masks bytes 0-15; `SSU2Host.DispatchPacket` unmasks 0-31. The receiver therefore XORs 16 bytes the sender never masked, the header Bob hashes differs from the one Alice hashed, and the Noise AEAD tag fails. That is 3-3's C#-to-C# failure exactly.

Measured, not inferred: switching that one call to `EncryptLongHeaderComplete` takes the 3-3 loopback fixture from `sent=1` to `sent=2`. **It was deliberately not applied.** The correct fix is the single 48-byte pass, which subsumes the interim one, and there is no captured i2pd Session Request to verify it against until 4-2 lets us answer a TokenRequest. Landing the interim form would be merging a protocol change behind a test that only agrees with itself — the failure this plan keeps rediscovering. `Ssu2HeaderLayoutTest` pins the divergence as three tests: one green (asserting i2pd's convention) and two quarantined red, owner 4-0b.

**Phase 4 was about to spend a session treating these as two separate bugs.** Batch order changes accordingly: 4-2 before 4-0b, because 4-2 produces the reference bytes 4-0b needs.

#### 2. The test harness resets the process to netid 2 — the live network

`CSharpRouterHarness.Start()` sets `I2PConstants.I2PNetworkId = 99` and `Bootstrap.Disabled = true` (`:89`, `:92`). `Stop()` restores them to `I2PNetworkId = 0x02` and `Bootstrap.Disabled = false` (`:258-259`) under the comment "Restore defaults only when we own the router".

**Netid 2 is the live I2P network, and that restore also switches reseed back on.** These are process-wide statics in a test host that runs many fixtures in one process, so any router started afterwards that does not go through `Start()` inherits live-network settings. `ScaledNetworkFixture` has exactly such a path: when `TestNetworkFixture.CSharpRouter != null` it reuses that router (`:115-127`) and never calls `Start()`, so it never sets the netid and never disables Bootstrap.

Nothing observed has actually reached netid 2 — the fixtures that matter all run through `Start()` first. It is a latent violation of the plan's own non-negotiable rule 5, not a demonstrated live-network connection, and it should be fixed before it becomes one. The right shape is almost certainly to stop restoring these at all: there is no correct "default" for a test process to fall back to, and 0x02 is the worst available choice.

#### 3. The 11-test NRE is an ordering dependency, and does not reproduce standalone

Running `ExploratoryTunnelsShouldBeBuilt` on its own, locally, against i2pd 2.61.0: **the 10-router network starts in 113.5s and the test passes.** No NRE. The suspicion recorded in 3-2 — that the SAM-bridge cluster is collateral from a fixture that crashed earlier in the run — now has direct support, and the mechanism is visible in the code.

`TestNetworkFixture` (namespace `I2PTests.IntegrationTests`) and `ScaledNetworkFixture` (namespace `I2PTests.ScaledNetwork`) are separate `[SetUpFixture]`s. Running one ScaledNetwork test alone, `TestNetworkFixture.CSharpRouter` is null, so `ScaledNetworkFixture` takes its **else** branch and builds its own harness — which works. In a full CI run `TestNetworkFixture` has already run, so it takes the **reuse** branch, which assumes a router another fixture owns and may already have stopped.

**Do not fix this by reading the code.** The CI failure carries no stack trace — 11 tests report a bare `OneTimeSetUp: SetUp : NullReferenceException`, and `ScaledNetworkFixture.cs:99` logs the real exception only to `/tmp/i2p_scaled_test.log`, which is not collected as an artifact. There are at least four plausible null sites in the reuse branch. **Step one of that batch is making the failure legible** — attach the exception to the fixture failure and/or collect that log file in CI — and only then fix what it names.

#### Tooling note

The integration `.trx` **is** in the CI artifacts, and `.github/scripts/summarise_trx.py` renders the six failure signatures and the exact failing-test list from it in one command. Reaching for the 1356-line job log first was wasted effort. `gh run download <id> -n integration-test-results` then summarise; the job log only adds value when you need a stack trace, and in this case it did not have one either.

**Next: batch 4-2** (`p4/ssu2-retry-token`) — it is now on the critical path for two reasons rather than one: it unblocks inbound SSU2 from i2pd, and it produces the captured Session Request that 4-0b needs. The fixture-NRE/SAM-bridge work should be split into its own batch before or alongside it, starting with diagnosability rather than a fix. **4-0b comes after 4-2, not before.**

### Session 4 (continued) — 2026-08-08 — batch 4-0c — PR #24, merged

**Unit suite 260 passed / 0 failed / 1 skipped** (was 256), Release build 0 errors, both CI jobs green. Integration **52 total / 49 executed / 29 passed / 20 failed / 3 skipped** (was 26/23). i2pd 2.61.0, all routers on netid 99.

#### The defect: three fixtures reused a router that was already stopped

`TestNetworkFixture`, `ScaledNetworkFixture` and `MultiHopTestFixture` each decided whether they could reuse the shared in-process router by testing `TestNetworkFixture.CSharpRouter != null`. Teardown disposes the router but leaves the static reference set, and `Router.Stop()` → `NetDb.Stop()` sets `NetDb.Inst = null`. **The check stayed true for a router that no longer existed.** `[SetUpFixture]`s in other namespaces run after that teardown, so `ScaledNetworkFixture` reused a dead router and died inside `NetDb.Inst.AddRouterInfo`.

It never reproduced standalone — run one ScaledNetwork test alone and the reference really is null, so the fixture builds its own router and the 10-router network comes up in 113.5s. **"Works alone, fails in the suite" was the whole signature**, and it is worth reading as "shared process state" on sight.

Fixed with `CSharpRouterHarness.IsRunning`, which asks the singletons rather than the object; all three call sites branch on it, and teardown now drops the reference with the router.

#### Two sessions were lost to a diagnosability gap, not a hard bug

The `.trx` carries a `StackTrace` next to every failure `Message`. `summarise_trx.py` only ever read `Message`. **The file and line were in the CI artifact the entire time** — 3-2 recorded these as an opaque `NullReferenceException`, 4-0 went digging through a 1356-line job log that did not contain the trace either, and printing the existing field named the defect in one command. The summariser now prints the repo's own frames per failure.

This is the second time this plan has paid a session for missing observability rather than for a hard defect (the first being 0-1's Release logging). **When a failure is unreadable, fix the reporting before fixing the code** — it is nearly always cheaper than the investigation it replaces.

#### The count barely moved and that is the wrong measure

23 → 20 failures, but **all 11 `NullReferenceException`s are gone** and the integration job went from 23m to **36m55s**. The 11 tests that used to die in `OneTimeSetUp` now run and do real work, and three report protocol defects the suite has never before been able to measure:

- `TestSend5MB_I2pd0_To_I2pd1` — **SHA-256 mismatch**, i2pd → i2pd with C# routers as tunnel hops
- `TestSend5MB_I2pd2_To_I2pd3` — **SHA-256 mismatch**
- `LeaseSetLookupAndEncryptionVerification` — LeaseSet lookup does not succeed

Data corruption with C# as a participating hop is a Phase 6 finding that arrived early. **Do not judge a fixture-repair batch by the failure count** — 3-2's "23 failures are six signatures, and mostly not protocol defects" framing was right, and the corollary is that fixing them raises the count of *meaningful* failures while barely moving the total.

#### A prediction made during the batch, and refuted by it

The guard test found `MultiHopTestFixture` carrying the same defect, and since four of the eight SAM-bridge failures are MultiHop tests, this session predicted the SAM cluster shared the root cause. **It does not.** SAM failures persist and now also appear on port **29102** — `PortAllocator.Scaled.Cs0Sam`, the router `ScaledNetworkFixture` now correctly starts for itself. `CSharpRouterHarness.Start()` wraps SAM startup in a `catch` that logs a warning, and that warning does not appear, so the bridge is not throwing — it simply never accepts a connection. **This is a separate defect and needs its own batch** (~13 tests).

#### Unplanned: the harness restored the process to the live network

`Stop()` restored `I2PConstants.I2PNetworkId = 0x02` and `Bootstrap.Disabled = false`, commented "restore defaults". Netid 2 is the live I2P network and that second line switches reseed back on, in process-wide statics that outlive the fixture that set them. Nothing observed reached netid 2, so this was latent rather than realised — but it is a breach of rule 5 sitting in the one place the rule most needs to hold. Nothing is restored now: **a test process has no legitimate non-test consumer of those globals, and 0x02 is the worst available choice of default.**

**Next: the SSU2 netid batch, then 4-2.** Scoping during this session found the hardcoded-netid problem is **five sites, not the two** 3-3 recorded: `SSU2Session.cs:496` and `:1382`, `SSU2RelayHandler.cs:990`, `Messages/SessionRequest.cs:27` (commented "I2P mainnet") and `Messages/SessionCreated.cs:25`. Meanwhile `SSU2SecurityValidator.cs:87` and `SSU2Helpers.cs:136` both validate against `I2PConstants.I2PNetworkId`. **The send path is pinned to the live network while the receive path honours configuration, so SSU2 rejects its own traffic on netid 3 or 99** — every SSU2 test runs on 99 and the plan mandates 3 for local work, so nothing in Phase 4 is measurable until this lands. It is small, and it comes before 4-2.

### Session 4 (continued) — 2026-08-08 — batch 4-0d — PR #25, merged

**Unit suite 266 passed / 0 failed / 1 skipped** (was 260), Release build 0 errors, both CI jobs green. Integration **29 passed / 20 failed** — unchanged, and expected to be: 4-0d removes a precondition failure, it does not complete a handshake. Nothing flips green until 4-2 and 4-0b land.

Five sites built SSU2 headers with a literal `NetId = 2` while `SSU2SecurityValidator.cs:87` and `SSU2Helpers.cs:136` validated against `I2PConstants.I2PNetworkId`. **The send path was pinned to the live network while the receive path honoured configuration, so SSU2 rejected its own traffic on any netid but 2** — and rule 5 forbids netid 2, integration runs on 99. No SSU2 handshake could complete on any netid this project is permitted to use.

3-3 recorded two sites. Grepping for the pattern rather than the symptom found five — the same lesson the ElGamal padding fix recorded in session 3, now with a second data point. `Messages/SessionRequest.cs` stated the assumption outright as `// I2P mainnet`.

**A guard test caught its own author.** The first version scanned for the substring `NetId = 2` and flagged `SSU2Blocks.cs`, which declares the termination reason `WrongNetId = 21`. It is a regex with a lookbehind now. A source-scanning guard is code, and gets the same scepticism as the code it guards.

#### Found while investigating the SAM cluster: `Router.Start()` starts client services before any host can configure them

Not fixed here — it is the next batch, and it is **a production defect, not a test one**.

`Router.cs:125` calls `ClientContext.Inst.Start()`. Every host app configures `ClientContext` *after* `Router.Start()` returns, and `ClientContext.Start()` opens with `if (IsRunning) { LogWarning("Already running."); return; }`. **The configuration is applied to a thing that already started, and is silently discarded.** Measured locally:

```
SAMBridge: Listening on 127.0.0.1:7656
ClientContext: SAM bridge started on port 7656.
SAM bridge started on port 29002      <- the harness printing its intent, not what bound
ClientContext: Already running.
```

Defaults are all enabled — SAM **7656**, HTTP proxy **4444**, SOCKS **4447**. `I2PRouterCli/Program.cs` calls `Router.Start()` at `:324` and sets SAM/HTTP/SOCKS config at `:354-374`, so for a real user:

- `--sam-port N` is ignored; SAM listens on 7656.
- `--http-proxy-port N` is ignored; the proxy is on 4444.
- `--sam-port 0`, which the CLI treats as *disable SAM*, **leaves SAM listening**.
- The comment "Disable SOCKS to avoid port conflicts" does not; SOCKS stays on 4447.
- The CLI prints "SAM bridge enabled on port {samPort}" and "HTTP proxy started on 127.0.0.1:{httpProxyPort}". Both are false.

There is a safety edge as well. `CLAUDE.md` says test ports use 29000-29099 "to avoid colliding with a live local I2P router", but every test run binds 7656/4444/4447 regardless — so the suite *does* collide with a local I2P install, and a service the operator asked to disable is listening anyway.

This is a Phase 0 safe-defaults and Phase 7 config-unification defect that also happens to cost 13 integration tests. **Fix the discarding, not just the call order** — moving the host's `SetConfig` calls earlier repairs the two hosts in this repo and leaves the trap set for the next one. A `Start()` that silently ignores configuration is the actual bug.

**Next: 4-0e** (`p4/clientcontext-config-before-start`), then **4-2**, then **4-0b**, then **4-1**.

### Session 4 (continued) — 2026-08-08 — batch 4-0e — PR #26, **merged with CI red**

> **⚠️ `github-master`'s integration job is RED as of this batch, and batch 4-0f owns it.**
> The test host crashes part-way through the run, so the 11 ScaledNetwork tests never execute
> and batch 3-2's `MIN_INTEGRATION_TESTS` floor fails the job. **This breaks the plan's
> "merge only when green" rule for every batch after it.** Until 4-0f lands, judge a batch by
> the unit suite plus the integration `.trx` numbers, and compare failures against this
> baseline rather than expecting a green job.

**Unit suite 270 passed / 0 failed / 1 skipped** (was 266), Release build 0 errors, build job green, integration job red.

#### The defect, which is a production one

`Router.cs:125` calls `ClientContext.Inst.Start()`, and `ClientContext.Start()` began with `if (IsRunning) { LogWarning("Already running."); return; }`. Every host configures `ClientContext` *after* `Router.Start()` returns, so the services came up on their defaults and every `SetConfig` afterwards was applied to an already-started object and discarded. For a user of `I2PRouterCli`:

- `--sam-port N` and `--http-proxy-port N` did nothing; SAM listened on 7656, the proxy on 4444.
- `--sam-port 0`, which the CLI treats as *disable SAM*, **left SAM listening**.
- "Disable SOCKS to avoid port conflicts" did not; SOCKS stayed on 4447.
- Both hosts printed the ports they had asked for, having bound others.

`CLAUDE.md` claims test ports avoid 29000-29099 so as not to collide with a live local I2P router; every run bound 7656/4444/4447 anyway.

**Verified by measurement**, not review: the bridge moved from 7656 to the configured 29002, disabled services stay down, and every "failed to connect to the SAM bridge" failure is gone from the integration suite — those tests now fail at `CANT_REACH_PEER`, i.e. they reach real I2P routing for the first time.

Reconciliation lives in each `StartX()` rather than in `Start()`, because `I2PRouterWeb`'s `RouterService.StartHttpProxy` calls `StartHTTPProxy()` **directly**; a `Start()`-only fix would have repaired the CLI and left the web console unable to move a port. **Fixing only the call order in the two hosts here would have left the trap armed for the next one.**

#### Three CI attempts, and what each one actually taught

| run | outcome | what preceded the crash |
|---|---|---|
| 1 | 41 of 52 in the report | `TestSend5MB_ECIES_X25519` hit `CancelAfter`, then the host died |
| 2 | 40 | quarantined that test; `TestSend5MB_CSharpToI2pd_SAM` hit `CancelAfter`, host died |
| 3 | 36 | quarantined all five 5 MB SAM transfers; **no timeout at all** — 5.5 min of silence after the last SSU2 test, then a hard process death |

So there are **two separate causes**, and the quarantine addressed only the first:

1. `[CancelAfter(n)]` cancels a `CancellationToken` NUnit passes **as a test-method parameter**, and none of the 23 tests carrying the attribute declares one. The timeout marks the test failed while its thread runs on; the orphans take the host down.
2. Something in fixture teardown or the namespace transition kills the process outright. `ScaledNetworkFixture` never logs a line — an earlier green run has 40 such log lines, this run has zero — so the crash lands before its setup produces output. No OOM signal.

**The hangs themselves are not a regression.** Before this batch those tests failed in seconds on a SAM connect that never succeeded; with the bridge bound they get far enough to stall on the streaming layer Phase 5 repairs. 4-0e converted fast failures into slow ones and thereby exposed a pre-existing landmine.

**A hypothesis was formed and then refuted mid-batch**, which is worth recording as much as the finding: cause 1 was assumed to explain everything, and run 3 disproved it. Quarantining tests one at a time is what let that assumption survive two runs — *the third failure is the signal to stop treating symptoms*, and it should have come sooner.

#### Merging red was a deliberate exception, taken by the maintainer

The plan's rule 4 says stop and report rather than merge a partial fix. That was done: the options were put to the maintainer, who chose to land 4-0e and revert the quarantine. The reasoning recorded here so it is not mistaken for drift: the production defect is real, verified and unrelated to the crash; the crash is a fixture problem that predates this batch; and holding a correct fix behind an unrelated failure helps nobody. **The quarantine was reverted** because hiding five tests bought only cause 1 and cost real visibility.

The CI integration filter keeps the new `TestCategory!=Experimental` exclusion, which the unit filter always had. Quarantine should mean quarantined everywhere — and it matters most for integration tests, which get quarantined precisely because of *how* they fail.

**Next: 4-0f is now the highest priority in Phase 4**, because until the integration suite completes, no later batch can be measured — and Phase 4's remaining batches (4-2, 4-0b, 4-1) are exactly the ones whose verification lives in that suite.

### Session 4 (continued) — 2026-08-08 — Phase 4 scoping, four parallel agents

No code merged in this step. Four scoping passes over 4-0b, 4-1, 4-2 and the 4-0f crash. **Every claim recorded below was re-verified directly before being written down** — session 4 had already had one hypothesis refuted by CI, and agent output gets the same scepticism as a test that only agrees with itself.

#### The golden vector decodes completely, and that settles more than 4-0 claimed

`TestData/ssu2_tokenrequest_i2pd.txt` was captured by 3-5 as a header sample. It is a whole packet, and it **fully authenticates**. Verified here with an implementation independent of this repository (Python `cryptography`, not `SSU2HeaderEncryption`):

```
header:  2229AB362729443526427CF60A026300 D0B4B204E03B0498 0000000000000000
         type=10 version=2 netid=99 token=0
payload: DateTime(0x6A76FD4C) + Padding(11)     <- Poly1305 tag VERIFIED
```

with key = the responder intro key, **AD = all 32 plaintext header bytes**, nonce = 4 zero bytes ‖ 8-byte little-endian packet number.

**A verifying Poly1305 tag over that AD proves all 32 header bytes were recovered exactly as i2pd wrote them.** `Ssu2GoldenVectorTest` only asserts type/version/netid — three bytes. So this confirms, byte-exact against i2pd 2.61.0:

- bytes 0-7 ← ChaCha20(intro key, nonce = `packet[len-24..len-12]`), **block 1**
- bytes 8-15 ← ChaCha20(intro key, nonce = `packet[len-12..]`), **block 1**
- bytes 16-31 ← ChaCha20(intro key, **zero nonce**), block 1, **one 16-byte pass**
- `ChaCha20Poly1305.CreateNonce` is already correct

**Consequences.** 4-0's block-counter fix is now confirmed against real bytes rather than inferred from an offset scan. And 4-0b is *constrained*: the 16-byte form is right for TokenRequest and Retry, so **4-0b may only change the region past byte 32, and must not touch the Retry path** — if it needs a 48-byte variant it must be a new method, not an edit to the existing one. The vector is a stronger asset than 3-5 knew; **the checked-in TestData deserves a fuller test than the one guarding it.**

#### Verified defects found while scoping, now batches of their own

- **4-0d was incomplete.** `SSU2Constants.NETWORK_ID = 2` is written raw as `header[14] = SSU2Constants.NETWORK_ID` (`SSU2RelayHandler.cs:1163`), and `Ssu2NetIdTest`'s regex sees neither the constant nor an indexed write. `NTCP2Constants.cs:27` declares the same literal. **A guard that only matches the syntax the fix happened to use is not a guard** — batch 4-0d-fix.
- **The data phase has its own self-agreeing convention error** — batch 4-1a, and it is the same shape as 4-0b but was unreachable because SSU2 has never had a data phase. `SSU2DataPacket.BuildWithBlock` takes `dataKey` and `headerKey2` and **uses neither**, returning the raw block list — so every relay-tag request and peer test `SendBlock` has ever sent went out unframed and unencrypted. `BuildEncryptedPacket` writes 2 bytes of connection ID at 0-1, the packet number at **4** (short headers put it at 8) and a type byte at **2** while every reader takes type from **12**; `Parse` mirrors the same wrong layout, so it round-trips and no test notices. And `ProcessReceivedPacket:621` hands a whole-packet clone to `DecryptShortHeader`, which throws for anything but exactly 16 bytes, so data packets are dropped into the outer catch. **All of it is verifiable with no handshake, so 4-1a can land before 4-0b and 4-2.**

#### Correction to batch 3-3's finding

3-3 recorded that SSU2 has no periodic per-session work. `SSU2Session.Tick()` **does** exist (`:225-249`) and `TransportProvider.Run` calls `Tick()` on every established transport once a second (`TransportProvider.cs:244-256`). What is missing is a tick that reaches sessions *not* registered in `EstablishedTransports` — which is every session in the socket-free loopback fixture — and 1 Hz is too coarse for a 500 ms ACK delay and a 1 s RTO floor. 4-1 still needs a ~100 ms tick in `SSU2Host`, but for a different reason than recorded.

#### Sequencing, revised

Both remaining SSU2 batches are over the ~400-line rule and must split:

| order | batch | why here |
|---|---|---|
| 1 | **4-0f** | the integration suite cannot complete, so nothing below can be measured |
| 2 | **4-1a** | data-phase header + `BuildWithBlock` encryption; needs no handshake, blocks nothing |
| 3 | **4-2a** | responder only — answer a TokenRequest with a Retry. Touches no `SSU2Session` code, so it collides with nothing, and it produces the captured i2pd Session Request that 4-0b has been blocked on since 3-5 |
| 4 | **4-0b** | the 48-byte pass, against those captured bytes |
| 5 | **4-2b** | initiator side: consume a Retry, enforce tokens |
| 6 | **4-1** | ACK wiring; its gate needs a working handshake, so it cannot precede 4-0b |

**4-2's stated gate cannot be met by 4-2**, and that is 4-0b's doing, not 4-2's: "outbound connect to a token-enforcing i2pd completes <5 s" needs a Session Request i2pd can authenticate. 4-2a's honest gate is *i2pd answers our Retry with a Session Request, and we capture it*. Say so in the PR rather than leaving a gate looking unmet for unknown reasons.

### Session 4 (continued) — 2026-08-08 — batch 4-0f — PR #27, merged — **`github-master` is green again**

> The warning at the head of the 4-0e entry is **lifted**. The integration job passes, and the report is back to **52 total / 49 executed / 29 passed / 20 failed / 3 skipped** — the pre-crash baseline, with all 11 ScaledNetwork tests running again. Judge batches normally.

**Unit suite 274 passed / 0 failed / 1 skipped**, both CI jobs green, integration job 47m33s (longer *because* the tests it used to kill now run).

#### The fixture was SIGKILLing its own test host

`RouterProcessManager.KillProcessOnPort` ran `fuser -k {port}/tcp`. **That signals every process holding the port and offers no way to spare the caller.** `ScaledNetworkFixture:111` sweeps 29000-29299 as its first action.

While the in-process SAM bridge was wrongly bound to its default 7656 the two ranges never overlapped. **Batch 4-0e fixed the bridge to honour its configured port — 29002, the third port in the sweep — and the fixture began killing its own test host a second into setup.** Hence "started after 4-0e" with 4-0e itself being correct.

Holders are now enumerated with `lsof -t` and killed by PID, skipping `Environment.ProcessId`. A missing `lsof` declines to kill rather than falling back to a blind `fuser`; killing blind is the defect.

#### Reproduced on demand, which is the standard to aim for

Reinstating `fuser -k` locally and running the new guard reproduces the CI signature verbatim — `The active test run was aborted. Reason: Test host process crashed` — and restoring the fix makes it pass. **A defect you can toggle is a defect you understand.** Three sessions of this plan have now been spent on failures that were merely *observed*; this one took minutes once it could be switched on and off.

#### The wrong inference, and what caused it

Session 4 recorded, as evidence, that `ScaledNetworkFixture` "never logged a line, so the crash lands before its setup produces output". **That was wrong.** `ScaledNetworkFixture.SetUp:74` redirects logging to `/tmp/i2p_scaled_test.log`, which the workflow did not collect — so the fixture ran, was killed mid-setup, and its evidence was discarded. The log is now in the artifact list along with `/tmp/i2pd_scaled_*.log`; both are flushed per line and survive a hard kill.

**Absence of logs is not absence of execution — check where the logs went before concluding anything from their silence.** This is the third diagnosability gap this session (after the unread `.trx` `StackTrace` and the uncollected router logs) and the third time the expensive part was not the defect.

#### Still open: the other crash cause

`[CancelAfter(n)]` cancels a `CancellationToken` NUnit passes **as a test-method parameter**, and none of the 23 tests carrying the attribute declares one — so a timeout marks the test failed while its thread runs on, and the orphans can take the host down. Two of the three crashed runs had exactly that signature. It is independent of the port sweep, unfixed, and it will resurface as Phase 5 lets more tests reach a real transfer. Give those tests a `CancellationToken` parameter and thread it through `SAMHelper`.

### Session 4 (continued) — 2026-08-08 — batch 4-1a — PR #28, merged

**Unit suite 279 passed / 0 failed / 1 skipped** (was 274), both CI jobs green, integration **52 / 49 / 29 passed / 20 failed / 3 skipped** — unchanged, and expected to be: 4-1a repairs data-phase framing, and SSU2 still cannot complete a handshake, so no data phase runs.

The SSU2 data phase carried its own self-agreeing convention error. Three defects, one cause — nothing had ever built *and* parsed a data packet in anger:

1. **The header was invented.** `BuildEncryptedPacket` wrote 2 bytes of connection ID at 0-1, the packet number at **4**, and a type byte at **2**, while every reader takes the type from **12**. `Parse` mirrored the same layout, so build/parse round-tripped perfectly. **Truncating the 64-bit connection ID to its top 16 bits was the worse half** — two sessions agreeing in those bits were indistinguishable. `SSU2Header.ToByteArray`/`ParseShortHeader` already emit and read the correct form and the long-header path has always used them; both sides now use that one definition.
2. **`BuildWithBlock` encrypted nothing** — it took `dataKey` and `headerKey2` and used neither, returning the bare block list. Every relay-tag request and peer test `SendBlock` has ever sent went out unframed and in the clear.
3. **The type peek dropped every data packet** — it handed the whole packet to `DecryptShortHeader`, which throws unless the array is exactly 16 bytes.

**The tests deliberately do not assert against `SSU2DataPacket`'s own round trip**, because that round trip is exactly what passed throughout the defect's life. They assert against `SSU2Header` and hand-computed offsets, and check that the block's plaintext bytes do not appear in the packet. 4 of 5 confirmed red with the defects reinstated.

**Not verified against i2pd, and the plan should not record otherwise.** A Data golden vector needs a completed handshake, blocked on 4-0b and 4-2. What is proven is internal consistency with the single definition of the wire format.

**A pattern worth naming, now that it has appeared four times.** 4-0 (header keystream block), 4-0b (48-byte pass), 4-1a (data header), and the `SSU2DataPacket` build/parse pair are all the same failure: *two halves of this codebase agreeing with each other on a convention the network does not use*. Every one was invisible to a round-trip test and every one needed either a reference implementation or an independent re-derivation to see. **When reviewing SSU2 code, a passing round-trip test is not evidence of anything — ask what the peer does.**

**Next: 4-2a** (`p4/ssu2-retry-token`, responder half) — answer an inbound TokenRequest with a Retry. It touches no `SSU2Session` code, so it collides with nothing, and it produces the captured i2pd Session Request that 4-0b has been blocked on since 3-5.

### Session 5 — 2026-08-09 — batch 4-0b — PR #34 — **the 48-byte pass, settled against i2pd's own bytes**

Also merged in this session: **4-2c (PR #30)**, whose capture ran green in CI against i2pd 2.61.0 and produced `TestData/ssu2_sessionrequest_i2pd.txt`. Open and green at hand-off, awaiting the maintainer: **#31** (4-2b), **#32** (4-0d-fix), **#33** (4-0g).

**Unit suite 293 passed / 0 failed / 1 skipped** (was 288), Release build 0 errors. Quarantined set unchanged at 5 red — the three ML-KEM handshakes (9-3), `SustainedTrafficExceedingTheTagWindow` (Phase 5), and `HandshakeCompletesOnACleanChannel`, which now fails **one message later**, for a cause named below.

#### The question was decided before a line of production code changed

The captured Session Request was decoded with an implementation independent of this repository — Python `cryptography`, not `SSU2HeaderEncryption` — under both candidate conventions:

```
i2pd: one 48-byte ChaCha20 pass over packet bytes 16..64   ->  payload Poly1305 tag VERIFIES
this repo: two restarted keystreams                        ->  tag fails
```

**A verifying tag settles the whole transcript at once**, not just the ephemeral key: the AD is the 32 plaintext header bytes and the Noise hash covers X and the protocol name, so every byte of both had to match what i2pd hashed. The recovered payload is `DateTime(0x6a77a32d) + Padding(26)`, and header bytes 24-31 carry the token our own Retry issued.

That is a different standard of evidence from the last four SSU2 batches, and deliberately so. **The fix was then written test-first against those bytes** — `Ssu2SessionRequestVectorTest` runs i2pd's real packet through the production receive path and was confirmed red with `AEAD authentication failed` before any change.

#### The fix is smaller than the finding

`ObfuscateEphemeralKey` now takes keystream bytes 16..48 instead of restarting at 0, and the four Session Request / Session Created send and parse paths call `EncryptLongHeaderComplete` instead of `EncryptLongHeaderInPacket`. Composing the two reproduces i2pd's single 48-byte call byte for byte — 48 bytes fit inside one ChaCha20 block, and both halves use the zero nonce.

**The 16-byte form was not touched**, per the constraint session 4 derived from the TokenRequest vector: it is correct for TokenRequest, Retry and PeerTest, and the Retry path 4-2a proved against the real peer must not move. Header bytes 16-31 decode identically under both conventions, which is why `TheHeaderRegionIsUnaffectedByTheChange` is green before *and* after — it is there to bound the change, not to detect the defect.

#### 3-3's C#-to-C# failure and the i2pd interop divergence really were one defect

Predicted in 4-0, confirmed here: the loopback fixture goes from `sent=1` to `sent=2`. Bob logs `SessionRequest received and validated` and answers with a Session Created. **Alice then logs `Unknown packet type 160`** — and that is a new, separate defect, now batch **4-0h**: `ProcessReceivedPacket` peeks the message type by trial-decrypting with `k_header_2 = ` the intro key, which is right for a Session Request and wrong for a Session Created, whose k_header_2 is `HKDF(chainKey, "SessCreateHeader")` — the derivation `ProcessSessionCreated` performs correctly two calls later. The type byte lives at offset 12, inside the group k_header_2 masks. **The dispatcher and the handler disagree about the key.**

#### Three findings recorded rather than fixed, because scope

- **4-0i, and it comes with proof.** i2pd's handshake payload is SSU2 **blocks** — `00 0004 <ts> | fe 001a <pad>` — while `BuildRequestPayload` writes a bare timestamp and both `ProcessSessionRequest` and `ProcessSessionCreated` read one back. Another pair agreeing with each other and not with the network. The captured plaintext is the reference, and it is asserted (as documentation, not as a guard on our code) in the new fixture.
- **4-0j, unverified and labelled as such.** `SendHolePunch` uses `Host.GetMyStaticKey()` where an intro key belongs, and masks bytes 0-15 where receivers unmask 0-31.
- **A fingerprint, not a bug.** `SendSessionRequest` regenerates its ephemeral key until the *obfuscated* first byte has its MSB clear, so 100% of our Session Requests carry a bit that is uniform in i2pd's. Worth removing when someone touches that loop; not worth a batch of its own.

#### One quarantined test was deleted rather than un-quarantined

`SessionRequestObscuresItsSourceConnectionIdAndToken` asserted that header bytes 16-31 are masked by calling the 16-byte primitive directly — but that primitive was never the defect; the Session Request path *calling* it was. Rewriting it to assert on the primitive would have produced a test that passed before the fix. The assertion now lives on the message, against i2pd's keystream, in `OurSessionRequestMasksBytesSixteenToSixtyFourAsOnePass`. **A guard that would have been green through the whole life of the defect is not a guard.**

**Next: 4-0h** (`p4/ssu2-sessioncreated-header-key`) — it is the single thing between here and a completed C#-to-C# handshake, and every remaining Phase 4 batch (4-1's ACK gate, 4-3, 4-4) needs one. **4-0i** follows, since no handshake we build will be accepted by i2pd until the payload is block-framed.

### Session 5 (continued) — 2026-08-09 — batch 4-0h — PR #35 — **the SSU2 handshake completes**

**Unit suite 296 passed / 0 failed / 1 skipped** (was 293), Release build 0 errors. `HandshakeCompletesOnACleanChannel` is **un-quarantined and green** — the first SSU2 session this repository has ever established, in four datagrams: Session Request, Session Created, and a Session Confirmed fragmented across two.

#### Four defects, each hiding the next, none visible to a round-trip test

4-0b removed the first. The other three were found by tracing the fixture one message at a time, and each was the same shape — *our two halves disagreeing about a key or a hash*:

| # | symptom | cause |
|---|---|---|
| 2 | Alice: `Unknown packet type 160` | the type peek trial-decrypted every packet with the intro key; a Session Created's k_header_2 is `HKDF(chainKey, "SessCreateHeader")`, and the type byte lives inside the group k_header_2 masks |
| 3 | Bob: `Unknown packet type 4`, then `13` | Alice derived the Session Confirmed header key **after** `CreateMessage3Part2`, which mixes `se` into the chaining key and splits — a key derived from a state that only exists after the message the header introduces |
| 4 | Bob: `AEAD authentication failed` | Alice hashes a canonical header with `flags[0] = 0x01`; Bob hashed the header as received. Identical for an unfragmented Session Confirmed, different for a fragmented one — and it always fragments, because the RouterInfo does not fit one datagram |

**Defect 3 is worth naming as a rule.** A header key must be derivable from state the receiver has *before* it opens the message that header introduces. Deriving it a line later than that is not a style question; it makes the message unreadable.

**Defect 4 is a fragmentation-only divergence**, which is why it survived: an unfragmented Session Confirmed hashes identically on both sides, so any test with a small RouterInfo would have passed.

#### The peek now chooses by state, and the order is load-bearing

With the wrong key the type byte is uniformly random, so an unordered "try both keys" would misdispatch roughly one packet in sixty on a coincidence. The peek tries what the session is *waiting for* first and accepts it only on an exact type match, so a wrong guess falls through to the intro key — which is what a Retry arriving in `SessionRequestSent` needs, and therefore what keeps 4-2b (#31) working.

#### The fixture could not see its own success

`HandshakeCompletesOnACleanChannel` asserted on `alice.Established`, which the fixture filled only from `Host.ConnectionCreated` — and `SSU2Session` fires that for **incoming** connections only. An outbound session announces itself by raising `ConnectionEstablished` on itself, which is what `TransportProvider` subscribes to. So the dialling peer's list was permanently empty and the test would have stayed red after the protocol was correct.

**That is the third time this plan has been misled by a measurement rather than a defect** — after the uncollected `/tmp/i2p_scaled_test.log` and the unread `.trx` stack traces. The rule earned here: when a test goes green in the logs but red in the assertion, **suspect the assertion's reachability before suspecting the code**.

#### What this does and does not prove

C#-to-C# only. **Nothing here says i2pd would accept this handshake**, and batch 4-0i has direct evidence that it would not: our handshake payload is a bare timestamp where i2pd sends SSU2 blocks. What is proven is that our two halves finally agree, which they never have before.

#### The data phase is now measurable, and it is much closer than "broken"

Both data-phase tests reach the data phase for the first time instead of being skipped by their own `Assume`:

* `CleanChannelDeliversEveryMessage`: **99 of 100** on a lossless channel — `sent=104 delivered=104 lost=0`. One message vanishes with nothing dropping it.
* `LossAtFivePercentStillDeliversEveryMessage`: 6 datagrams lost, 6 messages never delivered, nothing retransmitted — exactly the missing ACK/retransmit path.

Both stay quarantined and both belong to **4-1**, which now has a much sharper target than it was written with. **The one missing message on a lossless channel should be explained before any retransmission work starts** — a data phase that loses 1% with no loss is not a retransmission problem.

**Next: 4-1** (`p4/ssu2-ack-wiring`) has become the highest-value SSU2 batch, since its gate is finally measurable. **4-0i** is the one that decides whether any of this works against i2pd rather than against ourselves, and it should be the next thing verified against a real peer.

### Session 5 (continued) — 2026-08-09 — batch 4-1b — PR #36 — **1.2% of every data packet was being thrown away**

**Unit suite 298 passed / 0 failed / 1 skipped** (was 296), Release build 0 errors. **`CleanChannelDeliversEveryMessage` is green and un-quarantined — batch 3-3's gate, 100/100 at 0% loss, is met.** One quarantined test remains in the fixture: 5% loss, owned by 4-1.

#### The number that did not add up

4-0h left the data phase delivering **99 of 100** with `sent=104 delivered=104 lost=0` — every datagram arriving, one message never appearing. Small enough to wave through as a fixture quirk. It was not: it was a protocol defect losing **one packet in eighty**, permanently, in both directions.

#### Measurement before hypothesis, and it paid immediately

Probing 1, 2, 3, 10, 20, 50, 64, 65, 80, 100 messages showed full delivery at small counts and losses that **varied between runs of the same seeded, socket-free fixture** — 50/50 then 49/50, 99/100 then 97/100. Nondeterminism in a fixture with no clock, no socket and a seeded channel is a strong signal on its own; the peers generate fresh intro keys per run, and that turned out to be exactly the variable.

Turning debug logging on gave the answer in one line: **`SSU2-In-…: Received SessionCreated in state Established`**. Not a lost packet — a *misdelivered* one.

#### The cause is a coincidence, and coincidences have rates

In `Established` the peek fell through to a long-header trial decrypt under the **intro key**. No data packet is masked with the intro key, so the type byte read at offset 12 is uniformly random. Three of 256 values — Session Request, Created, Confirmed — are long-header types, and those skipped the short-header path entirely and were handed to a handshake handler that dropped them on a state check.

**3/256 ≈ 1.2% per packet.** The fix is one more branch in the state-ordered peek 4-0h introduced: `Established` tries the data header key first and accepts it only for `TYPE_DATA`.

#### Sizing a test to a probability rather than to a round number

At 100 messages this defect shows up as green about **one run in three** — which is precisely how it presented across three runs: 99, 97, 100. A regression guard with a 31% false-pass rate is not a guard. The new test sends **1000** messages, putting P(passing by luck) near 8 in a million, and the test's own comment carries the arithmetic so the number is not mistaken for arbitrary.

**The general lesson, and it is the fourth variant of this plan's recurring theme:** when a defect is probabilistic, *the sample size is part of the assertion*. A round number chosen for readability is not a measurement.

#### What is left

`LossAtFivePercentStillDeliversEveryMessage` now loses **exactly** what the channel drops — 6 datagrams, 6 messages — and nothing more. That is a clean statement of the remaining gap, and it is entirely **4-1**: `SSU2AckManager` is instantiated nowhere, the ACK block case is empty, and there is no session tick to hang `GenerateAck()` or retransmission on.

**Next: 4-1** (`p4/ssu2-ack-wiring`), whose gate is now measurable and whose target is now unambiguous. After that, **4-0i** decides whether any of this survives contact with i2pd.

#### Addendum — the integration baseline across this session

| PR | batch | total | executed | passed | failed | skipped |
|---|---|---|---|---|---|---|
| #30 | 4-2c | 53 | 50 | 30 | 20 | 3 |
| #34 | 4-0b | 53 | 50 | 29 | 21 | 3 |
| #35 | 4-0h | 53 | 50 | 30 | 20 | 3 |

#34's extra failure was `CaptureSessionRequestByAnsweringTheTokenRequest` and **#35's failure list is byte-identical to #30's** — same twenty tests, none new, none fixed. So the capture is flaky rather than regressed, and 4-0b and 4-0h changed the integration suite by nothing at all. That is the expected result: SSU2 is off by default there, so neither batch is exercised.

**Compare against the baseline before attributing a failure** — this is the second time this session that doing so turned an apparent regression into noise, and the first time (session 4) that skipping it cost two CI runs.

### Session 5 (continued) — 2026-08-09 — batch 4-1 — PR #37 — **SSU2 delivers 100/100 through 5% loss**

**Unit suite 300 passed / 0 failed / 1 skipped**, Release build 0 errors. **The 3-3 loopback fixture has no quarantined tests left**: handshake (4-0h), clean-channel delivery (4-1b) and delivery under loss (4-1) are all green.

#### The missing line was `new SSU2AckManager()`

`SSU2AckManager` is a complete class with its own unit tests, and **no production code had ever instantiated it**. The ACK block case in `SSU2Session` was an empty `break`. So a sender kept no record of what it sent, a receiver acknowledged nothing, and a dropped datagram was simply gone. Four call sites fixed that: `RecordSent` in `BuildDataPacket`, `RecordReceived` in `ProcessDataPacket`, `ProcessAck` in the ACK case, and `Tick()` to drive both halves.

#### Three decisions worth recording, because each is a trap

- **Only I2NP traffic is held for retransmission.** `SendBlock` also carries ACKs, relay tags and peer tests. An ACK held for retransmission would be an ACK that gets ACKed forever.
- **The ACK is emitted from the tick, not piggybacked.** A responder that only speaks when spoken to cannot acknowledge one-way traffic, and one-way traffic is the normal case for a tunnel hop. `MAX_ACK_DELAY_MS` is what stops two peers acknowledging each other's acknowledgements in a loop.
- **Retransmission makes duplicates normal**, and a receiver that hands both copies upward delivers the same I2NP message twice. A repeat packet number is now re-acked — its ACK is what got lost — and dropped rather than re-delivered. Without this the loss test would have failed *upward*, delivering more than it was sent, which is a nastier bug than losing one.

`GetPacketsNeedingRetransmit` returns two kinds of packet in one list — just-rescheduled and out-of-attempts — and distinguishes them only by having pushed the rescheduled ones' deadline into the future. That is documented at the call site rather than left to be rediscovered.

#### The tests spend real time, and there is no way around it yet

ACK delay is 500 ms and the RTO 1 s, so the two new tests sleep. **There is no time seam in this repository** — `TickCounter` reads `Environment.TickCount` statically and `SSU2AckManager` uses `DateTime.UtcNow` directly, which is also a divergence from the repo's own rule that monotonic time goes through `TickCounter`. A seam would make these tests instant and the RTO logic properly testable; it is worth its own batch, and it is not this one.

#### What is still not true

**SSU2 stays off by default, and this batch does not change that.** The handshake has never completed against i2pd, and 4-0i has direct evidence it cannot until the handshake payload is block-framed. Everything green here is C#-to-C#. The next thing that matters is not more SSU2 features — it is **4-0i**, and then a capture proving a real i2pd session.
### Session 5 (continued) — 2026-08-09 — batch 4-0i — PR #38 — **the handshake payload is finally framed the way the network frames it**

**Unit suite 302 passed / 0 failed / 1 skipped**, Release build 0 errors.

The fifth instance of this plan's recurring defect, and the last one the captured vector can settle on its own: `BuildRequestPayload` wrote a bare timestamp, both handlers read a bare timestamp, and the network sends blocks. i2pd's authenticated payload is `00 0004 6a77a32d | fe 001a 00…`. **Read our way, that decodes as a timestamp of `0x00000406`** — 1970 plus about seventeen minutes — so the clock-skew check alone would have rejected every real i2pd handshake even if everything else had been right.

#### Changing one side and not the other failed in seconds, which is the point

The first attempt reframed the Session Request only. The loopback fixture went red immediately with `Clock skew too large: 1786261566s` — Alice reading Bob's bare timestamp as a DateTime block. **That is the difference the last five batches have bought.** The same class of error used to require a captured packet and an independent re-derivation to notice; now our own two halves disagreeing is a red test in under a minute.

#### Deliberately not done

The PQ appendix — a version byte and a raw ML-KEM key with no block header — is still not block-framed. It now sits after the DateTime block instead of after the old 8-byte prefix, byte-for-byte otherwise unchanged. Giving it a real block type is a protocol decision and belongs to Phase 9, not to a batch about classical interop.

`ParseSessionCreatedBlocks` used to be handed a slice starting after a fixed 8-byte prefix that does not exist on the wire. It walks type/size pairs itself, so it now gets the whole payload and sees blocks that used to sit before the old offset.

**Next: the thing this unblocks is a capture.** Every SSU2 batch since 4-0b has been verified against a *stored* i2pd packet or against ourselves. What none of them can prove is that a full session establishes with a live i2pd — and that is now worth attempting directly, since the four defects known to prevent it are all fixed.

#### Addendum — trying it against a live i2pd, and what the local run actually measured

`SSU2LiveHandshakeTest` dials a real i2pd over SSU2 through a socket-backed `SSU2Host` — the loopback fixture's peer with the channel replaced by a UDP socket, so the bytes on the wire are the bytes production sends. **We dial i2pd rather than the reverse**, because the outbound direction depends on nothing but i2pd listening.

**Locally it proves nothing, and the test now says so itself.** i2pd 2.45.1 answers our Session Request with:

```
SSU2: Incoming packet received from invalid endpoint 127.0.0.1:29260
```

That is an endpoint check, and it fires **before any decryption**. Established directly rather than inferred:

- Firing **87, 200 and 1300 bytes of random data** at it produced the identical rejection three times, so it is not a size guard and not a crypto failure.
- Repeating from a **non-loopback** address (172.26.70.175) produced the same rejection, so it is not loopback-specific — it is the reserved-range check, and `reservedrange = false` does not take effect in that build.

So the local run measured i2pd's ACL, not our protocol. **A test that reported this as "handshake failed" would be worse than no test**, so it inspects i2pd's log and `Assert.Ignore`s with the reason when it sees that line. CI runs 2.61.0, which batch 4-2c already showed will dial us over loopback and accept a Retry — that is where this test gets to answer the question.

**Risk R4 in the plan is now concrete rather than theoretical:** the locally installed i2pd cannot exercise SSU2 interop at all, in either direction, so every SSU2 interop claim has to come from CI.

#### Addendum — the live test ran against i2pd 2.61.0 in CI, and the answer is no

`CSharpEstablishesAnSSU2SessionWithI2pd` **failed in CI**: `state SessionRequestSent, 1 datagrams sent, 0 received`. It did **not** take the `Assert.Ignore` path, so i2pd 2.61.0 logged no `invalid endpoint` — it accepted the datagram at its endpoint check and then said nothing.

**So the SSU2 handshake still does not work against i2pd**, after 4-0b, 4-0h, 4-2a/4-2b and 4-0i. Everything green in Phase 4 remains C#-to-C#, and the plan should not be read as saying otherwise.

**What is missing is the reason, and that is our fault, not i2pd's.** The test writes i2pd's log to a per-run temp directory the workflow does not upload, so the one thing that would explain the silence was discarded — the third time this plan has lost evidence that way, after `/tmp/i2p_scaled_test.log` and the unread `.trx` stack traces. The test now prints i2pd's own SSU2 log lines into the test output on failure, where the run report already goes.

**Next: run it again and read what i2pd says.** Do not guess at the cause from here — a first packet that draws total silence has several plausible explanations (token enforcement expecting a TokenRequest first, header key selection, netid, the Session Request's own framing), and this plan's record on guessing between plausible explanations is poor. The next batch is whatever that log says.

#### Batch 4-0k, applied — the fix is two lines and the finding was the work

The outbound constructor now generates **both** connection IDs. The responder adopts the destination ID we choose as its own and returns it as the source ID of its Session Created, so one assignment makes the whole exchange non-zero — the loopback's `Got remote connection ID: 0000000000000000` is gone with it.

**Asserted on the wire, not on the property.** `TheSessionRequestAddressesANonZeroConnectionId` taps the first datagram, decrypts it the way Bob does, and checks the header — because a property agreeing with itself is precisely what hid this for the whole life of the code. Confirmed red first.

**What this does not yet prove.** i2pd may now answer, or it may answer with a Retry we then have to complete, or it may still be silent for a further reason. The live test is the only thing that can say, and it can only say it in CI. **Do not record this as interop working until that test does something other than fail.**

#### Verified on the socket path, and the one remaining difference from i2pd

Capturing the outbound Session Request from the live test and decoding it independently now gives `destConnId=c519c3342d5b78b6`, `srcConnId=9102fd92a2d464a7` — non-zero and independent, `type=0 version=2 netid=99`. The batch's first gate is met on the real wire, not only in the loopback.

**`token` is still zero, and that is the next thing to check — with evidence already in hand.** `Ssu2GoldenVectorTest.I2pdOpensWithATokenRequest` records, from a captured packet, that **i2pd's first message to a peer it holds no token for is a TokenRequest (type 10), not a Session Request with a zero token.** We do the opposite: we send a Session Request with token 0 and rely on the responder answering with a Retry.

The SSU2 responder rules say a bad token draws a Retry, so ours may be answered — but **i2pd's observed behaviour is the stronger evidence about what i2pd accepts**, and 4-2a exists precisely because i2pd opens that way.

So the decision tree for the next session is already determined by the CI run of PR #40, and neither branch requires guessing:

- **i2pd replies** (Retry or Session Created) → the token flow works; carry on from whatever it sends.
- **i2pd is still silent** → batch **4-2d**: send a TokenRequest first when we hold no token, mirroring what i2pd itself does. The producer in `SSU2GoldenVectorCapture` already builds and reads that message type, so the pieces exist.

The live test now prints i2pd's own SSU2 log lines on failure, so the run will show which of these it is rather than leaving it to be inferred.

### Session 5 (continued) — batch 4-0l — **i2pd told us why, in one line**

With 4-0k's connection ID in place, i2pd 2.61.0 **decrypted our Session Request, recognised what it was, and rejected it on length alone**:

```
SSU2: SessionRequest message too short 87
```

That single line is the most valuable output of this session, and it exists only because 4-0i added log surfacing to the live test after the previous run threw the evidence away. **It also validates everything before it**: to say "SessionRequest" i2pd had to unmask the header, read the type, accept the netid and find a connection ID it could act on — 4-0b, 4-0h, 4-0i and 4-0k all confirmed against a real peer at once.

87 = 32 header + 32 ephemeral key + a 7-byte DateTime block + a 16-byte tag, one byte under the shortest request i2pd will look inside. i2pd's own Session Request carries a 26-byte Padding block. **Padding a handshake message is not decoration**: an unpadded request is cheaper to send than the reply it provokes, which is the shape of an amplification attack. Fixed with a random amount above the minimum, so length is not a fingerprint, and not applied to the PQ case whose appendix is read from a fixed offset.

#### An intermittent failure found while verifying, and deliberately not papered over

The full unit suite failed once (1 of 309) and passed on re-run, and a fixture loop showed one run with a test going **Inconclusive** rather than passing. `SSU2LoopbackTest` alone is stable — eight consecutive runs, 13/13 — so this only appears when fixtures run **together**.

The suspect is `I2PConstants.I2PNetworkId`, a mutable process-wide static that `SessionRequestAnnouncesTheConfiguredNetworkId` sets to 3 and restores: any handshake running concurrently would be rejected by its own netid validator and its `Assume` would fire. That is a hypothesis with a mechanism, not a diagnosis — **it has not been confirmed, and this batch must not be recorded as clean until it is.** Phase 2 removed mutable static config elsewhere for exactly this reason (batch 2-6); this one survived in the test suite.

**Next: confirm or refute that before merging 4-0l**, then re-run the live test — a padded Session Request is the first one i2pd has had no stated reason to reject.

### Session 6 — 2026-08-09 — batch 4-0m — **the 4-0l flake, diagnosed: a Retry read as a Session Created**

**Unit suite 309 passed / 0 failed / 1 skipped, twelve consecutive runs**, Release build 0 errors. The same twelve-run protocol before the fix produced one failure, so this is measured against its own baseline rather than against a single green run.

#### The suspect named by 4-0l was wrong, and refuting it took a measurement rather than an argument

`I2PConstants.I2PNetworkId` could only cause this if two fixtures ran at once. **They never do:** the `.trx` records a start and end time per test, and across 309 tests there are **zero overlapping intervals**. There is no `[Parallelizable]` in the assembly, no `.runsettings`, and nothing in the workflow that asks for parallelism. The three fixtures that mutate the netid all restore it in a `OneTimeTearDown` `finally`, and the loopback fixture has no background threads to leak.

**"Only when fixtures run together" was an inference from eight clean fixture-only runs, and eight runs cannot see a 1-in-300 event.** The conclusion was drawn from a sample too small to support it, and it pointed the next session at the wrong file.

#### What it actually is

Reproduced by running the unit suite twelve times with `--logger trx`: `ARetryTeachesTheInitiatorATokenItThenPresents` failed once, and the captured stdout named the cause outright —

```
SSU2-In-777BE6D0: Session Request carried no token we issued; sent a Retry
SSU2-Out-40D9682D: ProcessReceivedPacket failed: System.Exception: AEAD authentication failed
   at SSU2Session.ProcessSessionCreated(Byte[] packetData)
```

Bob sent a **Retry**; Alice ran it through **ProcessSessionCreated**. `PeekMessageType` identifies a message by its type byte alone. In `SessionRequestSent` it trial-decrypts with the derived `SessCreateHeader` key first, and that key is wrong for a Retry — so the type byte is **uniformly random**, and one value in 256 is `TYPE_SESSION_CREATED`. The token is then never learned. **Against a token-enforcing peer, which is i2pd's normal configuration, that is not a flaky test — it is a handshake that fails outright.**

Batch 4-0h introduced the ordering and reasoned about exactly this, then stopped one step short: trying the expected message first lowers the odds from one in sixty to one in 256. It does not remove them.

#### The remedy was already written down, in a test, in the same file as the failure

`Ssu2TokenExchangeTest.TheInitiatorStopsAfterOneRetry` has identified messages by type *and* version *and* netid since 4-2b, and its comment states the arithmetic: *"decoding it this way yields a random type byte that would read as a Session Request once in 256. Three agreeing fields make that one in sixteen million."*

Version and netid sit at offsets 13 and 14, **inside the same eight bytes the type byte is recovered from** — the trial already had them and threw them away. So the fix is one condition in `TrialLongHeaderType`, and it is this plan's signature defect one level up: not "our two halves agree with each other and with nothing else", but **our test knows something our production code does not**.

#### The test states its own error rate, because it is a statistical test

`ARetryIsNeverMistakenForASessionCreated` drives 3000 Retries into a fresh session each and counts how many reach `ProcessRetry`, measured by consequence — a consumed Retry re-sends the Session Request, so one datagram leaves Alice. **The first attempt at this test passed against the broken code**: it counted `ConnectionException`, and `ProcessSessionCreated` rejects a garbage header quietly rather than throwing. A test that measures the wrong signal is indistinguishable from a fixed bug.

Confirmed red at 9 of 3000, then 6 of 3000 with the fix reverted — against a predicted 11.7. It tolerates one miss: fixed, three fields coincide at 1 in 16.7 million, so demanding a clean sweep would make the test itself fail about one run in 5600; broken, it still goes red 99.99% of the time.

#### Not fixed here, and deliberately

- **Short-header trials cannot be strengthened this way.** A short header carries no version or netid, so the `Established` and `SessionCreatedSent` cases keep a 1-in-256 exposure. The consequence is milder — a handshake retransmission eaten as data — but it is the same defect and has no test.
- **`SSU2Host.DispatchPacket` runs the same unvalidated trial** for packets from unknown endpoints, so roughly 3 random datagrams in 256 create an inbound session or enter the peer-test path. That is a DoS surface rather than a correctness bug, it predates this batch, and it wants its own failing test.

Also removed: `docs/PRODUCTION-PLAN.md` carried **committed merge-conflict markers** at the 4-0i addendum, one side empty. The addendum was kept.

**Next is unchanged from 4-0l: re-run the live test.** A padded Session Request is still the first one i2pd has had no stated reason to reject, and that answer can only come from CI — the locally installed i2pd 2.45.1 refuses SSU2 at its endpoint check.

#### Addendum — the CI run of PR #41, and the first real token exchange with i2pd

`CSharpEstablishesAnSSU2SessionWithI2pd` **still fails**, and the failure has moved two messages down the handshake. Previous run: `1 datagrams sent, 0 received`. This run: **2 sent, 24 received**, and i2pd's own log says what happened:

```
SSU2: SessionRequest token mismatch. Retry
SSU2: Session MTU=1500, max payload size=1440
SSU2: Block type 0 of size 4
SSU2: Datetime
SSU2: Block type 254 of size 17
SSU2: Padding
SSU2: Resending 4          (x22)
SSU2: Session with 127.0.0.1:29260 terminated
```

**Four things are confirmed against a real peer at once, none of them by inference:**

- **4-0l worked.** No `message too short`. i2pd accepted the padded Session Request and processed it.
- **The token exchange works with i2pd.** It answered `token mismatch. Retry`, we consumed the Retry and sent a second Session Request — the flow 4-2a/4-2b built, exercised for the first time against something that is not us.
- **i2pd parsed our handshake payload block by block**: `Block type 0 of size 4 / Datetime`, then `Block type 254 of size 17 / Padding`. That is 4-0i's framing and 4-0l's padding read correctly by the implementation they were written for. The 17 is ours — `MinimumPadding` 8 plus a random amount under 24.
- **4-0m is not implicated.** Our netid and i2pd's are both 99 here, so the added version/netid check accepts what it should.

**The new blocker, and our own log names it exactly.** `Resending 4` twenty-two times is i2pd retransmitting a Session Created we never answer. We do not drop it — **we decrypt it, authenticate it, and then throw while parsing its blocks**:

```
SSU2-Out-6A4CC6E0: ProcessReceivedPacket failed: System.Exception: Invalid Address block size: 29260
   at AddressBlock.Parse(I2PBufferCursor data)          SSU2Blocks.cs:182
   at SSU2Session.ParseSessionCreatedBlocks(...)         SSU2Session.cs:2026
   at SSU2Session.ProcessSessionCreated(Byte[])          SSU2Session.cs:1229
```

**Reaching `ParseSessionCreatedBlocks` at all is a large result**: the Session Created header key derivation, the header unmasking, the ephemeral key and the AEAD tag are all correct against a real i2pd. Everything from 4-0 through 4-0m holds on the wire. What is left is one block parser.

#### Batch 4-0n, already diagnosed — the Address block, and the seventh instance of the signature defect

`29260` is not a length. **It is our own SSU2 port**, which is what i2pd puts in the Address block when it tells us the address it sees us on.

- `ParseSessionCreatedBlocks` reads the type and the two-byte size itself, then hands `AddressBlock.Parse` **the payload only**.
- `AddressBlock.Parse` opens by reading a two-byte size **again**, so it consumes the first two payload bytes as a length.
- The SSU2 Address block is **port first, then IP**. So the two bytes it eats are the port: `0x724C` = 29260, and it throws on a size that is neither 6 nor 18.
- Our `AddressBlock.Serialize` writes **IP first, then port**, and writes the size field its own `Parse` then re-reads. **The pair round-trips perfectly against itself and matches nothing on the network** — 4-0b, 4-0h, 4-0i, 4-0k, 4-0l and 4-0m were all this same shape.

So the fix is two things that must move together: drop the redundant size read in `Parse`, and swap the field order in both `Parse` and `Serialize` so the block is port-then-IP.

**A round-trip test cannot catch this** — it is what hid it. The guard has to be i2pd's bytes: the Address block from a real Session Created, asserting the parsed value is our own `127.0.0.1:29260`. The live test does **not** currently record datagrams (an earlier draft of this note claimed it did; it does not), so 4-0n's first move is to have it write the received Session Created to `TestData/` the way `SSU2GoldenVectorCapture` already writes the others, and the workflow already uploads `ssu2_*.txt`.

### Session 6 (continued) — batches 4-0n, 4-0d-fix2 and 5-2 — **the Address block, and two small debts**

**Unit suite 315 passed / 0 failed / 1 skipped** (316 total), Release build 0 errors. Merged straight to `github-master` — the whole branch backlog was already squash-merged, so PR #41 was the only outstanding work and it fast-forwarded.

#### 4-0n — the Address block agreed with itself and with nothing else

Diagnosed entirely from the CI log of PR #41, which is worth stating because the previous three SSU2 batches each needed a round trip through CI to find their next fact and this one needed none. `AddressBlock` had **two** defects that cancel:

- `ParseSessionCreatedBlocks` consumes the block type and two-byte size, then hands `Parse` the **payload**. `Parse` opened by reading a two-byte size **again**.
- The wire layout is **port then address**. `Serialize` wrote address then port, so the bytes `Parse` ate were the port: `Invalid Address block size: 29260`, our own listening port.

Together they round-trip perfectly. **That is exactly why nothing caught it**, and it is the seventh instance of this plan's signature defect. The tests are therefore byte-literal — `72 4C 7F 00 00 01` parsed to port 29260 and 127.0.0.1, and the serialiser asserted against `0D 00 06 72 4C 7F 00 00 01` — rather than a round trip, which passes on the broken code.

The blast radius is wider than the Session Created: `Retry.BuildPayload` puts an Address block in **every Retry we send**, so i2pd has been mis-reading our reported address the whole time as well.

#### 4-0d-fix2 — already fixed, and now self-checking

The row was stale: batch 4-0d-fix (#32) added `StripComment` to `CsprngGuardTest.ScanFor`. What remained was the workaround it left behind — `SSU2TokenCache.NewToken`'s doc comment was written *around* the banned constructor and said so. It now names `new Random(` plainly, which makes the file a live check that the scan still strips comments: if that regresses, `NoSystemRandomUnderI2PCore` goes red on its own documentation.

#### 5-2 — the level was only half of it

Both ECIES handshake diagnostics ran at `LogInformation`, the default level, on every session establishment in both directions. **Lowering the level alone would have fixed nothing measurable**: each site builds its fingerprints — and one performs an `Elligator2.Decode` — into locals *before* the call, and CLAUDE.md's interpolated-string handler can only skip formatting it is handed, never an argument already evaluated. Both are now behind `Logging.IsEnabled(Debug)`.

**The guard is a source scan, and deliberately.** These lines sit on the hybrid post-quantum path, and nothing in the repository can drive one: `ECIESPump` pairs two classical key managers, so a behavioural test would have passed without executing the code it claimed to cover. A vacuous test is worse than an honest scan — the scan carries its own "did it read anything" check, which this plan has now had to add three times.

**Next: 4-0n needs the live test to confirm it**, the same way 4-0l did. The handshake got as far as parsing blocks in the Session Created, so the next CI run says whether that was the last thing between us and an established SSU2 session with i2pd.

### Session 6 (continued) — batch 5-1 and a README correction

**Unit suite 315 passed / 0 failed / 1 skipped**, Release build 0 errors. Deletion only; nothing changed behaviour.

#### 5-1 — three dead things, and one kept on purpose

Each was checked for references before removal rather than trusted from the plan row:

- **`ECIESGarlicProcessor`** and **`NTCP2AckManager`** — referenced nowhere outside their own files.
- **`ECIESRatchet`** — the plan called it "never invoked", which was nearly right and worth pinning down: it *was* constructed, once, at the end of session establishment, and the field was then never read. No caller ever invoked `RatchetForward`, `GetSendKey` or `GetReceiveKey`. Its derivation, `HKDF(key, counter, "ratchet")`, is not the I2P ECIES ratchet either. **A non-spec ratchet nothing drives is worse than no ratchet**: it reads as forward secrecy that is not there.

**`RatchetTagSet.NextKeyHandler` is kept**, and the reason is now a header comment in `ECIESSessions.cs` rather than folklore. It is unused *today for the same reason the deleted code was*, so the distinction — it models i2pd's `HandleNextKey` and batch 5-4 implements against it — could not be left to the next reader's judgement.

#### The README said something that is no longer true

Not batch 6-3, which rewrites the whole board from measurement; this is the narrower obligation CLAUDE.md sets, to keep the status current when a batch changes it. The SSU2 entry claimed we had "never yet completed a handshake with i2pd, though the four defects known to prevent it are fixed". After PR #41 that understates it in one direction and overstates it in another, so it now records what was actually measured against i2pd 2.61.0 — Session Request accepted, Retry issued and consumed, our blocks parsed, its Session Created decrypted and authenticated — and states plainly that **no session with another implementation has been established**, so the detail cannot be read as SSU2 working.

### Session 6 (continued) — **an SSU2 session with i2pd, established**

The CI run of `github-master` at `b71f8cc` (batch 4-0n) reports:

```
SSU2-Out-2CCFB0CA: Session established
final state Established after 4 sent / 2 received
```

`CSharpEstablishesAnSSU2SessionWithI2pd` **passed**. This is the first SSU2 session this repository has established with another implementation, and it closes a run of eight batches — 4-0, 4-0b, 4-0d, 4-0h, 4-0i, 4-0k, 4-0l, 4-0n — every one of which was necessary and none of which was sufficient.

**Four datagrams sent and two received is the whole exchange including the token round trip**: Session Request, Retry back, Session Request again with the token, then a Session Confirmed across two fragments, with i2pd's Session Created as the second thing received.

#### What this does and does not license

- **It does not mean SSU2 works.** A handshake is not a transport. Carrying I2NP traffic to i2pd over that session is unmeasured, inbound sessions *from* i2pd are untested, and the integration suite is still 30 passed / 21 failed. **4-5 does not become available because of this**, and SSU2 stays off by default.
- **It does retire the plan's biggest open question.** Every SSU2 batch since 4-0b was verified against a stored packet or against ourselves, and R4 said interop claims could only come from CI. They now have.

#### The one outcome that moved the other way, and why it is not 4-0n

`CaptureSessionRequestByAnsweringTheTokenRequest` went Passed → Failed in the same run. 4-0n changes `Retry.BuildPayload`, and that test answers a TokenRequest with a Retry, so the causal link had to be checked rather than assumed.

**It is not the cause.** The test fails on the *first datagram it receives*, before it sends anything at all — it publishes a RouterInfo, starts i2pd, and waits. Nothing we build can influence what i2pd opens with. It is the flake already recorded against run #34, and the new detail worth keeping is the number: the first datagram was **63 bytes**, one byte under `SSU2Host.DispatchPacket`'s 64-byte floor, so whatever it is, it is not the TokenRequest the test wants and our own dispatcher would drop it too.

**Next, in order:** carry an I2NP message to i2pd over the established session — that is the measurement 4-5 actually depends on, and nothing before it should be read as SSU2 being usable.

### Session 6 (continued) — batch 4-1c — **does the session actually carry anything?**

4-0n established a session with i2pd. **That is not the same as a transport**, and the gap matters because 4-5 turns SSU2 on by default: the data phase uses different keys, a short header, and its own packet-number and ACK bookkeeping, none of which a handshake exercises.

`CSharpDeliversAnI2npMessageToI2pdOverSsu2` sends a DatabaseStore of our own RouterInfo — what a real router sends first on a new session, so a rejection is about our framing and not about i2pd objecting to something it never asked for — and waits for `UnackedPacketCount` to return to zero.

**The observable is i2pd's acknowledgement, not our own send returning.** Zero unacked means i2pd received the datagram, accepted it under the data-phase keys, and said so in an ACK block we then parsed. A test asserting only that `Send` was called would have passed against a black hole, which is exactly what the four CI runs before 4-0n were.

The establishment path is now shared by both tests, on separate ports and separate i2pd instances, so neither depends on the other's teardown. Locally both still `Assert.Ignore` — i2pd 2.45.1 refuses us at its endpoint check — so **this answer comes from CI, like every SSU2 interop claim before it.**

### Session 6 (continued) — batch 5-3 — **the tag window is a window now**

**Unit suite 316 passed / 0 failed / 1 skipped** (317 total). `SustainedTrafficExceedingTheTagWindow` is **un-quarantined and green**: 100000 messages in 2.5 seconds, where it previously stopped dead at 5000.

`InitializeBiDirectionalTags` drained two `ECIESTagSet` generators into a fixed block and dropped them. They are now kept alive, the initial block becomes the width of a window, and each consumed tag generates exactly one more — so the cost is O(1) per message rather than a bigger block. Expiry behind is bounded and only sweeps when the set has actually grown past its bound, because an O(n) sweep per message at 100000 messages is its own defect.

#### The half that was not in the plan's description, and cost a round to find

The plan scoped this as `ECIESSessions.cs:373-400`. Sliding the session's own window was not enough: **`ECIESSessionKeyManager` snapshots `session.InboundTags` into `_tagToDestination` at five separate call sites**, once, at handshake time. That snapshot is correct only while the tags are a fixed block. With a window, message 5001 arrives with a perfectly valid tag that routes nowhere.

It fails as an *unrecognised tag*, so the symptom was `All variants failed: [IK:ArgumentException...]` — the message being retried as a fresh handshake. **A bookkeeping bug wearing a crypto bug's clothes**, and the second one this session (`Invalid Address block size` was the first).

The five sites are now one `TrackInboundTags` that seeds *and* subscribes, and the session raises `InboundTagAdded` / `InboundTagExpired` as the window moves.

#### And a second, subtler misfiling underneath it

Routing the new tags to `session.RemoteHash` produced `Session not found`. A responder's session carries a **temporary** ident hash derived straight from the remote static key, while `_sessions` is keyed by `GetRemoteHash`, which may already know the real one. `CurrentHashFor` therefore returns `RemoteHash` only when the session is actually filed under it, and the captured hash otherwise — the two converge once `ConfirmRemoteHash` re-keys both together.

#### What this does not do

**It does not make a session immortal, and Gate 5 should not be read as met.** A window that always slides forward has no upper bound on how far the two sides may drift apart if messages are lost, and there is still no DH ratchet — that is 5-4, and `RatchetTagSet.NextKeyHandler` is kept for it (batch 5-1). What this buys is that ">10 MB sustained" is no longer arithmetically impossible.

### Session 6 (continued) — **4-1c answered: the session carries traffic**

CI on `84a4e7a`:

```
SSU2-Out-D62FC7A2: Session established
final state Established after 4 sent / 2 received
after send: 0 unacked, 8 sent / 16 received
```

`CSharpDeliversAnI2npMessageToI2pdOverSsu2` **passed**. i2pd acknowledged our I2NP message, so the data-phase keys, the short header, the packet numbering and our ACK parsing all agree with a real peer — not just the handshake. Integration moved **30 passed / 21 failed → 32 / 20** (one test added).

**SSU2 still stays off by default.** Inbound sessions *from* i2pd remain untested and sustained transfer is unmeasured; 4-5's gate is the suite, and the suite is not green.

#### The remaining 20 failures, and a hard look at what they are

Almost none of them are SSU2. They are 5 MB transfers, SAM sessions, streaming and LeaseSet publication — Phase 5 and Phase 6 territory. **Two of them deserve to change how the rest are read:**

```
TestSend5MB_I2pd0_To_I2pd1
TestSend5MB_I2pd2_To_I2pd3
```

**Those are i2pd talking to i2pd. Our router is not in the path.** Whatever makes them fail is the fixture, the tunnel setup, the netid, or the environment — it cannot be our transport or our streaming code. Until that is explained, **every conclusion drawn from the other five-megabyte tests is suspect**, because they share the same harness and the same tunnel plumbing with two tests that fail without us.

That is worth its own batch before Phase 5 work is scoped off these numbers: this plan has twice recorded a failure as ours that turned out to be the fixture's (batch 4-0c, batch 4-0f), and the cheapest way to avoid a third is to explain the two failures we provably did not cause.

**Next: explain `TestSend5MB_I2pd0_To_I2pd1` before treating any 5 MB failure as a product defect.**

#### Correction, same session — the two i2pd-to-i2pd failures *are* ours, and they are the most informative failures in the suite

The note above says our router is not in the path for `TestSend5MB_I2pd0_To_I2pd1` and that the failures therefore cannot be ours. **That is wrong**, and reading the test rather than its name says so plainly:

> i2pd 0 sends 5MB to i2pd 1. Both endpoints are i2pd; **C# routers serve as tunnel participants.**
> This is the critical test: proves C# routers correctly relay tunnel traffic as intermediate hops for i2pd.

Both endpoints being i2pd is exactly what makes our router the *only* variable: everything else in the path is a reference implementation.

**And the failure mode is corruption, not loss:**

```
Sent 5242880 bytes
Received 5242880 bytes
SHA-256 mismatch!
```

Every byte arrives, and the count is exact — so streaming, tunnel build, LeaseSet lookup and reassembly all work end to end. What comes out the other side is not what went in. **A length-preserving content mismatch through a hop is the signature of the tunnel layer's own crypto or fragment handling**, which is precisely what the README already records as broken (Outbound Endpoint, Inbound Gateway) and what batch 6-2 owns.

So the conclusion inverts. These are not fixture noise to be explained away before Phase 5 — **they are the sharpest measurement of the transit-tunnel defect in the whole suite**, because they isolate our code as the only non-reference component. 6-2 previously said "static reading found no defect"; this is the dynamic evidence it lacked, and the 5 MB transfers that involve our *endpoints* rather than our *hops* should be read only after it is fixed, since they cannot distinguish the two.

**Next: batch 6-2, driven by this.** A hop that preserves length and destroys content narrows it a long way — it is not routing, not reassembly boundaries and not tunnel build; it is layer encryption or fragment ordering inside a tunnel we participate in.

### Session 7 — batch 3-7 — **the corruption was ours, but it was in the harness**

The entry above says the 5 MB SHA-256 mismatch is "the sharpest measurement of the transit-tunnel defect in the whole suite". **It is not a measurement of the tunnel layer at all.** The receiving side of the test harness was counting a protocol line as payload.

**Unit suite 318 passed / 0 failed / 1 skipped** (319 total), Release build 0 errors.

#### What the reference implementation does, and what we did with it

On `STREAM ACCEPT` with `SILENT=false` — the default, and what `SAMHelper` sends — a SAM v3 bridge writes the peer's destination, base64 and newline-terminated, as **the first bytes of the data stream**. Not a reply: the head of the payload. i2pd, `SAM.cpp`, `SAMSocket::HandleI2PAccept`:

```cpp
auto ident = std::make_shared<std::string>(stream->GetRemoteIdentity()->ToBase64 ());
ident->push_back ('\n');
// send remote peer address back to client like received from stream
boost::asio::async_write (m_Socket, boost::asio::buffer (ident->data (), ident->size ()), ...
```

`SAMHelper.StreamAcceptAsync` read the `STREAM STATUS` line and stopped. `ReceiveDataAsync(expectedSize)` then read **exactly** `expectedSize` bytes from the same socket, the first ~517 of which were that destination line.

So the two observations the previous entry reasoned from —

```
Sent 5242880 bytes
Received 5242880 bytes
SHA-256 mismatch!
```

— are not two facts. **The byte count is not an observation**: the harness reads a fixed count by construction, and would report it against a black hole that emitted anything at all. The only fact is the mismatch, and a body shifted by one line explains it without involving a tunnel.

#### The inference that failed, and it is the same one twice

The previous entry inverted an earlier conclusion by reading the test's *doc comment* ("C# routers serve as tunnel participants … proves C# routers correctly relay tunnel traffic") and concluding our router was the only variable. Two things were wrong with that:

- **The fixture is one C# router and nine i2pd.** Whether our router appears in a 2-hop tunnel is i2pd's peer-selection decision, not the fixture's. "C# as hops" is a hope the test name states as a fact.
- **The harness is ours too.** "Our code is the only non-reference component in the path" was true, and the component it indicted was the one nobody was looking at, because the path was assumed to end at the SAM socket.

Worth naming plainly, because this plan keeps meeting it: **the test's name and comment were treated as evidence of what the test measures.**

#### And the CI run said something else again

The entry above attributes corruption to both i2pd→i2pd tests. In the run it was written from (`31352682437`), `TestSend5MB_I2pd0_To_I2pd1` failed with `CANT_REACH_PEER MESSAGE="LeaseSet not found"` — it never transferred a byte. **Exactly one test in the entire suite reached the hash comparison**, `TestSend5MB_I2pd2_To_I2pd3`, and it is the one with an i2pd receiver. Every other 5 MB test died earlier, at `STREAM CONNECT`.

#### Our own bridge had the mirror defect, twice

`SAMBridge.HandleStreamAcceptAsync` never wrote the destination line — the `if (!silent)` branch and its `else` were **identical**, with a comment describing the behaviour the code did not have. So a conforming SAM client talking to us consumes our first ~517 payload bytes as a destination and shifts everything after. Symmetric to the harness bug, and undetectable by our own tests, because our harness and our bridge agreed with each other and with nothing else — the eighth instance of this plan's signature defect.

The same handler also deferred `STREAM STATUS RESULT=OK` until a peer connected. i2pd sends it immediately (`ProcessStreamAccept`: reply, *then* arm `AcceptOnce`), and the spec makes it the answer to the command. A client that waits for the status before telling its peer to connect deadlocks against us. Both are fixed here, plus the same destination line on `STREAM FORWARD`.

#### The guard runs in the unit suite, and it was red first

`SamAcceptDestinationLineTest` pairs `SAMHelper` with a fake SAM bridge on a loopback `TcpListener` — no i2pd, no I2P network, 160 ms. Two tests: a bridge that sends the line, asserting the payload starts after it; and a bridge that omits it, asserting the helper **rejects** that rather than shifting silently. Both were confirmed red against the previous behaviour before the fix went in.

The helper checks the *shape* of the line (≥516 base64 characters), not merely that a line arrived. Against a bridge that omits it, a length check is the difference between failing here and failing 5 MB later: the read would otherwise return whatever payload precedes the first `0x0A` byte and look like a short destination.

#### What this does not settle

- **It does not mean transit tunnels work.** It means the evidence that they are broken has been withdrawn. README's "Outbound Endpoint: Broken / Inbound Gateway: Broken" is back to being an unmeasured claim inherited from the original author, and 6-2 is back to having no dynamic evidence — as it was before the previous entry, not worse.
- **It does not predict a green `TestSend5MB_I2pd2_To_I2pd3`.** It removes one cause of failure from a test that has never got past it. Anything the transfer hits after byte 517 is now visible for the first time.
- **A local reproduction was attempted and failed.** Three attempts at a private netid-99 network (one i2pd, then two cross-seeded, then two destinations inside one router) all died at `Remote LeaseSet not found` before delivering a byte, so the byte-level shape of the corruption is *not* confirmed by observation here. What is confirmed is i2pd's source, which is the code that produced the failing run.

**Next: CI on this branch.** `TestSend5MB_I2pd2_To_I2pd3` is the one test that reaches a hash comparison, and its next failure — or pass — is the first honest reading the 5 MB path has had.

#### Addendum, same session — CI answered, and the answer is unambiguous

PR #42, run `31359793794`: build green, unit **318 / 0 / 1**, integration **33 passed / 19 failed / 3 skipped** (was 32 / 20 / 3).

**`TestSend5MB_I2pd2_To_I2pd3` passes. So does `TestSend5MB_I2pd0_To_I2pd1`.** Both are absent from the failed list, the totals are unchanged at 55, and nothing was newly skipped. Five megabytes now cross the scaled network between two i2pd endpoints with a matching SHA-256.

So the "length-preserving content mismatch, the signature of tunnel-layer crypto" was a missing `ReadLine`. **Nothing in `TunnelLayer` was touched by this batch**, which is the whole point: had 6-2 been executed as scoped, it would have been a search for a defect in code that was working, guided by a measurement that was not one.

One test moved the other way — `CaptureSessionRequestByAnsweringTheTokenRequest`, the flake already recorded against runs #34 and `b71f8cc`, which fails on the first datagram i2pd sends before we transmit anything. Net −2 +1 = 19.

#### The failure mode of the rest changed, and that is the next lead

Nine tests that used to die at `STREAM CONNECT` with `CANT_REACH_PEER` now die *later*, and several die inside the new destination-line read:

```
TestSend5MB_I2pd0_To_CSharp0 — System.OperationCanceledException
   at SAMHelper.ReadLineAsync(Int32 timeoutMs)
   at SAMHelper.StreamAcceptAsync(String sessionId)
```

That is not a regression — the same tests failed in the previous run for the same underlying reason — but it relocates the report to a more informative place. **A 120-second wait for a peer destination that never arrives means no stream was ever accepted**, so for the C#-receiver cases it points at our own accept path or the LeaseSet the sender needs, not at the transfer.

**Next, and it is not 6-2.** Nineteen failures are dominated by one signature: `CANT_REACH_PEER MESSAGE="LeaseSet not found"` / `"Destination not found"` at `STREAM CONNECT`, plus `LeaseSetLookupAndEncryptionVerification` and `SamDataTransferWithLeaseSetLookup` failing their lookups outright. LeaseSet publication and lookup in the scaled fixture gates almost everything left in Phases 5 and 6 — including every transfer that involves one of our endpoints, which is now the only category of 5 MB test still failing.

### Session 7 (continued) — batch 3-8 — **the LeaseSet the network was asked for did not exist**

Nineteen integration failures were dominated by LeaseSet lookups, and the two most direct — `LeaseSetLookupAndEncryptionVerification` and `SamDataTransferWithLeaseSetLookup` — were **asking every floodfill in the network for a hash that is not an identity**.

**Unit suite 322 passed / 0 failed / 1 skipped** (323 total), Release build 0 errors.

#### The evidence came from both ends of the same lookup

Our router's log, ten times, fifteen seconds apart:

```
IdentResolver: Starting lookup of LeaseSet for [ck2hk].
IdentResolver: ECIES garlic-wrapped DLM for [ck2hk] to ff [yekl3]
```

and the floodfill's log — the CI artifacts include every i2pd's debug log, which is what made this quick:

```
06:10:32@510/debug - NetDb: Requested LeaseSet not found for ck2hke3b5mpmlwyc5bryyoc5eb2g4vxvj7o6ev5djuxw3txsprxa
```

**Our DatabaseLookup arrives, is parsed, and is answered.** The garlic wrapping, the reply tunnel, the tunnel-borne lookup path — all working. i2pd simply does not have that LeaseSet. Neither does the router **hosting** the destination, which answers "not found" for it too.

That last detail is the one that gives it away: a router always knows its own client's LeaseSet. So the hash being asked for is not that destination's hash.

#### What `SESSION STATUS` actually returns

```cpp
std::string priv = session->GetLocalDestination ()->GetPrivateKeys ().ToBase64 ();
snprintf (m_Buffer, ..., SAM_SESSION_CREATE_REPLY_OK, priv.c_str ());
```

The **private keys**, destination-first — not the destination. Both tests did:

```csharp
// SAM destinations are base64-encoded full Destination (keys+cert)
var destBytes = FreenetBase64.Decode(destBase64);
var destHash = SHA256(destBytes, 0, destBytes.Length);
```

The comment states the belief the code depends on, and it is wrong. `SHA256` over a key blob is not a routable identity, so **no answer existed to be found** — which is exactly what 150 seconds of correct floodfill responses reported.

**The lengths were in the log the whole time**, printed by the harness itself:

```
[C# 0 → i2pd 0]      Receiver session created (884 chars)
[i2pd 0 → C# 0]      Receiver session created (524 chars)
```

884 against 524. Two different contracts from the same field, logged side by side, for as long as the tests have existed.

#### Our bridge sent the wrong one, and had already computed the right one

`SAMBridge` replied with the bare 391-byte destination. Three lines above the reply:

```csharp
var privKeyBase64 = destInfo.ToBase64();   // computed, never used
```

So the conformant value was sitting there unused, and a SAM client of ours could not persist a TRANSIENT destination across reconnects — the entire reason the field carries keys.

#### Two design decisions worth stating

- **`StreamConnectAsync` now normalises whatever it is handed down to a destination.** Callers pass the SESSION CREATE reply, and CONNECT takes a destination. Both i2pd and our bridge happen to parse the identity off the front of a longer blob, so this worked by tolerance on both sides — the harness should not be resting on that, and after the bridge change the blob would have got longer.
- **The unit guard asserts the negative as well as the positive.** `HashingTheWholeBlobYieldsSomethingThatIsNotTheDestination` states the defect as a test, because the failure mode is not "wrong answer" but "a question with no answer" — indistinguishable, from the caller's side, from a network that cannot look anything up.

#### What this does not settle

**It does not mean LeaseSet lookup works.** It means two of the tests that said it does not were asking an unanswerable question. The remaining `CANT_REACH_PEER` failures at `STREAM CONNECT` are unaffected by this batch — those pass a real destination — and they stay the open question. The MultiHop fixture is the sharper case there: `TestSend5MB_I2pdA_To_I2pdB_MultiHop` is **i2pd to i2pd** and still fails with `LeaseSet not found`, which points at that fixture's network rather than at our router, exactly as the scaled fixture's equivalent test did before 3-7 fixed the harness.

**Next: CI, then the MultiHop fixture's LeaseSet publication** — and the discriminator is already known, so it need not be guessed at: if i2pd cannot reach i2pd there, the fixture is the suspect before we are.

#### Addendum — CI on 3-8, and the alternating test settled by running the same commit twice

PR #43, run `31371030221`. Build green, unit **322 / 0 / 1**. Integration, **two runs of the identical commit**:

| | passed | failed |
|---|---|---|
| run 1 | 34 | 18 |
| run 2 | 35 | 17 |

`TestSend5MB_I2pd2_To_I2pd3` failed in the first and passed in the second. **Same commit, so it is fixture flakiness, not a regression** — and it is worth having spent the 30 minutes to establish that rather than reasoning about it, because the batch had changed the very string that test passes to `STREAM CONNECT`. (The other half of the argument: `TestSend5MB_I2pd0_To_I2pd1` passed in run 1 through the identical normalisation, and a malformed destination draws `INVALID_KEY`, not `LeaseSet not found`.)

3-8 did what it was for: `LeaseSetLookupAndEncryptionVerification` **passes**, and `SamDataTransferWithLeaseSetLookup` now gets *past* the LeaseSet assertion — `Receiver LeaseSet found: I2PLeaseSet2, 2 leases` — before failing three seconds later at `STREAM CONNECT`.

### The next batch, diagnosed but not implemented — **client-scoped lookups never ask anyone**

From the C# router's own log in that run:

```
09:31:35  FloodfillServer: Storing LeaseSet for [nhlto] (Type LeaseSet2)
09:32:05  FloodfillServer: Storing LeaseSet for [nhlto] (Type LeaseSet2)
09:32:10  IdentResolver: Starting lookup of LeaseSet for [nhlto].
09:32:11  IdentResolver: Lookup of LeaseSet [nhlto] failed: no more floodfills to try
```

Three facts, none of them inferred:

- **We are the floodfill that holds it.** i2pd published that exact LeaseSet to us twice in the preceding 35 seconds and we stored it.
- **No DatabaseLookup was ever sent.** There is not one `LS lookup … -> ff …` line between the start and the failure — in fact **zero in the entire run**. `GetClosestFloodfill` returned an empty candidate set, so `ToTry` stayed empty and the next timeout tick failed the lookup one second later.
- **It is not LeaseSet-specific and not client-specific in its mechanism.** RouterInfo lookups fail the same way later in the run, and the NetDb report prints its `Floodfill routers` header with **no rows under it** — while `FloodfillUpdater: Publishing LS to ECIES FF [epfpe]` succeeds two seconds before the failed lookup.

So two components disagree about whether this router knows any floodfills, and the one that says "none" is the one that answers `STREAM CONNECT`. That is the single largest remaining signature in the integration suite: every `CANT_REACH_PEER MESSAGE="Destination not found"` is this.

**A decision is needed before the obvious fix.** The shortest path — answer a client's lookup from the LeaseSet we already hold in our own floodfill store — is precisely what `CLAUDE.md` forbids: *"Do not 'fix' a missing-LeaseSet bug by reaching for the global NetDb."* The invariant is deliberate and about anonymity, so it is not for an executing session to overturn. **The empty candidate set is a defect on its own terms** and can be fixed without touching the invariant; that is the batch. Whether a floodfill router may serve its own clients from its own store is a separate question, and it belongs to whoever owns the invariant.

### Session 7 (continued) — batch 3-9 — **asking for a floodfill and being handed something else**

The previous entry left a decision pending: whether a floodfill router may serve its own clients from its own store. **It turned out not to be the question.**

**Unit suite 328 passed / 0 failed / 1 skipped** (329 total), Release build 0 errors.

#### What the protocol actually says

`geti2p.net/en/docs/how/network-database`, section *Network Database Segmentation — Sub-Databases*, states the invariant `CLAUDE.md` carries, and gives the reason:

> …to prevent a class of attacks where a malicious actor can try to associate a client tunnel with a router by sending a store to a client tunnel, then requesting it back directly from the suspected "Host" of the client tunnel.

> **A client should never answer queries with an entry from the main netDb, only it's own client network database.**

So the invariant is spec-backed and stands. **But it is narrower than it reads**: it governs *LeaseSets*, and it governs *answering*. RouterInfos are explicitly not segmented — the same section says the main netDb is used "for direct lookups **and floodfill operations** first", and Java's client sub-database refuses to hold RouterInfos at all:

```java
public RouterInfo lookupRouterInfoLocally(Hash key) {
    // Client netDb shouldn't have RI, search for RI in the floodfill netDb.
    if (isClientDb()) { ... return null; }
```

`OutboundClientMessageOneShotJob` shows the split in one file: the LeaseSet from `ctx.clientNetDb(_from).lookupLeaseSetLocally(...)`, the lease's gateway RouterInfo from `getContext().netDb()`. i2pd matches — `LeaseSetDestination::FindLeaseSet` reads a per-destination map with no main-netdb fallback, while RouterInfo requests go to `i2p::data::netdb`.

**Floodfill selection is a RouterInfo operation.** No decision was needed; the shortcut that needed permission was never the one that had to be taken.

#### Following the asymmetry rather than the theory

The batch was scoped from a wrong guess and corrected twice by measurement, which is worth recording as the method:

1. *"The `/24` IP-diversity filter collapses the candidate list on a loopback network."* Plausible, and wrong — the filter always admits its first candidate, so it cannot produce zero.
2. *"`FloodfillInfos` is empty."* The NetDb report prints `Floodfill routers` with no rows, so this looked settled — until `FloodfillUpdater` was seen publishing to **six distinct floodfills** in a network that has two, minutes after that empty report.

The second observation is the one that pays. Six floodfills cannot come from a set of two, so the selector was not returning floodfills at all:

```csharp
private I2PIdentHash GetRandomRouter(
    RouletteSelection<...> r,          // the floodfill roulette, for a floodfill request
    ...
    if (exploratory)
    {
        var subset = RouterInfos.Values   // and here it is ignored
```

Three paths did this: the `exploratory` branch unconditionally, its own empty-subset fallback, and the non-exploratory fallback when the roulette came up empty. **Every route to a floodfill could return a router that is not one**, and the caller had no way to know — `FloodfillUpdater` logs `Publishing LS to ECIES FF [x]` either way.

#### Why that is the other half of the suite

A LeaseSet published to a non-floodfill is discarded. From every other router, that is indistinguishable from a destination whose LeaseSet cannot be found — which is exactly what i2pd reports for our destinations in `TestSend5MB_I2pd0_To_CSharp0`, `TestSend5MB_I2pdToCSharp_SAM`, `TestBidirectional5MB_SAM` and `TestSend5MB_I2pdB_To_CSharpA_MultiHop`. **The failures are on the publish side, not the lookup side**, which is not where two sessions of evidence pointed.

#### Two more defects found by writing the test rather than by reading

- `RouletteSelection.GetWeightedRandom` ends in `Wheel.Random().Id`, and `Random()` on an empty wheel returns null — so *any* non-exploratory floodfill request threw `NullReferenceException` once the floodfill set was empty. Guarded at the call site on the roulette's own `Count`.
- `GetRandomRouter` dereferenced `TransportProvider.Inst` unconditionally, so a NetDb query before the transport layer starts threw. Reachable in production during startup, and it made the code untestable without a full router.

Neither was visible from reading; both appeared the moment a test drove the function with an empty NetDb.

#### The guard, and what it asserts

`FloodfillSelectionTest` starts an isolated NetDb, adds signed RouterInfos with real `caps` values, and asserts (a) with no floodfills known, every form of the request returns **nothing** rather than a substitute, and (b) with three known among nine routers, forty draws on each of the exploratory and non-exploratory paths are all floodfills. Confirmed red first: `selected [dezjn] has caps 'X', which is not a floodfill (exploratory=True)`.

`FloodfillRecognitionTest` pins the layer underneath against **a real i2pd 2.45.1 floodfill RouterInfo** checked in as `TestData/routerinfo_floodfill_i2pd.dat` — caps parsed, `f` recognised, signature verified. That fixture exists because the first hypothesis was "we misparse i2pd's caps"; it is checked in rather than discarded, because the next reader deserves the answer to that question without re-deriving it.

#### What this does not settle

**It does not explain why the floodfill set is empty in the first place.** The scaled fixture starts two floodfill i2pds and injects their RouterInfos, and by the time of the failures our NetDb held 8 routers with **none** classified as floodfill. Parsing is now proven innocent, so the remaining candidates are the injection path, an update replacing those entries with something lacking `caps=f`, or eviction. That is the next batch, and the new `LogWarning` in `GetRandomRouter` — floodfills known, routers known, excluded — is there to name it in the next CI run.

#### Addendum — CI on 3-9, and the diagnostic answering on its first run

PR #44, run `31393168558`. Build green, unit **328 / 0 / 1**, integration **34 passed / 18 failed** — inside the 33–35 band three runs of near-identical commits have now established, so no movement attributable either way.

The batch's purpose was the warning, and it fired **120 times**:

```
FloodfillUpdater: no floodfill to publish [yfsog] to. Floodfills known: 0, routers known: 8
```

**Zero floodfills, eight routers.** Our LeaseSets were never published anywhere, by anyone, for the whole run. That is the publish-side half of the suite, now measured rather than argued.

And the layer under it is visible in the same log. We *do* receive floodfill RouterInfos —

```
I2PMapping: Pairs: ->(caps:XfR)(netId:99)(router.version:0.9.69)<-
Imported RouterInfo [yta3m] from /tmp/i2pd_scaled_0_.../router.info
Imported RouterInfo [wy4is] from /tmp/i2pd_scaled_1_.../router.info
```

— both floodfills, imported at 13:43:51, and gone from the index by 13:49:58.

### The next batch — **the floodfill index is a cache with different lifetime rules from its source**

```csharp
public void RemoveRouterInfo(I2PIdentHash hash)
{
    if (RouterInfos.TryGetValue(hash, out var p)) p.Meta.Deleted = true;   // soft, reversible
    FloodfillInfos.TryRemove(hash, out _);                                 // hard, and only an
                                                                           // update restores it
```

Both overloads do this, and the only caller that matters is `RemoveOldRouterInfos()` → `Statistics.GetInactive()` → everything `NodeInactive` judges idle. In this fixture we reach the floodfills *through tunnels* rather than by direct transport, so "inactive" is exactly what they look like.

`AddRouterInfo` does put a floodfill back — but only on the update branch, which requires a RouterInfo more than two seconds newer than the one we hold. Between sweeps, nothing restores it.

**Two things to settle before touching it, in this order:**

1. **Are the other 8 marked `Deleted` too?** `RouterCount` counts entries including deleted ones, so "8 routers known" may itself be overstating what we can use. Deletion is filtered at read time in the roulette and in `GetRandomRouter`, but **not** in `GetClosestFloodfill` — three readers, two rules.
2. **Why does `NodeInactive` fire on peers we are actively using?** That is the actual question, and the answer is currently unreadable in CI: `RoutersStatistics.GetInactive` reports its reasons under `#if DEBUG`, so a Release run cannot say why anything was swept. This is the plan's founding complaint — an undiagnosable Release build — surviving in one more place, and it should be fixed first for the same reason batch 0-1 came first.

### Session 7 (continued) — batch 3-10 — **the sweep that empties the floodfill index, made readable**

3-9 ended with a question it could not answer from CI: *why does `NodeInactive` fire on peers we are actively using?* The reason breakdown exists. It was compiled out.

**Unit suite 329 passed / 0 failed / 1 skipped** (330 total), Release build 0 errors.

```csharp
private bool TestInactive(Func<bool> test, string desc)
{
    var result = test();
#if DEBUG
    if (UpdateInactiveStatistics && result) AddInactiveReason(desc);
#endif
    return result;
}
```

Five such blocks in `RoutersStatistics`, and they do not merely suppress the report — `UpdateInactiveStatistics` is only ever *set* inside one of them, so in a Release build `NodeInactiveReason` is never populated at all. The dictionary, the `PeriodicAction` and the reporting code are all `#if DEBUG` too.

**This is the plan's founding defect in its second form.** Batch 0-1 removed `[Conditional("DEBUG")]` from eleven logging methods for exactly this reason, and `LoggingVisibilityTest` guards against its return. The same mistake survived here in preprocessor form, in the subsystem whose behaviour Phase 3 has spent this whole session trying to explain.

#### What changed

- **Reason tracking is unconditional**, and the report runs at `Warning` rather than `Debug`. It is one dictionary increment, on the inactive path only, once per statistic — and gating the recording on `Debug` would have left the report with nothing to say at the default level, which is precisely the trap being fixed.
- **`InformationFaulty` is now a reason like any other.** It was checked first and returned early, so the one condition that marks a peer inactive *permanently* — a single faulty RouterInfo, never reset — was the one condition that never appeared in the breakdown.
- **The report says how many of how many**: `N of M routers inactive`, from the set `GetInactive` has already computed. Calling `NodeInactive` again to count would have recorded reasons for every router it walked, so the diagnostic would have altered what it measures.
- **The NetDb report prints counts**: `N routers known (D deleted), F floodfills, L leasesets`, and each roulette header carries its own size. An empty section used to print a header and nothing, which reads as a truncated report rather than as "we know zero floodfills" — the difference between looking at NetDb and looking somewhere else, and it cost an hour of this session.
- Two further `#if DEBUG` diagnostics in `NetDb.cs` and `NetDb.Reports.cs` are converted; the latter samples and formats before it logs, so it is guarded by `Logging.IsEnabled` rather than left to the interpolated-string handler, which can only skip formatting it is handed.

#### The guard

`NetDbDiagnosticsVisibilityTest` scans `src/I2PCore/NetDb` and fails on any `#if DEBUG`. Verified to bite by planting one (`NetDb.Store.cs:222`) and watching it go red. It strips comments before matching, which makes the fix's own comment — it names the banned construct — a live check that the stripping works, the same trick 4-0d-fix2 used.

#### What this does not do

**It fixes nothing about the sweep itself.** The asymmetric removal recorded in the previous entry is untouched: `RemoveRouterInfo` still soft-deletes in `RouterInfos` and hard-removes from `FloodfillInfos`, and only a strictly newer RouterInfo restores it. That is deliberate — the next batch should be driven by the reason breakdown this one makes visible, not by a guess about which of the six inactivity tests is firing. **Next: read `RoutersStatistics: N of M routers inactive. Reasons: …` from the next CI run, then fix the sweep or the statistic it trusts.**

#### Addendum — CI on 3-10, and the diagnostic answering in one line

PR #45, run `31414288923`. Build green, unit **329 / 0 / 1**, integration **34 passed / 18 failed**, the same band three runs have now held (the job itself reports green; it is `continue-on-error`). The reason breakdown fired twice, and said the same thing both times:

```
RoutersStatistics: 3 of 11 routers inactive. Reasons: FloodfillUpdateTimeout: 3 (100.0%)
RoutersStatistics: 1 of  4 routers inactive. Reasons: FloodfillUpdateTimeout: 1 (100.0%)
```

**Not one of the other five tests fired.** Nothing was swept for failed tunnel builds, failed connects, unresolvable idents or age. Every router the sweep removed — including both floodfills, which is what empties the index — was removed for failing to answer a publish.

So the question changed from "why does the sweep fire" to "why does no floodfill ever answer us", which the same artifacts settle.

### Session 7 (continued) — batch 3-11 — **we publish our RouterInfo in a form no modern floodfill can decrypt**

**Unit suite 333 passed / 0 failed / 1 skipped** (334 total, +4), Release build 0 errors.

`SendUpdate` — the RouterInfo publish — wrapped its DatabaseStore with `Garlic.EgEncryptGarlic`, unconditionally. So did `TimeoutRegenerateLsUpdate`, the LeaseSet *retry*. Only `StartNewUpdatesLeaseSetInternal`, one of four garlic sends in the file, asked what key the recipient holds.

Every i2pd since 2.36 has an X25519 identity. Handed an ElGamal block, it reads the first 32 bytes as a Noise N ephemeral key, finds something that is not a curve point, and drops the message.

#### The evidence, from the 3-10 artifacts

Our sends, and the two floodfills' reactions, to the second:

```
17:45:44 FloodfillUpdater: RI replacement update [lueyf]     17:45:44 i2pd_scaled_0 warn - Garlic: Incorrect N ephemeral public key
17:46:08 FloodfillUpdater: RI replacement update [lueyf]     17:46:08 i2pd_scaled_0 warn - Garlic: Incorrect N ephemeral public key
17:46:32 FloodfillUpdater: RI replacement update [lueyf]     17:46:32 i2pd_scaled_0 warn - Garlic: Incorrect N ephemeral public key
17:46:56 FloodfillUpdater: RI replacement update [lueyf]     17:46:56 i2pd_scaled_0 warn - Garlic: Incorrect N ephemeral public key
17:47:44 … 17:49:20, four more                               same four seconds, i2pd_scaled_1
```

Twenty RouterInfo publishes in the run. **Zero delivery statuses for any of them** — the single `FloodfillUpdater: Floodfill delivery status … received` line in the whole log is an `LS`, from the one path that chose correctly. That is the whole chain: unreadable publish → no reply → `FloodfillUpdateTimeout` → the 100% above → both floodfills swept → `Floodfills known: 0` → nothing can be published at all, LeaseSets included, and every client is offline.

#### What changed

- **`Garlic.EciesEncryptGarlic`**, beside `EgEncryptGarlic`, because which one applies is a property of the recipient and the two belong in one place. It replaces two copies of the same twenty lines (`IdentResolver.WrapInEciesGarlic`, `FloodfillUpdater.SendLeaseSetUpdateEciesGarlic`) and takes any `I2NpMessage` rather than one message type each.
- **`FloodfillUpdater.WrapForFloodfill`** is now the only place the publisher decides. All four sends go through it.
- **`GetECIESPublicKey()` is the question**, not a `PublicKeyType` switch. For a hybrid identity the X25519 half is the *trailing* 32 bytes; the LeaseSet path passed `PublicKey.ToByteArray()` whole, which is correct only for a locally generated key and wrong for one parsed off the wire.
- **The two `SendLeaseSetUpdate*` methods collapse into one.** They differed only in the encryption they had already chosen.
- A retry that could not be sent no longer registers an outstanding request. It would have charged the floodfill a timeout for a message it never received — the same statistic this batch exists to stop corrupting.

#### The guard

`FloodfillPublishEncryptionTest`, four tests, all confirmed red against the pre-fix file:

- a RouterInfo we publish to an X25519 floodfill opens with **that floodfill's own Noise N responder**, and carries our ident and the reply token (without which no delivery status is ever sent, and a perfect publish still counts as a timeout);
- the same for an ML-KEM hybrid identity, which also pins `GetECIESPublicKey()` at 32 bytes;
- an identity that really does hold an ElGamal key still gets ElGamal — the fix is a choice, not a replacement;
- the publisher names an encryption function exactly twice, both inside `WrapForFloodfill`. The pre-fix file has three such calls, so the scan bites.

#### What this does not settle

1. **The reply is still requested direct, not through a tunnel.** `SendUpdate` sets reply gateway = us, reply tunnel = 0, so i2pd answers over transport and needs a session to us. Legal, and worse for anonymity than the LeaseSet path's inbound-tunnel reply. If publishes still time out in the next run, this is the next suspect, and it is a batch of its own.
2. **`TimeoutRegenerateRiUpdate` still throws `NullReferenceException`** when no floodfill is known — `list.Random()` returns null and line 406 dereferences it for a log message. 3-9 made the empty list legitimate; the sibling LS path already guards with `if (ff is null) continue`. It fired every 5 s in both CI logs, and it aborts `CheckTimeouts` **before** the LeaseSet retries, so those requests are never marked `TimedOut` and are re-counted as fresh timeouts on every pass until the 80 s window drops them — up to twelve charges for one unanswered publish, against a threshold of five. It is the amplifier that turned a slow failure into an emptied index. Left out of this batch so that the encryption fix can be measured on its own; **it is batch 3-12, and it should be the next thing done whatever the next CI run says.**
3. **The asymmetric removal from 3-9 is still there.** `RemoveRouterInfo` soft-deletes in `RouterInfos` and hard-removes from `FloodfillInfos`.

**Next: read the next CI run for `FloodfillUpdater: Floodfill delivery status RI …`. If it appears, the publish path works end-to-end against a real floodfill for the first time, and the sweep should stop taking floodfills with it.**

#### Addendum — CI on 3-11, and the first RouterInfo publish a floodfill has ever answered

PR #46, run `31568274081`, merged. Build green, unit **333 / 0 / 1**, integration **36 passed / 16 failed** — the band had been 34/18 for three runs.

```
05:59:05 FloodfillUpdater: Floodfill delivery status RI 1108014163 [udgxx] received in 18 mseconds.
06:11:42 FloodfillUpdater: Floodfill delivery status RI 3225614749 [3k52m] received in  2 mseconds.
```

Both are firsts. Against them:

- **Zero `Garlic: Incorrect N ephemeral public key`** across all ten i2pd logs, where 3-10 logged one per publish, at the second of each publish.
- **27 publishes, every one of them `publishing DatabaseStore to ECIES FF`.** Not one chose ElGamal. 12 were answered (2 RI, 10 LS) against 0 RI and 1 LS before.
- **No `RoutersStatistics: … routers inactive` line anywhere in the run.** That report returns early when no reason was recorded, so its absence is not a missing diagnostic — it means nothing was judged inactive at all. The NetDb reports hold at `11 routers known (0 deleted), 3 floodfills`, where 3-10 ended at `Floodfills known: 0`.
- **No `NullReferenceException` in either router log**, where 3-11's note recorded one every 5 s. The empty-list path in `TimeoutRegenerateRiUpdate` was simply never taken, because the index never emptied. The defect is latent, not fixed.

So the chain the last three batches traced — unreadable publish → no reply → `FloodfillUpdateTimeout` → floodfills swept → nothing publishable — is broken at its first link, and the two downstream symptoms disappeared with it.

**What did not move.** The 16 failures are the same set: `TestSAM_SessionCreate_I2pd` (`Expected SESSION STATUS, got:` — an empty reply), `TestSAM_DatagramSession_I2pd`, and fourteen 5 MB transfers failing as `SAM STREAM CONNECT failed` (`LeaseSet not found`, `CANT_REACH_PEER`) or `OperationCanceledException`. Publishing our RouterInfo is a precondition for those, not a cause of them.

### Session 8 — batch 3-12 — **one unanswered publish, one charge**

**Unit suite 336 passed / 0 failed / 1 skipped** (337 total, +3), Release build 0 errors.

The defect 3-11 deferred, and it is larger than the `NullReferenceException` it was filed as.

#### Three faults, one shape: a failure to *send* was recorded as a failure to *answer*

**1. The mark was in the wrong method.** `TimedOut` is what stops a request being charged again on the next pass, and it was set by the two regeneration methods, after `CheckTimeouts` had charged the statistic. So any request whose *replacement* could not be built stayed unmarked and was charged afresh every 5 s, for the 80 s the request lives.

Measured, not argued: with the null dereference patched but the mark left where it was, the guard test reports **`Expected: 1, But was: 5`** for a single unanswered publish. Five timeouts against two successes is exactly what `RoutersStatistics` requires to call a router inactive — so one publish that went unanswered was, on its own, enough to sweep the floodfill that failed to answer it.

**2. The dereference aborted the whole NetDb tick, not just the retry.** `list.Random()` on an empty floodfill list returns null; 3-9 made that list legitimately empty. The exception is caught by the NetDb worker's own `catch`, so what is lost is everything *after* the throw in that pass: the LeaseSet retries, `ProcessPendingUpdates`, `IdentHashLookup.Run()`, and `ImportNetDbFiles` — **the one thing that can put a floodfill back into an emptied index.** The failure was self-sustaining.

**3. `SendUpdate` could not report failure, and its caller assumed success.** It returned `void`, and both call sites registered an outstanding request regardless — the same defect 3-11 fixed on the LeaseSet retry, in the sibling path it did not touch. Two ways it silently fails:

- `TunnelProvider.Inst.GetEstablishedOutboundTunnel(...)` — `NetDb.Start()` runs before `TunnelProvider.Start()`, and the NetDb worker waits only for the *transport* layer, so the tunnel layer is legitimately null in the first moments of every startup, and `StartNewUpdateRouterInfo` is constructed with autotrigger set.
- The `TransportProvider.Send` fallback answers with a `bool` but **rethrows** anything it did not expect — and marks the destination `DestinationInformationFaulty` on the way out, which 3-10 showed is the one inactivity reason that is never reset. Our transport layer not being up could permanently condemn a floodfill.

#### What changed

- **The charge and the mark are one decision**, both in `CheckTimeouts`. Regenerating is separate and best-effort, and may legitimately do nothing.
- **An empty floodfill list returns**, after `GetNewFfList` has already logged why (3-9).
- **`SendUpdate` returns whether it sent**, tolerates a null tunnel layer, and converts a transport throw into `false`. Both callers register an outstanding request only on a true.
- The RI retry loop gets the per-request `try`/`catch` the initial publish loop has always had, so one unbuildable replacement costs one replacement.
- `rinfos.SelectMany(inf => FfUpdateRequestInfo.Exclude?.Select(e => e.Key))` — which repeats the whole exclude set once per request, and null-guards a `readonly static` that cannot be null — becomes `FfUpdateRequestInfo.Exclude.Select(e => e.Key)`, in both regeneration methods.

#### The guard

`FloodfillTimeoutChargingTest`, three tests, all confirmed red against the pre-fix file:

- with the index empty, `CheckTimeouts` does not throw, and five passes charge each of two outstanding publishes exactly once (pre-fix: `NullReferenceException`; with only the dereference fixed: 5 charges);
- a replacement that could not be sent is not left awaiting a reply, and the original stays marked;
- `TimedOut = true` appears exactly once in the file and within three lines of the charge — pre-fix it appears twice, in neither case inside `CheckTimeouts`.

The fixture boots a real NetDb into a temp directory on netid 3 with `Bootstrap.Disabled`, as `FloodfillSelectionTest` does, and backdates `FfUpdateRequestInfo.Start` with `TickCounter.Set` — `TimeDeltaMs` is modular, so "a minute ago" reads correctly however long the process has been up. `OutstandingRequests`, `CheckTimeouts` and `FfUpdateRequestInfo` become `internal` for it.

#### What this does not settle

1. **The RouterInfo reply is still requested direct, not through a tunnel** — 3-11's item 1, unchanged.
2. **`TransportProvider.Send` still rethrows from a method that returns `bool`**, and still records `DestinationInformationFaulty` for what may be our own fault. This batch stops that reaching the NetDb tick from one caller; the contract itself, and the permanence of that reason, are their own batch.
3. **The asymmetric removal from 3-9 is still there.**
4. **`2 + rinfos.Sum(inf => inf.Retries) * 2`** is always `2` for RouterInfo requests: the replacement is built with the constructor that has no retry count, so the sample widening never widens. Commented in place rather than changed, because making it live changes floodfill selection and nothing here can measure that.

**Next: the CI run for this batch should show the RI delivery statuses of 3-11 with no charge against a floodfill that answered, and the 16 integration failures are now the whole story — start at `TestSAM_SessionCreate_I2pd`, which answers an empty SESSION STATUS and is the cheapest of them to read.**

#### Addendum — CI on 3-12

PR #47, run `31624921565`, merged. Build green, unit **336 / 0 / 1**, integration **36 passed / 16 failed** — the same set as 3-11, no movement either way. What the batch was for is visible in the artifacts:

- **No `NullReferenceException` in either router log**, where the 3-10 run had one every 5 s.
- **The reason breakdown is no longer `FloodfillUpdateTimeout`.** It reads `1 of 4 routers inactive. Reasons: InformationFaulty: 1 (100.0%)` and `2 of 13 routers inactive. Reasons: FailedTunnelTest: 2 (100.0%)`. The statistic the sweep trusts now reports something other than our own accounting error.
- RI and LS delivery statuses continue to arrive (1 RI + 9 LS in the scaled run, 1 RI in the integration run).

### Session 9 — batch 3-13 — **the tunnel build reply, read the way i2pd reads it**

**Unit suite 339 passed / 0 failed / 1 skipped** (340 total, +3), Release build 0 errors.

Starting where 3-12 pointed — `TestSAM_SessionCreate_I2pd`, "Expected SESSION STATUS, got:" — the empty reply turns out not to be a SAM defect at all. i2pd defers `SESSION STATUS` until the session's destination has tunnels, and in that run it had none: **689 `Pending build request timeout, deleted`, 529 `Creating destination outbound tunnel...`, and not one tunnel built.** The two failing SAM tests are exactly the two that ask for default-length tunnels; every SAM test that passes sets `inbound.length=0 outbound.length=0`.

i2pd's tunnels in that fixture must run through us, and it says plainly why they cannot:

```
17:54:49 TunnelProvider: ECIES OBEP: Sent Garlic-wrapped build reply to IBGW [fm3ol]:3553813756
17:54:49 i2pd  warn  - Garlic: Symmetric key tagset unexpected block 0
17:54:49 i2pd  error - Garlic: Can't handle ECIES-X25519-AEAD-Ratchet message
```

**370 of those, one per reply we sent.**

#### Two defects, and what makes them one batch

**1. The payload must lead with the clove.** A tunnel build reply is wrapped in a garlic keyed by a one-time symmetric key and tag, both derived from the build record's Noise chaining key (`RGarlicKeyAndTag`). The receiver has no session to parse blocks against, so i2pd reads *exactly one* block and requires it to be the clove — `SymmetricKeyTagSet::HandleNextMessage` (`ECIESX25519AEADRatchetSession.cpp`) tests `buf[offset] != eECIESx25519BlkGalicClove` and returns false. Its own sender agrees: the symmetric `WrapECIESX25519Message` calls `CreateGarlicPayload(msg, payload, false, 956)` — datetime **off** — where the Noise N `WrapECIESX25519MessageForRouter` passes true. We led with a DateTime block on both paths.

**2. The reply's message ID comes from the record, not from the request.** The creator matches a reply against its pending tunnels by I2NP message ID, and the ID it waits for is the one it wrote into the endpoint record's send-message-ID field at offset 52. i2pd's endpoint reads exactly that: `FillI2NPMessageHeader (eI2NPShortTunnelBuildReply, bufbe32toh (clearText + SHORT_REQUEST_RECORD_SEND_MSG_ID_OFFSET))`. We copied `stbm.MessageId`, the arriving request's header ID — which is the same value **only because our own creator sets `stbm.MessageId = replymessageid`**, while i2pd's `Tunnel::Build` ends with a bare `FillI2NPMessageHeader (eI2NPShortTunnelBuild)` and `FillI2NPMessageHeader` fills an unset ID with `RAND_bytes`.

So the reply would have been dropped as an unknown pending tunnel even after the framing let it be read. That is why both are in one batch: fixing either alone moves nothing measurable.

**What was never wrong is worth recording.** i2pd *decrypted* our garlic — it reached a block-type check, which is past the AEAD — so the `RGarlicKeyAndTag` derivation, the tag byte order, the AD, and the nonce were all already correct. This is the plan's signature defect for the eighth time: our writer and our reader agreed with each other, and with nobody else.

#### The guard

`ObepBuildReplyFramingTest`, three tests, driving the new `TunnelProvider.CreateObepBuildReply` — the OBEP reply path lifted out of `HandleShortTunnelBuildRecords`, which needs a NetDb and a transport layer to reach. The decode is **hand-written against i2pd's layout** (`GarlicDestination::HandleECIESx25519GarlicClove`: flag | type | msgID | expiration | payload) rather than calling our own parser, because our parser is half of what hid the defect.

Confirmed red separately: reinstating the DateTime block fails all three; reinstating `MessageId = stbm.MessageId` fails one, on the assertion that the arriving message's ID matches nothing.

#### What this does not settle

1. **Whether i2pd then accepts the reply *records*.** Getting the garlic read is a precondition; the per-hop AEAD reply record under the reply key is the next gate, and nothing but a CI run can test it — `NoiseNSelfTest` only proves we agree with ourselves.
2. **The two SAM tests are still fixture-shaped.** `TestSAM_SessionCreate_I2pd` and `TestSAM_DatagramSession_I2pd` ask i2pd for default-length tunnels; if tunnels through us now build, they should pass, but neither test says what tunnel length it depends on. Worth pinning either way.
3. **Non-endpoint records carry `NextMessageId = 0`** (`VariableTunnelBuildMessage.cs:347,454`) where i2pd puts a random ID in every non-final record. Harmless as far as this reading goes — a forwarded build message's ID is matched by nobody — but it is a divergence, and it makes our outer STBM ID equal to the reply ID, which i2pd deliberately avoids.
4. **`TunnelProvider.cs:1814` still has an `#if DEBUG`** around a build-timeout diagnostic. 3-10 removed these from `src/I2PCore/NetDb` and `NetDbDiagnosticsVisibilityTest` guards that directory only; the tunnel layer has never been swept.

**Next: read the CI run for this batch for `Tunnels: Tunnel ... created` in the i2pd logs, and for the count of `Pending build request timeout, deleted` against the 689 above. If tunnels build, `TestSAM_SessionCreate_I2pd` and the fourteen 5 MB transfers are the ones to re-read; if they still time out, the reply *records* are the next suspect and the failure will have moved past the garlic.**

#### Addendum — CI on 3-13, and the first tunnel i2pd has ever built through us

PR #48, run `31629297607`, merged. Build green, unit **339 / 0 / 1**, integration **36 passed / 16 failed** — the same set, unmoved. What moved is underneath it, and the whole chain is in one place in i2pd's log:

```
18:47:03 Tunnel: Gateway of 969 bytes for tunnel 4078269471, msg type 11
18:47:03 Garlic: Type local
18:47:03 I2NP: Handling message with type 26
18:47:03 Tunnel: TunnelBuildReply for tunnel 752812528
18:47:03 Tunnel: TunnelBuildResponse 4 records.
18:47:03 Tunnel: Build response ret code=0
18:47:03 Tunnel: Outbound tunnel 752812528 has been created
```

Every step is a thing that had never happened before. `Garlic: Type local` is the clove being read (defect 1), `TunnelBuildReply for tunnel 752812528` is the reply reaching the right pending tunnel (defect 2 — the ID is matched, not merely present), and `ret code=0` is our reply record decrypting and parsing correctly under the reply key, which was the open question this batch could not test.

| | 3-12 run | 3-13 run |
|---|---|---|
| `Garlic: Symmetric key tagset unexpected block 0` | 370 | **0** |
| `Tunnel: Build response ret code=…` read at all | 0 | 1182 |
| `Tunnel: Outbound tunnel … has been created` | 0 | **2** |
| `Tunnel: Pending build request … timeout, deleted` | 689 | 399 |

Two built tunnels out of 529 attempts is not a working network, and the reason is now equally explicit — and it is ours:

```
528  TransitProvider AcceptingTunnels: Reject due same next destination
  3  Accepted
```

### The next batch — **the next-hop filter cannot tell a small network from an attack**

`TransitTunnelProvider.AcceptingTunnels` (`:398`) rejects a build when `NextHopFilter.Update(nextIdent)` says it has seen that next hop too recently. In a fixture with two routers there is exactly one next hop it can ever see, so the filter fires on nearly every request: **528 of 531 decisions**, answered with `RejectBandwidth`, which i2pd reads as `ret code=30` (726 of them) and logs as `Outbound tunnel … has been declined` (392 outbound, 71 inbound).

The filter is a real anti-enumeration defence and should not simply be deleted. What to settle before touching it:

1. **What does i2pd do here?** It throttles per-peer tunnel *requests* rather than refusing on next-hop repetition alone; a router with few peers must still carry traffic or a small network can never bootstrap.
2. **The rejection is silent to the operator.** `Reject due same next destination` is `LogDebug`, so a Release router at the default level declines every tunnel it is asked to carry and says nothing — the same complaint batches 0-1 and 3-10 were written for, in a third place.
3. **1086 requests decrypted against 531 accept/reject decisions.** Roughly half the build requests we decrypt never reach a decision at all. Where they go is unknown and should be counted before anything is tuned.

**Next: batch 3-14, the next-hop filter — and note that until it lands, every integration test that needs a tunnel through the C# router is measuring the filter, not the protocol.**

### Session 9 (continued) — batch 3-14 — **a router with one usable next hop must still carry tunnels**

**Unit suite 348 passed / 0 failed / 1 skipped** (349 total, +9), Release build 0 errors.

3-13 left the C# router able to answer a build request correctly and refusing to answer 528 of 531. Two causes, one in the throttle and one under it.

#### 1. The window was decorative

```csharp
list.AddLast( TickCounter.Now );
return list.Count < Limit;          // every entry ever recorded for this key
```

`ItemFilterWindow.Update` counted the whole list, where its siblings `Test` and `Count` both count `t.DeltaToNow < MemorySpan`. Entries leave only via `Cleanup`, which runs at most every 240 seconds and only when one of these methods is called — so a key under sustained load never fell back below its limit. Each refusal appended another entry; the ones a cleanup removed were replaced faster than they aged out. **The filter was not a rate limit, it was a latch.**

#### 2. The limit was a constant where both reference implementations use a curve

`new ItemFilterWindow<I2PIdentHash>( TickSpan.Minutes( 5 ), 2 )` — two requests per next hop per five minutes, whatever the router is doing. With the latch above, in practice one.

- **i2pd has no throttle of this kind at all.** `TransitTunnels::HandleShortTunnelBuildMsg` accepts unless tunnels are disabled, connectivity is limited, or `GetCongestionLevel()` — transit count against `DEFAULT_MAX_NUM_TRANSIT_TUNNELS = 5000`, plus transport bandwidth — is past `CONGESTION_LEVEL_MEDIUM = 70`, above which it rejects probabilistically.
- **Java I2P throttles per hop, on a curve.** `ParticipatingThrottler`: a counter per hop cleared every `11 min / 3`, and `limit = max(12/3, min(66/3, participating * 1 / 100))` — a floor of 4 per window for an idle router, rising to 22 for a busy one.

The filter is kept, because a router that relays unlimited tunnels toward one peer is an amplifier pointed at that peer. It now uses Java's window and Java's curve. Java counts the previous hop in the same counter; we count only the next hop, because the amplification argument is about where traffic is aimed and counting both would halve the budget again in exactly the small networks this batch exists to unblock.

#### 3. The refusals were invisible

Every reason was `LogDebug`, so a Release router at the default level could refuse every tunnel it was offered and say nothing — which is why 528 consecutive refusals survived until someone read an i2pd log beside ours. Now each decision is counted by reason and reported with the existing periodic transit status at `Information`:

```
Transit build requests        : 531 answered, 3 accepted (0.6%). Refused: RejectNextHopThrottle: 528 (99.4%)
```

`RejectCapacity` and `RejectOwnTunnelsDown` were one branch and are now two: being full is not the same as declining to relay because our own client tunnels are down behind a firewall (`TunnelProvider.AcceptTransitTunnels`), and in a test fixture the second is far more likely than the first.

Also folded in: `LogStatus` was `#if DEBUG` 30 s `#else` 2 minutes, and the Release branch declared a *second*, non-readonly field of the same name — the two builds disagreed about how often the router reports what it carries. Same class as the `#if DEBUG` diagnostics 3-10 removed from NetDb.

#### The guard

`NextHopThrottleTest`, six tests, both defects confirmed red separately: reinstating `list.Count` fails the window test, and pinning the limit back to 2 fails two more. It asserts the window actually expires, that keys are counted independently, that an idle router answers at least three requests for its only next hop, that the curve matches Java's floor/percentage/ceiling, and that the report names the dominant reason with its share.

#### What this does not settle

1. **Whether the new budget is enough for the fixture.** A floor of 4 per 220 s means three accepted builds per window per next hop; i2pd wants roughly six to ten tunnels, each living ten minutes. It should converge, since i2pd only retries that hard *because* builds fail — but the number is a guess until a run measures it, which is what the new counters are for.
2. **`AcceptTransitTunnels` couples relaying to our own tunnel health** (`ClientTunnelsStatusOk || !IsFirewalled`). If the next run shows `RejectOwnTunnelsDown` dominating, that coupling is the next question, not the throttle.
3. **~28 `#if DEBUG` sites remain in `TunnelLayer` and `TransportLayer`** (`TunnelProvider.cs` alone has 9). 3-10 swept NetDb and guards it with a test; the rest of the router has never been swept, and some of those sites are validation rather than diagnostics, so it wants reading rather than a blanket removal.

**Next: read the next CI run for `Transit build requests … answered, … accepted`. That one line now answers what took two sessions and an i2pd log to establish. If the accept ratio is healthy and i2pd still cannot keep tunnels, the failure has moved past the build decision.**

#### First CI run on 3-14, and the correction it forced — **the budget must count what we did, not what we were asked**

Run `31637492053`, on PR #49 before merge. The report worked on its first outing, and it refused the batch:

```
Transit build requests        : 1166 answered, 9 accepted (0.8%). Refused: RejectNextHopThrottle: 1157 (99.2%)   (integration fixture)
Transit build requests        :  187 answered, 39 accepted (20.9%). Refused: RejectNextHopThrottle: 148 (79.1%)  (scaled fixture)
```

Three accepts became nine. **The gate — a router with one usable next hop still carries tunnels — was not met**, so per rule 4 the batch was corrected on its own branch rather than merged.

Why it was still starved: **Java increments its counter before checking, so a refused request spends budget too**, and the first cut of this batch copied that faithfully. A peer retrying a failed build ~35 times a minute spends a budget of four per window on refusals within seconds, and never recovers — a softer version of the latch the same batch had just removed.

Java's rule is safe in Java's setting for two reasons we do not have: a router there has hundreds of possible next hops, so a flood aimed at one leaves tunnels toward the others alone; and Java escalates from REJECT to DROP past 9/8 of the limit, treating a flood as abuse rather than as traffic.

So the budget now counts **tunnels we agreed to relay** toward a hop — `Count` to check, `Update` only on the accept path. That is also the better anti-amplification measure: what a peer can be hurt by is traffic we relay toward it, and that is bounded by acceptances, not by requests. Refused requests still cost us a record decryption and a reply, which is request-rate abuse — a different problem, wanting a throttle keyed on the *sender* rather than the target, and it is not in this batch.

**The guard had to change shape too.** The defect was not in the rule but in *where* the budget was spent, and driving the pure functions cannot see that — reinstating the misplaced `Update` left all eight tests green. `TheBudgetIsSpentOnlyWhereWeAccept` reads the source and requires exactly one `NextHopFilter.Update(` in the file, guarded by having decided to accept, in the style batches 3-11 and 3-12 used for the same class of mistake. Confirmed red against the reinstated call.

**Also from that run:** integration went 36/16 → 35/17, the one difference being `TestSend5MB_I2pd0_To_I2pd1` (`LeaseSet not found`), an i2pd-to-i2pd transfer in the scaled fixture. One marginal test in a family of fourteen that all fail the same way; not read as signal either direction.

#### 3-14 confirmed in CI, and merged — **the throttle recovers; the floor is now the binding constraint**

Run `31640992625`, PR #49, merged. Build green, unit **348 / 0 / 1**, integration **35 passed / 17 failed / 3 skipped** — unmoved.

| | 3-13 | 3-14 first cut | 3-14 merged |
|---|---|---|---|
| Integration fixture, accepted | 3 of 531 (0.6%) | 9 of 1166 (0.8%) | **20 of 1722 (1.2%)** |
| Scaled fixture, accepted | — | 39 of 187 (20.9%) | **47 of 54 (87.0%)** |
| i2pd tunnels created, integration | 2 | — | **7 outbound, 0 inbound** |
| i2pd tunnels created, scaled (one router of ten) | — | — | **46, not one `declined`** |

**Where the router has more than one next hop, the batch is done.** The scaled fixture accepts seven of every eight requests, `i2pd_scaled_0` built 46 tunnels and logged no decline at all, and `Build response ret code=30` — the rejection code that dominated 3-13 — does not appear in its log. That is the gate, and it is met.

**Where it has exactly one, the filter is still what the fixture is measuring, for a new reason.** Every refusal in the integration run names the same peer, and says the whole story on one line:

```
21:07:49  TransitProvider AcceptingTunnels: Reject, 4 tunnels already accepted toward [smtuw]
          in 3m 40s, limit 4. Running tunnels: 4.
```

`[smtuw]` is the only next hop that appears in 582 logged refusals — i2pd knows two routers, we know three. The budget was spent **21 seconds after start** and released exactly as designed: four accepts at 21:07:49, the next four at 21:11:30, one window of 3m 40s later. It is a rate limit now, not a latch. It is also, at four per window, less than i2pd asks for: it wants roughly five inbound and five outbound tunnels alive, two hops each, rebuilt every ten minutes, and every hop of every one of them is us.

The consequence is the whole downstream failure, in i2pd's own log: **0 inbound tunnels built**, so no lease, so `Destination: Own remote LeaseSet dropped` fifteen times, so all seventeen integration failures are `CANT_REACH_PEER MESSAGE="LeaseSet not found"`. The inbound declines are ours — `ret code=0` from one hop and `ret code=30` from the next in the same reply — so an inbound tunnel needs *both* hops to have budget in the *same* window, and 626 of 633 did not.

**Not explained, and recorded rather than asserted:** the accept count later steps by 7 inside one 30 s report (9 → 16 at 21:13:47) where the window can only release 4. The debug trail in that log stops at 21:13, so whether a second next hop briefly appeared or two windows released together cannot be read from this run. The next run should carry the per-hop budget in the `Information` report so this is answerable without a debug build.

### Session 10 — batch 3-15 — **the per-hop budget must scale with how many next hops exist**

Filed from the 3-14 evidence above. The rule 3-14 shipped is Java's, and Java's floor of four assumes a router with hundreds of possible next hops: a peer's share of our capacity is small because there are many peers, and refusing one leaves the rest reachable. With one peer, "four tunnels per 220 s toward this hop" *is* our entire relaying capability, and a router that refuses to relay toward the only peer it knows is not a router.

The two reference implementations bracket it: **i2pd has no per-hop cap at all** and gates on congestion alone (transit count against 5000, plus bandwidth); **Java** caps per hop on a curve and never consults its peer count. The rule wanted here degenerates to each at the ends — Java's curve when we know thousands of routers, i2pd's capacity-only behaviour when we know one — because the per-hop cap's real job is *diversity*, not an absolute bound. The absolute bound is `MaxTransitTunnels`, which is enforced separately and already has its own refusal reason.

So the budget becomes the larger of Java's curve and this router's fair share of its own capacity: `MaxTransitTunnels / usable next hops`, converted from live tunnels to accepts-per-window by `NextHopWindow / Tunnel.TunnelLifetime`. On the live network with thousands of routers known the share is under one and Java's floor wins unchanged, which is the case the anti-amplification argument is about. In the fixture it lifts.

Also in scope, because 3-14's own evidence could not be read without a debug build: the periodic transit report must state the budget in force and how many routers it was computed from.

**Unit suite 356 passed / 0 failed / 1 skipped** (357 total, +8), Release build 0 errors, 58 warnings.

#### The rule

```csharp
internal static int NextHopRequestLimit( int transittunnelcount, int knownrouters, int maxtransittunnels )
{
    return Math.Max(
        JavaNextHopLimit( transittunnelcount ),
        CapacityShareOfOneNextHop( knownrouters, maxtransittunnels ) );
}
```

`JavaNextHopLimit` is 3-14's function under its own name, unchanged. `CapacityShareOfOneNextHop` is `MaxTransitTunnels / max(1, knownrouters)`, converted from tunnels *alive* to tunnels *accepted per window* by `NextHopWindow / Tunnel.TunnelLifetime` — the budget is a rate and capacity is a level, and that conversion is where a rule of this shape goes wrong, so a test pins it in both directions.

At the two ends it is each reference implementation:

| routers known | share per window | limit in force | which rule |
|---|---|---|---|
| 1–2 | 1833 | 1833 | i2pd's — capacity only |
| 100 | 36 | 36 | the share |
| 1000 | 3 | 4 | Java's floor |
| 5000 | 0 | 4 | Java's, entirely |

The crossover is around nine hundred routers known, so on the live network the rule is Java's and nothing about the anti-amplification case has changed. The router count comes from `NetDb.Inst.RouterCount`, which is the pool peers actually draw their hops from.

#### What it gives up, said plainly

On a small network a hostile peer can aim a large share of our capacity at the one other router — "fair share" of a capacity far above what anyone present can use is not a limit. That is equally true of i2pd, whose only cap is congestion, and the control is `MaxTransitTunnels` itself. The alternative — a per-peer demand model, "the most one peer could legitimately want is its own pool" — was rejected for this batch because it would put the fixture's budget at about 11 per window against an observed demand of ~1000 requests per window, and the whole point of 3-15 is that the *next* CI run should measure the protocol rather than our policy. **A third of i2pd's build attempts in the 3-14 run got no reply at all** (365 `timeout, deleted` against 626 declines and 7 successes), and that failure cannot be seen while the throttle is the top suspect.

#### Visibility

`Transit next-hop budget       : 1833 tunnels per 3m 40s toward any one hop, from 2 routers known`

printed with the build-decision report at `Information`. 3-14's evidence only existed because that run happened to carry debug lines, and they stopped at 21:13 — which is why the +7 step in one 30 s report could not be explained.

#### The guard

`NextHopBudgetScaleTest`, eight tests, confirmed red: with the rule reduced to Java's curve alone, `WithOneOtherRouterKnownTheBudgetSustainsThatPeersPool` and `TheBudgetNarrowsAsTheNetworkGrows` fail and the other six stay green. It pins that a live-sized network gets Java's curve exactly for every load, that the budget is monotonic in the router count and lands on Java's floor at the large end, that a spent budget sustains no more live tunnels than the share it came from, that an empty NetDb is not a division by zero, that a capacity of zero comes out as `RejectCapacity`'s problem rather than a budget of nothing, and that the report states the budget and its inputs.

#### What this does not settle

1. **Whether the fixture now builds tunnels.** The budget stops being the binding constraint; the 365 unanswered builds become the top suspect, and they are not this batch.
2. **The load this admits in a fixture.** If i2pd keeps retrying at ~1700 requests per ten minutes and we now accept nearly all of them, we will carry a thousand-odd transit tunnels for a peer that wants ten. It should collapse once its builds succeed — that is why it retries — but the next run should be read for transit tunnel counts as well as accept ratios.
3. **Request-rate abuse is still unaddressed.** Every refusal costs us a record decryption and a reply; a throttle keyed on the *sender* rather than the target is the missing piece, and 3-14 named it too.

#### 3-15 confirmed in CI, and merged — **i2pd builds tunnels through us in both directions, and the wall moves to the LeaseSet**

Run `31746173643`, PR #50, merged. Build green, unit **356 / 0 / 1**, integration **35 passed / 17 failed / 3 skipped**.

```
Transit next-hop budget       : 1222 tunnels per 3m 40s toward any one hop, from 3 routers known
Transit build requests        : 186 answered, 186 accepted (100.0%)
```

| integration fixture | 3-13 | 3-14 | 3-15 |
|---|---|---|---|
| build requests answered | 531 | 1722 | **186** |
| accepted | 3 (0.6%) | 20 (1.2%) | **186 (100%)** |
| i2pd outbound tunnels created | 2 | 7 | **22** |
| i2pd **inbound** tunnels created | 0 | 0 | **25** |
| `Build response ret code=30` (our refusals) | 726 | 1046 | **0** |
| `Pending build request timeout, deleted` | 689 | 365 | **46** |
| build messages i2pd dropped under load | — | 202 | **19** |

**The request count fell by a factor of nine, and that is the finding, not the accept ratio.** 1722 requests were i2pd retrying builds we refused; when the builds succeed it stops asking. The load worry in this batch's own open items — that a budget of 1222 would have us carrying a thousand transit tunnels for a peer that wants ten — did not happen for the same reason, and i2pd's own dropped-build-message warnings fell with it, 202 → 19.

**Not one integration test moved.** 17 failed before and 17 after; the sets differ by one in each direction, `CaptureSessionRequestByAnsweringTheTokenRequest` (an SSU2 capture test) leaving and `TestSend5MB_I2pd0_To_I2pd1` (the i2pd-to-i2pd scaled transfer that also flipped between the last two runs) arriving. Neither is read as signal.

That is the expected shape of this batch: it removed our own policy from between i2pd and the protocol, and what was behind it is now measurable.

### The next batch — **the LeaseSet does not survive the round trip between the two routers**

i2pd now has inbound tunnels, so it can publish, and it still cannot be reached:

```
241  warn - Destination: Publish confirmation was not received in 3 m   (403 in the 3-14 run)
 14  debug - Destination: Own remote LeaseSet dropped
 10  warn - NetDbReq: No more floodfills for <destination>
 15  RESULT=CANT_REACH_PEER MESSAGE="LeaseSet not found"                (SAM, unchanged)
 14  RESULT=CANT_REACH_PEER MESSAGE="Destination not found"             (SAM, unchanged)
```

i2pd asks for a destination, exhausts the floodfills it knows, and gives up. Our side logs `IdentResolver: LS lookup` 8 times and `FloodfillServer` not at all in this run. What to settle before touching anything:

1. **Is either router a floodfill in this fixture, and does each believe the other is?** A two-router network where neither answers `DatabaseLookup` cannot distribute a LeaseSet at all, and 3-9 already showed this router will answer a request for a floodfill with something that is not one.
2. **Does our destination's LeaseSet ever reach i2pd's NetDb?** i2pd logs `NetDb: LeaseSet2 updated` 20 times, so *some* store arrives; whose is not established.
3. **3-11 is the precedent to check first.** It found we published our *RouterInfo* under an encryption no modern floodfill can read. The LeaseSet publish path is the sibling that batch did not touch, and `GetECIESPublicKey()` was noted there as being used differently by the two paths.

**Next: batch 3-16, LeaseSet publication and lookup between two routers — and note that the tunnel layer is no longer the suspect. Builds succeed in both directions and 186 of 186 requests are accepted.**

### Session 11 — batch 3-16 — **the fixture has one floodfill, and it is i2pd itself**

**Unit suite 364 passed / 0 failed / 1 skipped** (365 total, +8), Release build 0 errors, 55 warnings.

**This session had no CI and no i2pd.** `gh api repos/samueldaaaarling/i2p-cs-renewed/actions/runs` returns `total_count: 0` from this machine, and `origin/github-master` is at `a08ad85`, hundreds of commits behind the local branch — so the run that would confirm this batch cannot be launched from here. Every claim below is therefore settled against **i2pd's own source**, fetched at head of the `openssl` branch, or against a unit test. Nothing here is claimed to be confirmed on the wire. **The batch is left on `p3/floodfill-reply-encryption` and deliberately not merged**, per rule 4.

#### The topology, which nobody had checked

The plan's own first question for 3-16 was "is either router a floodfill in this fixture, and does each believe the other is?" The answer is worse than "no":

- `TestNetworkFixture` starts the C# router with `CSharpRouterHarness()`, whose `floodfill` parameter defaults to **false**, so `RouterContext.cs:358` never adds `f` to our caps.
- `I2pdConfigGenerator.GenerateConfig` defaults `floodfill = true`, and its own comment says why: on a private network there is no external floodfill, so i2pd must be its own.
- i2pd's `NetDb::Start` (NetDb.cpp:83-86) inserts its own RouterInfo into `m_Floodfills`, and `GetClosestFloodfill` (NetDb.cpp:1296) filters only on the caller's excluded set. `LeaseSetDestination::Publish` passes an initially empty one. **So i2pd published its LeaseSets to itself**, through its own outbound tunnel and back through its own inbound tunnel — both of which run through us, which is why the failure looked like a LeaseSet problem.
- But `RequestedDestination`'s constructor (NetDbRequests.cpp:28-29) *does* exclude self when floodfill. With one floodfill, every RouterInfo lookup i2pd makes has an empty candidate set — exactly the `NetDbReq: No more floodfills for <dest> after N attempts` warning (NetDbRequests.cpp:322) recorded in the last three runs.

The consequence that matters most: **`FloodfillServer` has never executed in any integration run this project has ever done.** "FloodfillServer not at all in this run" was not a symptom, it was the configuration. The fixture now starts the C# router as a floodfill, which is the only way a LeaseSet can travel between the two routers, and the first thing that will exercise the code below.

#### Two defects, found because that code was about to be turned on

Both are the plan's signature shape — the two halves of this repository agreeing with each other and with nothing else.

**(1) The reply tag was never read.** i2pd's `CreateLeaseSetDatabaseLookupMsg` (I2NPProtocol.cpp:193) writes flags `DELIVERY | LEASESET_LOOKUP | ECIES` = `0x15`, with the encryption bit `0x02` **clear**, and then unconditionally appends `replyKey(32) ‖ numTags(1) ‖ tag(8)`. Its own floodfill reads them back on either flag: `if (flag & (DATABASE_LOOKUP_ENCRYPTION_FLAG | DATABASE_LOOKUP_ECIES_FLAG))`, then `excluded[32]` as the tag count regardless (NetDb.cpp:1058-1066). Our `UpdateCachedFields` read the key on either flag but gated the tag count on `Encryption` alone, so **every LeaseSet lookup i2pd sends us parsed with zero tags** — a reply key with no address to send the reply to. Invisible because our own writer sets both flags. The writer now emits the group whenever there is a key, which is what both reference implementations do.

**(2) The reply was sent in the clear anyway.** `FloodfillServer.SendReply` and `SendSearchReply` put the DatabaseStore or DatabaseSearchReply on the wire unencrypted whatever the lookup asked for. i2pd wraps it with `WrapECIESX25519Message (replyMsg, sessionKey, tag)` — which is byte-for-byte the one-time symmetric garlic **batch 3-13 already proved correct against i2pd** for tunnel build replies, so `TunnelProvider.CreateOneTimeGarlicMessage` is now shared rather than reimplemented, with a new overload that takes the tag as the eight bytes it must appear as on the wire instead of round-tripping through a `ulong`.

Said plainly: **this was not fatal on its own.** i2pd's destination accepts a cleartext DatabaseStore — `HandleCloveI2NPMessage` takes a null session. What it costs is the thing the field exists for: every hop of the reply tunnel could read which destination was asked about. The legacy ElGamal/AES reply form is *not* implemented and now says so, rather than answering in an encryption the requester holds no key for.

#### The guard

`FloodfillReplyEncryptionTest`, 8 tests. **The lookup is built byte by byte to i2pd's layout, not by our own writer** — a round trip passes against the broken code, which is exactly what hid defect 1 — and the reply is decrypted the way i2pd decrypts it: leading 8 bytes as the tag, used as AEAD associated data with a zero nonce and the requester's key, then the blocks parsed and the first one required to be the clove. Confirmed red with each defect reinstated separately: 3 of 8 fail for the parser, 1 of 8 for the missing wrap.

#### What this does not settle

1. **Whether the LeaseSet now survives the round trip.** The fixture change makes the question askable for the first time; it does not answer it. The next run should be read for whether `FloodfillServer` appears in our log at all, whether i2pd stores a LeaseSet whose key is *our* destination, and whether the SAM `LeaseSet not found` count moves off 15.
2. **Whether turning on floodfill perturbs the rest of the integration suite.** It changes what the shared in-process router advertises and adds a message handler; 35/17/3 is the baseline to compare against.
3. **The transit data path is still unmeasured.** i2pd publishing to itself means its LeaseSet stores and delivery statuses have been traversing our OBEP and IBGW all along, and 241 missing publish confirmations per run is consistent with that path dropping traffic. Builds succeeding (3-15) is not the same as data flowing. If 3-16 does not move the numbers, that is the next suspect, and it is Phase 6's subject.

#### 3-16 confirmed in CI, and merged — **the floodfill code runs, and four tests come back**

Run `31804699506`, PR #51, merged. Build green, unit **364 / 0 / 1**, integration **39 passed / 13 failed / 3 skipped** against a 35/17/3 baseline.

**A correction to session 11's premise first: CI was available all along.** That session concluded the run could not be launched because `gh api repos/samueldaaaarling/...` returned `total_count: 0`. That is `origin`, the upstream this repository was forked from; every run and every PR from #1 onward has been on the `fork` remote, `fredriksknese/i2p-cs-renewed`, whose `github-master` was exactly one commit behind. Check `git remote -v` before concluding the pipeline is unreachable.

| | 3-15 | 3-16 |
|---|---|---|
| integration passed / failed | 35 / 17 | **39 / 13** |
| `FloodfillServer` lines in our log | 0 | **194** |
| — lookups answered | — | **63** |
| — LeaseSets stored | — | **24** |
| — floods sent | — | **10** |
| i2pd `NetDbReq: No more floodfills` | 10 | **5** |
| i2pd `LeaseSet2 updated` | 20 | **30** |
| SAM `LeaseSet not found` | 15 | **4** |

Four tests moved from failing to passing and **none regressed**: `TestSAM_DatagramSession_I2pd`, `TestSAM_SessionCreate_I2pd`, `TestSend5MB_I2pd0_To_I2pd1`, `TestSend5MB_I2pdA_To_I2pdB_MultiHop`. The third of those is the known flapper the last two runs disagreed about; the other three are new.

The batch's four questions, answered:

1. **Does `FloodfillServer` execute at all?** Yes, for the first time in this project's history — 63 `DatabaseLookup` answered, 24 LeaseSets stored, 10 floods. Every previous run's silence was the configuration, not a symptom.
2. **Does a LeaseSet reach the other router's NetDb?** i2pd's `LeaseSet2 updated` went 20 to 30 and we are now storing 24 LeaseSets that arrive from it, so stores cross in both directions.
3. **Does SAM's `LeaseSet not found` move?** 15 to 4.
4. **Does turning on floodfill perturb the suite?** No regression; the two i2pd-to-i2pd transfers that pass are the ones whose lookups had nowhere to go before.

**One number moved the wrong way and is recorded rather than explained: `Destination: Publish confirmation was not received in 3 m` went 241 to 1490.** i2pd publishes far more often now (it has somewhere to publish to) and is not getting the store acknowledged, which points at the DeliveryStatus that should come back through its inbound tunnel — our OBEP and IBGW, the transit data path that 3-16's own open items already named as the next suspect and that batch 6-1 instruments.

### Session 12 — batch 6-1 — **the trace categories were compile-time, so nobody could turn one on**

**Unit suite 376 passed / 0 failed / 1 skipped** (377 total, +12), Release build 0 errors.

Filed by the plan, and made urgent by the run above: the transit data path is the last unmeasured stretch between us and i2pd, and the tracing that would show it was unreachable.

#### What was actually there

`I2PCore.csproj` defined `NOLOG_ALL_TUNNEL_TRANSFER` and five siblings as inert placeholders; the source was guarded by `#if LOG_ALL_TUNNEL_TRANSFER`, so selecting a category meant editing the project file and rebuilding. **That is the compile-time gating batch 0-1 removed from the rest of the logging, for the reason 0-1 gave: the output you need to diagnose a router is unreachable in the build you have.** In a fixture that costs half an hour a run it is worse than that — you cannot go back and ask a finished run a new question.

Three things fell out of turning it on, none of which a running router could have shown:

1. **Two lines could never have compiled.** `Router.cs` interpolated `{this}` in two `#if LOG_ALL_TUNNEL_TRANSFER` blocks, inside the **static** `Router` class. Switching that category on would have failed the build, which is a fair summary of how much the guarded code had been exercised since the fork.
2. **`LOG_ROUTER_SELECTION_HISTORY` had no call sites at all** — a `ConcurrentDictionary` and a `PeriodicAction` in `NetDb.Query.cs` that nothing in the repository reads. Whatever logged them was deleted and left the fields behind. Both are gone, and there is deliberately no router-selection category: it would be a switch that turns nothing on.
3. **`LOG_ALL_UPNP` was never in the project file**, so five call sites were unreachable in every build this repository has ever produced.

#### The mechanism

`TraceCategories` is a `[Flags]` enum on `Logging.EnabledTraces`, selected by `--log-trace tunnel-transfer,lease-mgmt,...`. `Logging.LogTrace(category, $"...")` binds an `[InterpolatedStringHandler]` that takes the category as a constructor argument via `[InterpolatedStringHandlerArgument]`, so the bit is tested **before** the interpolation runs — exactly what batch 0-6 did for `LogDebug`, and what makes it safe to leave these calls in per-message tunnel paths.

**Both filters apply, deliberately.** The category says which firehose you asked for; `LogLevel` still says how much the router emits at all, and a trace is Debug-level output. A category alone therefore produces nothing, which would be a trap — so the CLI says so at startup and a test pins the warning true.

Two smaller decisions, both recorded in-code:

- The four identical per-instance `ItemFilterWindow` fields in `TransitTunnel`, `EndpointTunnel`, `GatewayTunnel` and `OutboundTunnel` became one `Tunnel.TraceMessageFilter`. Every key already names the destination or message type it limits, so one shared window is equivalent — and a router carrying a thousand transit tunnels no longer allocates a thousand of them to rate-limit traces that are switched off. `OutboundTunnel`'s allowed 5 per 30 s rather than 2; it now gets 2.
- `TraceCategoryNames.TryParse` clears its `out` on a rejected list rather than leaving what it parsed so far, and the CLI exits 2 naming the bad element. A misspelt category that silently enables nothing is this batch's own failure mode.

#### The tracing itself

`TransitTunnel` now traces **both sides of its layer crypto** — tunnel id, length, and an FNV-1a digest of the IV and the encrypted window, before `EncryptTunnelMessages` and after.

The shape is chosen against session 6's finding, a hop that **preserves length and destroys content**. Digesting our own input against our own output proves nothing: they are supposed to differ. What is diagnostic is that the digest we log on the way *out* is the digest the next hop logs on the way *in*, which makes one message followable across two routers' logs and localises a corruption to a hop instead of to a 5 MB transfer.

#### The guard

`TunnelTracingTest`, 12 tests. Both halves confirmed red: reinstating a single `#if LOG_ALL_TUNNEL_TRANSFER` in `Tunnel.cs` fails `NoCompileTimeTraceGatesRemainUnderI2PCore`, and deleting the post-crypto trace fails `TheTransitHopTracesBothSidesOfItsLayerCrypto` — that one reads the source, because a trace on one side only reads as working and answers nothing. The rest pin that an off category neither formats its message nor runs its generator, that a category with the level too high emits nothing and `IsTraceEnabled` agrees, that a two-category message is an "or", and that the project file defines no logging symbols.

#### What this does not settle

1. **Nothing about the data path yet.** This batch is the instrument, not the measurement. The next integration run should be read with `--log-trace tunnel-transfer` if the fixture can be made to pass it.
2. **The 1490 unconfirmed publishes.** That is the question the instrument was built for, and it is the next batch.

#### 6-1 confirmed in CI, and merged — **and it corrects 3-16's headline**

Run `31808376962`, PR #52, merged. Build green, unit **376 / 0 / 1**, integration **37 passed / 15 failed / 3 skipped**.

Two fewer passes than the 3-16 run, and the difference is exactly two tests: `TestSend5MB_I2pd0_To_I2pd1` and `TestSend5MB_I2pdA_To_I2pdB_MultiHop`. Nothing else moved in either direction.

**Read as flake, and the reasoning is worth stating because "integration went down" is the kind of result that gets a good batch reverted.** 6-1 cannot change what a router does: every category defaults to `None`, so each converted call site evaluates one mask and returns, exactly as the `#if` that preceded it compiled to nothing. The two tests are also the pair the plan has already recorded flapping — `TestSend5MB_I2pd0_To_I2pd1` flipped between the 3-14 and 3-15 runs and again between 3-15 and 3-16, and the multi-hop sibling has now flipped twice.

**So 3-16's "four tests came back" was two solid and two flapping.** `TestSAM_DatagramSession_I2pd` and `TestSAM_SessionCreate_I2pd` have passed in both runs since; the two i2pd-to-i2pd transfers should not have been counted. **The working baseline is 37 / 15**, and the two i2pd-to-i2pd transfers are a known-unstable pair that no future batch should read as signal in either direction without a second run.

That instability is itself unexplained and worth a batch eventually: both are transfers between two i2pd routers, in which our only role is to carry the tunnels — so a test that passes and fails alternately with no change on either side is measuring something nondeterministic in the path we provide. That is the same suspect as the 1490 unconfirmed publishes.

### Session 12 (continued) — batch 4-3a — **we advertise path validation and answer it with silence**

**Unit suite 369 passed / 0 failed / 1 skipped** (370 total, +5), Release build 0 errors. Run in parallel with 6-1's CI; the two batches share no files.

#### The split, and why

The plan's 4-3 row reads "real `SendPathResponse`; only then restore `ConnectionMigrationSupported`", which reads like a one-liner and is not. Reading the dispatch path first:

**`SSU2Host.Sessions` is keyed by `IPEndPoint`.** `DispatchPacket` looks a packet up by the address it arrived from, and anything from an unknown address that is not a SessionRequest, PeerTest or TokenRequest is dropped with a warning. So a peer that has moved never reaches a session at all, and no amount of block handling changes that: **migration needs the session table keyed by connection id**, which is what the short header carries it for.

That is a change to the transport hot path and deserves its own batch. Split:

- **4-3a (this one)** — answer a challenge, because we already invite them.
- **4-3b** — key sessions by connection id, challenge the new address, migrate only on a matching response, and only then publish `m`.

#### The defect

`SendPathResponse` hand-rolled a type byte and a big-endian length in front of the challenge data, into a local array, logged, and returned. Batch 0-4 had already found that its log line claimed "PathResponse sent" and corrected the message to say it was a stub — the send was left for here.

**A dormant stub would be harmless. This one is not:** `SSU2Host.PathValidationSupported` is `true`, so this router publishes `p` in its SSU2 `caps`, which is precisely an invitation to send us the challenge we answered with silence. Batch 0-4 turned `m` off for exactly this reason and left `p` on.

Two smaller things fell out of fixing it:

1. **The hand-rolled framing was wrong as well as unsent.** `SendBlock` takes the block *payload* and `SSU2DataPacket.BuildWithBlock` writes the type and length. Wiring the stub up as it stood would have sent every response with its header twice. A test pins that the framing is not written here.
2. **The echo is bounded.** Its size is the peer's choice, so a challenge larger than one datagram's payload is refused with a warning rather than handed to a builder that cannot produce a sendable packet. The 1:1 echo is also why this is not an amplification vector, and the comment says so.

`ConnectionMigrationSupported` stays **false**, and the reason in its comment is now the endpoint keying rather than the missing send.

#### The guard

`Ssu2PathResponseTest`, 5 tests. The round trip goes through the real `BuildWithBlock` and `Parse` for a range of challenge lengths, rather than asserting on bytes we write — "builds the right block" is what the stub already did, so a byte-level assertion would have passed against it. `SendPathResponseReachesTheSendPath` reads the source and requires the call to `SendBlock`; confirmed red by replacing that call with the old local-array build, which fails 1 of 5 and leaves the other four green. The last test ties the two published capabilities to what is implemented, and pins the endpoint keying that is `m`'s stated reason.

#### What this does not settle

**Whether i2pd ever challenges us.** Path validation is for a peer whose address has changed, which does not happen in a fixture where both routers sit still. This is correctness against the capability we publish, not something the integration suite will show moving — and SSU2 is still off by default (4-5).

#### 4-3b started and stopped before writing code — **and it turned up a question about `k_header_1` that has to be settled first**

Batch 4-3b (`p4/ssu2-session-migration`) was opened and abandoned with no code. Recorded here because what stopped it is more useful than the batch would have been.

**What 4-3b needs.** Migration means finding a session for a packet that arrives from an address we have never seen. Our `SSU2Host.Sessions` is a `Dictionary<IPEndPoint, SSU2Session>`, so such a packet matches nothing and `DispatchPacket` drops it. The fix is to find the session by the **connection id** in the short header — which is what the header carries it for.

**What i2pd does** (`SSU2Server::ProcessNextPacket`, `SSU2.cpp`, head of the `openssl` branch): `m_Sessions` is keyed by `uint64_t connID`, not by endpoint, and every incoming packet is unmasked with

```cpp
connID ^= CreateHeaderMask (i2p::context.GetSSU2IntroKey (), buf + (len - 24));
```

`i2p::context.GetSSU2IntroKey()` is **i2pd's own** intro key, used for every incoming packet regardless of who opened the session.

**Our rule is different, and the two only agree in one direction.** Both our send and receive paths choose

```csharp
var kHeader1 = IsOutgoing ? GetRemoteIntroKey() : Host.GetMyIntroKey();
```

(`SSU2Session.cs:376`, `:403`, `:728`, `:745` sending; `:1503` receiving). That is batch 4-1a's rule — *the intro key of whichever router published the SSU2 address that was dialled* — and it is used for **both directions of a session**. So:

| session | we send, masked with | i2pd unmasks with | agree? |
|---|---|---|---|
| we dialled i2pd | i2pd's intro key | i2pd's own | yes |
| i2pd dialled us | **our** intro key | **i2pd's own** | **no** |

**This is a question, not a finding.** It rests on a fetched summary of `ProcessNextPacket` rather than on the SSU2 spec text or a captured packet, and the repository's own history argues both ways: batch 4-0h established a handshake and 4-1c carried traffic over it, but **both were C#-to-C#** — two halves agreeing with each other, which is this project's most common failure shape and exactly what 4-1a's rule was derived to fix. Session 6 did establish a session with i2pd, but SSU2 is off by default (`EnableSSU2`, batch 4-5), so the data phase in the responder direction has never been measured against i2pd.

**What to do first, before any of 4-3b:**

1. Read the SSU2 specification's header-encryption section for what `k_header_1` is in the **data phase**, in each direction. 4-1a's citations were re-derived from i2pd symbols after the "spec lines" references turned out to point at an absent document, so cite symbols or captured bytes.
2. If the rules differ, that is a defect ahead of 4-3b in priority and it is why the responder direction should be captured against i2pd before 4-5 turns SSU2 on.
3. Only then key `Sessions` by connection id — because *which key unmasks an unknown packet* is the whole design of that lookup, and getting it wrong makes every session unfindable rather than one.
