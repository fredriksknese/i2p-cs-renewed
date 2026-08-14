# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A C# I2P router — a fork of https://github.com/PeterZander/i2p-cs. The README is explicit that most of the newly-changed code is AI-written, largely unverified, and that many subsystems are partly or wholly broken. **Read the "Current Status" section of `README.md` before assuming any feature works** — it is the authoritative statement of what is believed functional (NTCP2 mostly works; SSU2 is broken; session/streaming encryption is unreliable). Treat it as a status board and keep it current when you fix or break something.

Target framework is `net10.0`. Only external dependency of note is BouncyCastle.

**There is an active production-readiness plan: `docs/PRODUCTION-PLAN.md`.** It is the source of truth for what to work on and in what order — phases, gates, one-batch-per-PR rules, and a session log. Read it before starting work, and append to its session log on hand-off.

**Safety rule, in force until Gate 6: never run a router built from this repo on netid 2 (the live I2P network).** Pass `--netid 3` for all local and integration testing. This is anonymity software; a half-working router on the real network degrades other users' traffic and its own operator's anonymity set.

## Commands

```bash
dotnet build i2p.sln                 # builds all 10 projects
dotnet test src/I2PCore.NTests       # runs unit + integration tests

# Unit tests only — this is what CI gates on. Keep in sync with .github/workflows/dotnet.yml
# and src/I2PCore.NTests/TestCategories.cs:
dotnet test src/I2PCore.NTests -c Release \
  --filter "TestCategory!=Integration&TestCategory!=ScaledNetwork&TestCategory!=MultiHop&TestCategory!=Experimental"

# One fixture / one test:
dotnet test src/I2PCore.NTests --filter "FullyQualifiedName~NTCP2HandshakeTest"
dotnet test src/I2PCore.NTests --filter "Name=TestSAM_Hello_I2pd"

# Run a router:
dotnet run --project src/I2PRouterCli -- --help          # headless, see PrintHelp() for all flags
dotnet run --project src/I2PRouterWeb                    # web console on http://localhost:5197
```

Integration tests spawn real `i2pd` processes; they self-skip (`Assert.Ignore`) if no i2pd binary is found. Set `I2PD_PATH` to point at one. Test ports are allocated from 29000-29099 (`PortAllocator`) to avoid colliding with a live local I2P router.

The unit suite is **green on `github-master`** as of batch 0-3: 176 pass, 0 fail, 1 skipped. Keep it that way — a red suite blocks every gate in the plan. `TestNTCP2PQHandshake` (all three ML-KEM sizes) is *quarantined*, not fixed: it carries `[Category("Experimental")]` and is owned by batch 9-3. Establish a baseline before assuming a failure is yours.

### Logging

**Logging is runtime-filtered only.** `Logging.LogLevel` is the single filter; there is no compile-time gating. Debug output is therefore reachable in a Release build, which is the whole point — the router used to strip `Log`/`LogDebug`/`LogTransport`/`LogDebugData` from every non-DEBUG build via `[Conditional("DEBUG")]`, making a Release router undiagnosable. Do not reintroduce that; `LoggingVisibilityTest` fails if you do.

- Default level is `Information`. The CLI exposes `--log-level <LEVEL>` (`Everything`, `DebugData`, `Transport`, `Debug`, `Information`, `Warning`, `Error`, `Critical`, `Nothing`).
- **Just write `Logging.LogDebug($"...")`.** `LogDebug`, `LogTransport`, `LogDebugData` and `Log` bind interpolated strings to an `[InterpolatedStringHandler]` (`Utils/Logging/LogInterpolatedStringHandlers.cs`), which checks the threshold *before* the interpolation runs. A suppressed message costs a comparison — nothing is formatted, boxed, or allocated. This is why hot paths did not need rewriting.
- The `Func<string>` overloads still exist and also short-circuit; they are only worth reaching for when building the message needs statements rather than an expression. `Logging.IsEnabled(level)` guards larger blocks.
- The saving is lost if you format eagerly yourself — `LogDebug("x " + Expensive())` or `LogDebug(string.Format(...))` build their argument before the call. Keep it an interpolated literal.

```bash
dotnet run -c Release --project src/I2PRouterCli -- --netid 3 --log-level debug
```

**Trace categories** are the second, orthogonal filter, for the very high-volume tunnel/transport tracing (batch 6-1). They were `NOLOG_*` `#if` symbols in `I2PCore.csproj`; they are now runtime flags in `TraceCategories` (`Utils/Logging/TraceCategories.cs`), selected by `--log-trace <list>`: `tunnel-transfer`, `lease-mgmt`, `ident-lookups`, `transport`, `tunnel-selection`, `upnp`, `all`, `none` (default `none`).

- Write them as `Logging.LogTrace(TraceCategories.TunnelTransfer, $"...")` — same interpolated-handler rule as above, so an off category costs a mask and a comparison.
- **Both filters apply.** A trace is Debug-level output, so a category alone emits nothing: `--log-trace tunnel-transfer --log-level debug`. The CLI warns when you ask for one without the other.
- Do not reintroduce a `#if LOG_` guard anywhere under `I2PCore` — `TunnelTracingTest` fails if you do, for the same reason `LoggingVisibilityTest` exists.

## Architecture

Four layers under `src/I2PCore`, each with a process-wide singleton or static entry point. Everything is started by `Router.Start()` (`SessionLayer/Router.cs`), which is the one place that shows the whole boot order.

**`RouterContext`** (`SessionLayer/RouterContext.cs`) — this router's identity, keys, published RouterInfo, and settings. Accessed as `RouterContext.Inst`. Mutable statics must be set *before* `RouterContext.Inst` is first touched: `RouterContext.RouterSettingsFile` (each host app picks its own, e.g. `I2PRouterCli.bin`), `StreamUtils.AppPathOverride` (data dir), `I2PConstants.I2PNetworkId`, `Bootstrap.Disabled`. After that, mutate properties and call `ApplyNewSettings()`. `I2PRouterCli/Program.cs` is the clearest example of the required ordering.

**TransportLayer** — `TransportProvider.Inst` owns per-peer connections and exposes `IncomingMessage`. Transport implementations (`NTCP2/NTCP2Host`, `SSU2/SSU2Host`) are discovered by reflection: a class implementing `ITransportProtocol` and decorated with `[TransportProtocol]` with a parameterless constructor is instantiated automatically. Adding a transport means adding the attribute, not editing a registry. Handshakes live in `Crypto/Noise/` (`NoiseXK` for NTCP2, `NoiseIK`/`NoiseIKhfs` for SSU2 and the hybrid post-quantum variants); `Crypto/MLKEM/` supplies the PQ KEM.

**TunnelLayer** — `TunnelProvider.Inst` subscribes to `TransportProvider.IncomingMessage`, dedupes via a decaying bloom filter, and pumps I2NP messages on its own thread. Three owners sit above it: `ClientTunnelProvider` (per-destination pools), `TunnelPoolManager` (exploratory pools + per-client pools keyed by ident hash), `TransitTunnelProvider` (tunnels we participate in for others). Tunnel roles are `InboundTunnel`/`OutboundTunnel`/`GatewayTunnel`/`EndpointTunnel`/`TransitTunnel`, all deriving from `Tunnel`. I2NP message types and garlic/build records are under `TunnelLayer/I2NP/`.

**SessionLayer** — `ClientDestination` is one local destination (split across `ClientDestination.*.cs` partials: `.Tunnels`, `.Leases`, `.Send`, `.RecvGarlic`, `.IClient`). Create one via `Router.CreateDestination(...)`, which registers it and attaches it to `ClientTunnelMgr`. `SessionManager` holds the end-to-end crypto sessions; `SessionLayer/ECIES/` is the ratchet implementation (`ECIESSessionKeyManager`, `RatchetTagSet`), `SessionLayer/ElGamal-AES/` is the legacy path, `SessionLayer/Streaming/` is the I2P streaming ("TCP") protocol.

**Per-client isolation is a deliberate invariant.** `ClientDestination` does *not* subscribe to global NetDb LeaseSet events and `SessionManager` does *not* fall back to the global NetDb LeaseSet cache — a destination only learns LeaseSets from its own garlic messages or its own client-scoped lookups. Both places carry comments saying so. Do not "fix" a missing-LeaseSet bug by reaching for the global NetDb.

**NetDb** — `NetDb.Inst`, split across `NetDb.Query/Store/RouterEntry/Reports.cs`. `IdentResolver` drives lookups (direct and via tunnels), `FloodfillServer` answers them when floodfill is enabled, `Bootstrap` handles reseed (certificates in `I2PCore/certificates/reseed/`), `RouterProfile`/`RoutersStatistics` feed peer selection via `RouletteSelection`.

**Client services** (`I2PCore/Client/`) — `ClientContext.Inst` starts HTTP proxy, SOCKS proxy, SAM bridge, BOB, I2PControl, address book, and generic client/server tunnels. Configured by string keys (`ClientContext.CfgHttpProxyPort`, `CfgSamEnabled`, …) via `SetConfig` before `Start()`.

**`src/I2CP`** is a separate project (namespaces `I2P.I2CP`, `I2P.Streaming`) implementing the I2CP client protocol and its own streaming packet type — distinct from `I2PCore.SessionLayer.Streaming`. Don't conflate the two `StreamingPacket` classes.

### Serialization primitives

All wire types implement `I2PType` (`void Write(IBufferWriter<byte> dest)`), and parse by taking an `I2PBufferCursor` in the constructor. `I2PBufferCursor` (`Utils/I2PBufferCursor.cs`) is a *class* with an advancing position — deliberately, so chained constructors share the position — and `I2PByteBlock` (`Utils/I2PByteBlock.cs`) is a readonly struct view over `byte[]` with value equality. These replace the upstream `BufRef`/`BufRefLen`/`BufLen`; if you port code from upstream i2p-cs, that's the mapping you need.

Other pervasive utilities: `TickCounter`/`TickSpan` (monotonic time — used everywhere instead of `DateTime`), `PeriodicAction` (rate-limits work inside the layer worker loops), `Store` (custom sector-based file store, comments in Swedish), `Logging` (static, `LogTransport`/`LogDebugData`/etc. with `Func<string>` overloads for the guarded paths).

### Threading model

Each layer runs its own long-lived background `Thread` with a `while (!Terminated)` loop that drains a `ConcurrentQueue` and ticks its `PeriodicAction`s — `TransportProvider`, `TunnelProvider` (plus a separate `IncomingMessagePump` thread), `Router`. Shared state is `ConcurrentDictionary` plus targeted `lock`s. New periodic work belongs in an existing loop as a `PeriodicAction`, not on a new thread.

## Host applications

- `I2PRouterCli` — headless router, flag-driven, also used as the in-process router under integration tests.
- `I2PRouterWeb` — Razor Pages console (NetDb, tunnels, transports, transit, logs, settings). `RouterService` is the singleton that owns start/stop and persists to `web_settings.json` (gitignored).
- `src/Samples/` — `I2PRouter`, `I2PDemo`, `I2PEchoServer`, `I2PEchoClient`. Each picks its own `RouterContext.RouterSettingsFile`, so they can coexist in one directory.

Router state files (`*.bin`, `router.info`, `peerProfiles/`, `logs.txt`, `hosts.txt`) are written to the working directory or `--data-dir` and are gitignored.
