# i2p-cs-renewed-slop

This is a slop-fork of the following to increase functionality: https://github.com/PeterZander/i2p-cs

# WARNING/DISCLAIMERS: 
- There are no guarantees for this project. 
- 99% of the newly changed code was AI-written by a variety of models and agents. 
- This is genuinely slop. 
- This is likely filled to the brim with vulnerabilities and bad crypto.
- The code organization/architecture is genuinely terrible.
- The author of this fork has no idea what he is doing and barely understands I2P.

Please do not use this without acknowledging the above.

This is an experimental project. Some components could be useful for a less-slop rewrite (but unlikely).

# You should use other I2P implementations instead:
 - Java I2P: https://github.com/i2p/i2p.i2p/
 - Purple i2pd: https://github.com/PurpleI2P/i2pd
 - I2P+: https://github.com/I2PPlus/i2pplus/
 - go-i2p: https://github.com/go-i2p/go-i2p
 - emissary: https://github.com/eepnet/emissary/

# Current Status

There is an active plan to make this production-ready: [`docs/PRODUCTION-PLAN.md`](docs/PRODUCTION-PLAN.md).
Percentages below are the original author's estimates and are mostly unmeasured; phase 6-3 of
that plan replaces them with measured results.

**What a default router now does (as of batch 0-4).** Anything known-broken is off by default,
so a stock router does not advertise capabilities it cannot honour. Opt back in with the flags
shown. Until Gate 6, do not run this on the live network (netid 2) — use `--netid 3`.

| Feature | Default | Opt-in |
|---|---|---|
| NTCP2 | **on** | — |
| NTCP2-PQ (`pq` option in RouterInfo) | **off** | `--experimental-pq` |
| SSU2 | **off** | `--enable-ssu2` |
| SSU2 connection migration (`m` cap) | **off** | none — stub, see batch 4-3 |
| Destination encryption | **ECIES-X25519** | `--proxy-encryption mlkem\|hybrid` |
| Reseed TLS certificate validation | **on** | `--insecure-reseed` |
| Reseed SU3 signature verification | **enforced, fail-closed** | `--insecure-reseed` |

* NTCP2: 
  * Inbound: 90% working
  * Outbound: 80%? working
* NTCP2-PQ: *(off by default — handshake tests are quarantined, see batch 9-3)*
  * Inbound: 50%? working
  * Outbound: 50%? working
* SSU2: *(off by default — no ACK/retransmit or Retry/token handling wired up)*
  * Inbound: Totally broken
  * Outbound: Totally broken
* SSU2-PQ: *(off by default)*
  * Inbound: Totally broken
  * Outbound: Totally broken
* Transit Tunnels:
  * 'middle hop': 70%? working? maybe fully working?
  * Outbound Endpoint: Broken
  * Inbound Gateway: Broken
* Reseed / bootstrap: **working and authenticated** (measured, batches 1-1 and 1-2)
  * TLS certificates validated against the system trust store
  * SU3 signatures verified against the 14 pinned reseed certificates; a failed or
    missing signature rejects the archive and the next host is tried
  * One default host (`i2pseed.creativecowpat.net:8443`) is self-signed and is now
    skipped; cold start still succeeds from the remaining hosts
* NetDB:
  * Floodfill:
    * Direct: LS2 store and lookup working
    * Direct: RI store and lookup working
    * Via tunnels: LS2 store and lookup working
    * Via tunnels: RI store and lookup working
  * Working NetDb isolation for different client destinations/named tunnel pools
* Session layer encryption (the e2ee through tunnels between clients or client <-> server) / "TCP" Streaming
  * ECIES-X25519: 70%? Doesn't work properly *(the default)*
  * MLKEM768-X25519: 70%? Doesn't work properly *(off by default)*
  * LS2 included in garlic for session start, stored by server in isolated netdb
* HTTP Proxy Client:
  * 60%? working, needs working session encryption/streaming
* HTTP Server Tunnel:
  * 60%? working, needs working session encryption/streaming
  * LS2 publish to floodfills via outbound tunnels working

# Memory Usage
* With I2PRouterWeb:
  * 200MB base
  * +~300MB per 1000 active NTCP2 connections (bad)
  * 3700 NTCP2 = 1.1 GB