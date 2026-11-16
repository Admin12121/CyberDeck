# Network Parity Roadmap

The explicit, tiered checklist for completing Wireshark / Nmap / Ettercap / Bettercap
capability in CyberDeck. Each item is a vertical slice: native Rust engine → typed IPC →
UI (coss card pattern) → source-contract tests → honest runtime gates. Nothing is
advertised before it proves itself (KAT gates, tag-verified decryption, on-scope checks).

This file is the measure of "how close to done" — every completed wave checks items off.
Landed work stays in the list with ✅ so progress stays countable.

## Ground rules

- Native Rust reimplementation; upstream sources in `reference/` are behavior
  documentation only. Bundling happens only where a license permits and engine speed
  demands it (hashcat MIT vendored; john GPLv2 sidecar) — the network category is
  100% own code.
- Platform policy (user decision 2026-11-16): wifi monitor mode — own Rust nl80211 on
  Linux, optional detected Npcap on Windows (never bundled), honest `Unsupported` on
  macOS. BLE — own raw HCI on Linux, `Unsupported` elsewhere.
- Every slice degrades honestly: unknown protocols show structure + hex, never guessed
  fields; decryption only with verified tags; scanning refuses anything off-scope.

## Tier 0 — Landed (the foundation)

- ✅ Packet engine: PCAP/PCAPNG, Ethernet/ARP/IPv4/IPv6/TCP/UDP/ICMP, fragments,
  TCP stream reassembly + follow-stream (directional, gap-honest)
- ✅ Application dissectors: DNS/mDNS/LLMNR, DHCP, NTP, STUN, HTTP/1.x, HTTP/2+HPACK,
  TLS 1.0–1.3 hello depth, QUIC v1
- ✅ Display filters + BPF capture filters (own implementations)
- ✅ Export on click: payload → Recipes, payload → derived case evidence, lab session
  report → case finding, PCAP export
- ✅ Scanning: TCP connect + SYN (Linux raw), ICMP echo, ARP sweep, profiles, depth,
  OS hints, NSE-lite 32 checks (grew from 13)
- ✅ QUIC decryption chain: Initial (stateless) + Handshake/1-RTT (keylog), hand-rolled
  SHA-256/HKDF/AES-128-GCM, RFC 9000 pn reconstruction
- ✅ TLS 1.3 stream decryption via NSS keylog
- ✅ Ettercap/Bettercap LAN core: live monitor, ARP-conflict watch, DNS monitor,
  gated full-duplex ARP spoofer (native dialog, restoration ledger), session reports
- ✅ Zero-dependency crypto module in the packet crate (SHA-256/HKDF/AES/GCM/HMAC)

## Tier 1 — next wave (in progress, high real-capture frequency)

✅ **Wifi monitor crate layer (Linux)** — hand-rolled nl80211/netlink client,
  radiotap, 802.11 MAC dissection (beacon/probe/data/auth/deauth), EAPOL 4-way capture
  → hashcat 22000 lines (PMKID + EAPOL), cross-crate e2e verified through our own
  WPA verifier (`windows_auth::verify_wpa_eapol`) (6cca540)
✅ **TLS 1.2 decryption via keylog CLIENT_RANDOM** — RFC 5246 key block, AES-128-GCM
  suites (a5d4307); CBC + AES-256-GCM/SHA-384-PRF deferred to Tier 1 tail
✅ Wifi IPC + Network Lab "Wifi" mode end-to-end (interfaces, pinned channel list,
  start/stop, beacons/clients tables, handshake-captured → ONE bounded case finding)
  (71fbbd8)
✅ Windows: Npcap presence detection (registry probe, surfaced as adapter status;
  detection ≠ support — monitor control stays Linux-only) (71fbbd8)
✅ SMB bounded dissector — SMB1+SMB2 commands/status/NTLMSSP/share names, dispatch
  after TLS/HTTP claims, 1800-case truncation fuzz clean (32febae)
✅ TLS 1.2 CBC suites — AES-128-CBC + HMAC-SHA1/SHA-256, both MT-E and RFC 7366 EtM
  shapes, constant-time strip, seq-advancing failure honesty; validated against live
  OpenSSL captures (3feea8e)
- [ ] EAPOL/PMKID capture → case finding → Recipes/cracking pipeline button-through

## Tier 2 — MITM completion (Bettercap/Ettercap arc)

✅ DNS spoofer — gated responder: allowlist-spoof (≤16 domains) + honest upstream
  forwarding, query log, one bounded case finding per session (525cfda)
✅ HTTP proxy — gated plain-HTTP forward proxy with sslstrip-lite rewrites
  (individually toggled, all OFF by default, counted), CONNECT refused to the Web
  studio, full header+excerpt logging, one bounded case finding per session (525cfda)
- [ ] SSL-strip module (gated, honest about HSTS limits)
✅ NSE-lite UDP plumbing — per-family bounded datagrams (NTP/DNS/mDNS/SSDP/SNMP),
  silence = open|filtered honesty; registry 42 checks (7b4974e)
- [ ] Filter-language depth: protocol/field expression grammar beyond the current
  subset (Wireshark filter parity for the fields we dissect)

## Tier 3 — radio + long tail (demand-driven)

✅ Wifi injection — gated deauth (session-observed targets only, ≤4 bursts × 32
  frames, ≥20 ms pacing, hard 10 s cap, Linux-only) (8b39756)
✅ Channel-hop scheduler — bounded list ≤ 16, 250–2000 ms interval, pause/resume,
  hop log ≤ 256, refuses while another gate op runs (8b39756)
✅ BLE Linux raw HCI — advertising scan (AD structures, names/UUIDs/manufacturer
  data, LRU ≤ 128), gated scan IPC; UI arc deferred and stated; `Unsupported`
  elsewhere (8871e09)
- [ ] WPA-enterprise (EAP) handshake handling beyond PSK
✅ More dissectors: MQTT (3.1/3.1.1/5.0), SOCKS5/4a, DHCPv6, RDP X.224 — landed
  (e9225d0); QUIC v2 remains demand-driven
✅ IO graph + endpoints — ≤120 buckets with TCP/UDP/other split from dissector
  evidence, top-64 endpoints with talker convention, case-scoped paths (ecd0306)

## Explicitly out of scope (with reason)

- Bundling Wireshark/Nmap/Ettercap/Bettercap engines — license + product shape
- macOS/Windows wifi monitor mode via own kernel drivers — OS vendor refusal
  (Apple: no public API, locked kexts; Microsoft: driver-signing cost, ecosystem
  gates via Npcap instead)
- NSE scripting engine (arbitrary Lua) — fixed honest registry replaces it
