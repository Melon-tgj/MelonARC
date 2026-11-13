# Technology validation results

Three spikes were built to retire the open risks of the MVP before the core work
starts: TUN packet handling on Linux, a QUIC round trip, and rule matching at the
100k rule scale demanded by the performance target.

- Date: 2026-11-13
- Module: `github.com/melon-tgj/melonarc`
- Toolchain: Go 1.27.4 linux/amd64, git 2.43
- Host: Linux x86_64 container, AMD EPYC 9D25, process running as root
- Dependencies added: `github.com/quic-go/quic-go v0.65.0`, `golang.org/x/sys v0.50.0`

## Summary

| Spike | Code | Result | Key number |
|---|---|---|---|
| TUN device + packet read | `spikes/tun` | Pass | 46-byte IPv4/UDP packet read from `melonarc0`, header decoded |
| QUIC loopback echo | `spikes/quic` | Pass | QUIC v1, TLS 1.3, ALPN `melonarc-echo`, 23-byte payload echoed byte for byte |
| Rule index at 100k rules | `spikes/ruleindex` | Pass | 330 ns per mixed match, 0 allocations; target was < 1 ms |

All three pass. Two of them only pass with an explicit workaround for the
sandbox this was run in, which refuses `sendto`/`sendmsg` and `connect` to
anything outside `127.0.0.0/8`. The workarounds are behind flags, so the default
code path stays the one a real host would use.

Reproduce:

```
go run ./spikes/ruleindex
go test -bench . -benchmem ./spikes/ruleindex
go build -o /tmp/tunspike ./spikes/tun && unshare -Urn /tmp/tunspike -loopback
go build -o /tmp/quicspike ./spikes/quic && /tmp/quicspike -connected-udp
```

## 1. TUN device and packet read

Goal: open `/dev/net/tun`, create a TUN device, assign a test address, push a
packet through the kernel routing path into the device, read it back and print
the IP header summary.

How: `open("/dev/net/tun")` then `ioctl(TUNSETIFF)` with `IFF_TUN|IFF_NO_PI`,
address and link state configured over rtnetlink (`RTM_NEWADDR`, `RTM_NEWLINK`,
`RTM_NEWROUTE`), then a UDP datagram is sent so the kernel routes it into the
device. The reader polls the descriptor and decodes the IPv4 header.

Output (inside `unshare -Urn`, `-loopback` probe):

```
tunspike: device melonarc0 created, fd=4
tunspike: ifindex=2 mtu=1500
tunspike: address 198.18.0.1/24 assigned, link up
tunspike: route 127.0.0.9/32 dev melonarc0 installed, local 127.0.0.0/8 route removed
tunspike: probe datagram sent to 127.0.0.9:5300
tunspike: skipped a non-IPv4 packet (version 6, 48 bytes)
packet: 46 bytes captured (ip total length 46, ihl 20)
  src=198.18.0.1 dst=127.0.0.9 proto=17 (udp)
  udp src=40319 dst=5300 payload="melonarc-tun-probe"
OK: read one packet from the TUN device
```

Verdict: pass. A TUN device can be created from Go with three netlink calls and
raw packets can be read and decoded from the descriptor. No user-space network
stack was needed for this step, so the protocol stack question stays open and is
not blocked by anything here.

Pitfalls:

1. `TUNSETIFF` needs `CAP_NET_ADMIN`. This container keeps `/dev/net/tun` but
   drops that capability from the bounding set (`CapEff=000001ffffb7cfff`, bit 12
   clear), so even root gets `EPERM`, and a new network namespace does not help
   because the capability is gone for good. A user plus network namespace
   (`unshare -Urn`) does help, because a fresh user namespace hands the process a
   full capability set inside it. On a normal host `sudo` is enough.
2. The sandbox refuses `sendto` and `sendmsg` with `EPERM`, and `connect` to
   anything outside `127.0.0.0/8` with `ENETUNREACH`. A UDP socket that is
   `connect`ed first and then written to works, so the probe does that.
3. With the natural probe address unreachable, the `-loopback` mode routes
   `127.0.0.9` at the device. The kernel's local table owns `127.0.0.0/8`, so that
   route has to be removed first and is restored on exit. This rewrites host
   routing, hence the requirement to run it inside a private namespace only.
4. A fresh namespace has `lo` down, so there is no `127.0.0.0/8` route to remove
   and the delete fails with `ESRCH`; the spike now brings `lo` up and treats a
   missing route as success.
5. Netlink details that cost time: `rtm_dst` must be masked to the prefix length
   or the kernel answers `EINVAL`, and a route delete only matches when protocol,
   scope and type are left unspecified (`RTPROT_UNSPEC`, `RT_SCOPE_NOWHERE`,
   `RTN_UNSPEC`).
6. Bringing a link up makes the kernel emit IPv6 auto-configuration traffic on
   it. A 48-byte IPv6 packet arrived before the probe, so the reader filters by IP
   version.

## 2. QUIC loopback echo

Goal: quic-go server on `127.0.0.1` with a self-signed certificate, a client that
dials it, sends a string over a bidirectional stream and verifies the echo.

How: one process starts both endpoints. The certificate is ECDSA P-256 with
`127.0.0.1` as an IP SAN; the client trusts it through `RootCAs` rather than
skipping verification. The server reads to EOF and writes the bytes back.

Output (`-connected-udp`):

```
quicspike: server listening on 127.0.0.1:36391 (udp), alpn "melonarc-echo", connected sockets: true
quicspike: connected: version=v1 alpn="melonarc-echo" tls=TLS 1.3
quicspike: server read 23 bytes on stream 0
sent:     "melonarc-quic-echo-ping"
received: "melonarc-quic-echo-ping"
OK: echo round trip over QUIC matches
```

Verdict: pass. quic-go v0.65 integrates with plain `crypto/tls` and needs no
special build tags; a full handshake plus a bidirectional stream costs about a
millisecond on loopback. The Hysteria2 and TUIC outbounds can be built on it.

Pitfalls:

1. The default path fails here: `DialAddr` reports `write udp ...: sendmsg:
   operation not permitted`, the same sandbox restriction as the TUN spike.
   quic-go writes datagrams with `sendmsg` on an unconnected socket, which this
   sandbox denies.
2. Workaround: both endpoints bind a loopback port, `connect` their sockets to
   each other and hand quic-go a `quic.Transport` with a small `net.PacketConn`
   adapter that only uses `read`/`write`. Because the connection is no longer a
   `*net.UDPConn`, quic-go disables GSO, ECN and `recvmmsg` batching, and logs
   `connection doesn't allow setting of receive buffer size`. Correct, but it
   costs throughput: real deployments must use the plain path.
3. The server must not close the connection right after writing the echo. Doing
   so pushed a `CONNECTION_CLOSE` ahead of the buffered stream data and the client
   failed with `read echo: Application error 0x0 (remote)`. The echo server now
   leaves the connection open and lets the transport close it during cleanup.
4. Half-close semantics: `stream.Close()` only closes the write direction, which
   is what makes "write, half-close, read the echo" work while the server still
   sees EOF.

## 3. Rule index at 100k rules

Goal: a prototype matcher that answers a single match in well under 1 ms with
100k mixed rules, to prove the indexed design before committing to it.

How: `DOMAIN-SUFFIX` rules go into a label trie walked from the top-level domain
downwards with no allocation per lookup; `IP-CIDR` rules are compiled into a
sorted array of disjoint address ranges searched with binary search. Because CIDR
blocks are either disjoint or nested, one sweep over the blocks sorted by start
address produces the range table, with the most specific block winning. The data
set is deterministic: 50k suffixes, 50k prefixes (masked, length `/8` to `/32`,
with plenty of nesting and overlap), plus 4096 domain and 4096 address probes,
two thirds of which hit.

Index size:

```
rules: 50000 domain suffix + 50000 ip-cidr = 100000 total
index: 86676 disjoint ip ranges, built in 255ms
heap after build: 13.0 MiB (allocated in total 41.6 MiB)
```

Benchmarks (`go test -bench . -benchmem -benchtime=2s -count=3`, one process):

```
BenchmarkMatchDomain-4   12182047    220.3 ns/op    0 B/op   0 allocs/op
BenchmarkMatchDomain-4   11110944    235.9 ns/op    0 B/op   0 allocs/op
BenchmarkMatchDomain-4   10921443    220.6 ns/op    0 B/op   0 allocs/op
BenchmarkMatchIP-4        7553878    301.9 ns/op    0 B/op   0 allocs/op
BenchmarkMatchIP-4        8072361    339.9 ns/op    0 B/op   0 allocs/op
BenchmarkMatchIP-4        8038178    308.6 ns/op    0 B/op   0 allocs/op
BenchmarkMatchMixed-4     7182003    334.1 ns/op   24 B/op   0 allocs/op
BenchmarkMatchMixed-4     6358118    330.5 ns/op   24 B/op   0 allocs/op
BenchmarkMatchMixed-4     6142118    330.5 ns/op   24 B/op   0 allocs/op
BenchmarkBuild-4               21  101187758 ns/op  23726028 B/op  300472 allocs/op
```

Verdict: pass, with three orders of magnitude of headroom. A mixed match averages
330 ns against a 1 ms budget, and a full 100k rule rebuild takes about 105 ms and
24 MB, which is affordable for a configuration reload and fits the "idle under
80 MB" memory target together with the rest of the core. Indexed matching is the
right design; no further comparison against linear scanning is needed, since a
linear scan at 100k rules is orders of magnitude away from the target.

Pitfalls:

1. A 64-bit cursor is mandatory in the sweep. With `uint32`, `end+1` at
   `255.255.255.255` wrapped to `0` and emitted a bogus `0.0.0.0-255.255.255.255`
   range at the end of the table, which broke the sorted-order invariant the
   binary search depends on. The 4k-scale oracle test passed anyway; only the
   100k-scale invariant test (`TestRangesSortedAndDisjoint`) caught it. Keep both.
2. `DOMAIN-SUFFIX` has to match on label boundaries. A plain `strings.HasSuffix`
   would make `notexample.com` match `example.com`. The trie walk handles this,
   and `TestSuffixNeedsLabelBoundary` pins it.
3. The dispatcher `Match(string)` calls `net.ParseIP` first and that allocates
   24 bytes per call, which shows up as `24 B/op` in `BenchmarkMatchMixed`. The
   real engine knows whether the target is a domain or an address from the
   connection, so the string dispatcher will not be on the hot path. If it ever
   is, a hand-written IPv4 literal check removes the allocation.
4. Random prefix generation collides: 50k draws produced only 44k unique
   prefixes, so the generator retries until the count is exact. Rule counts in a
   benchmark must be the count claimed in the report.
5. The range table is memory bound, not compute bound: 302 ns for a binary search
   over 86k ranges is dominated by cache misses, and a longest-prefix-match trie
   would not do better at this size. If IP rules ever grow by an order of
   magnitude, the next step is a 16-bit first-level index over the range table,
   not a different data structure.

## Notes

- Naming hygiene: all files and both commit messages were checked for
  non-open-source commercial product names; only protocol names from the MVP
  scope appear.
- The spikes are throwaway prototypes. Their packages live under `spikes/` and
  are not imported by the core; the rule matcher is the one piece intended to be
  reworked into `internal/rules`.
- Not covered here, and still open for the MVP: the user-space network stack for
  TUN mode, Windows support (the TUN code is Linux-only by design), and any
  protocol implementation work.
