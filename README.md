# ipscan

Finds devices with a **static IP outside the expected range** on a local
network — the box plugged into a switch holding an address that does not belong
to your subnet, invisible both to DHCP and to a plain `arp-scan` of your own
network.

It does that by combining four discovery layers and cross-checking the result
against observed DHCP leases, so it can point at exactly who does not fit.

## Why an ordinary scanner misses it

A device configured with a fixed IP outside your subnet (say `10.37.129.88` on a
`192.168.1.0/24` network):

- never asked for DHCP, so there is no lease for it;
- does not answer `arp-scan 192.168.1.0/24`, because its ARP responder only
  reacts to requests whose *target* is the address it actually owns;
- never lands in your machine's ARP table, because the two of you exchange no
  packets.

Angry IP Scanner finds it by brute-force ICMP ping with a per-host timeout —
which is why it is slow. `ipscan` takes more direct routes.

## The four layers

1. **Passive.** Listen only. A misconfigured static IP still gives itself away:
   gratuitous ARP at boot, ARP probes (RFC 5227), IPv4 traffic and ICMPv6. Every
   frame carries a `(MAC, real IP)` pair. Cost: zero packets sent
   (`--passive-only`).

2. **L2 enumeration over IPv6.** One ICMPv6 Echo to `ff02::1` makes every device
   with an IPv6 stack answer with its link-local address — **regardless of the
   IPv4 it holds**. This reveals the MAC of whoever is silent on IPv4.

3. **Directed ARP sweep** (`--scope auto`, the default). Sweeps the local
   subnet, the subnets revealed by layers 1–2, and a list of factory defaults
   (Mikrotik `192.168.88`, Fritz!Box `192.168.178`, Moxa `192.168.127`, …).
   Seconds.

4. **Exhaustive ARP sweep** (`--scope rfc1918`). The whole private space, using
   an ARP probe (sender `0.0.0.0`), which reaches foreign subnets without
   poisoning anyone's ARP cache. Minutes.

## The ARP probe (`--spa`)

The subtlest point. Measured in a lab against a Linux target holding a static
address in a subnet the prober does not belong to:

| ARP request sender | does the target answer? |
|---|---|
| our own IP (different subnet) | no |
| same as the target | no |
| a neighbour inside the target's subnet | yes |
| `0.0.0.0` (ARP probe, RFC 5227) | **yes** |

Hence the `--spa probe` default: it is the only sender that reaches any subnet
**and** writes no bogus IP→MAC pair into the neighbours' ARP caches. A forged
neighbour sender (`--spa neighbor`) beats stacks that ignore the probe, but it
is ARP poisoning — use it knowingly; the program warns while that mode is on.

## Pacing and storm control (important)

ARP is broadcast: every request is flooded to all switch ports. Sweeping large
ranges at high speed **trips the broadcast storm control** on managed switches,
which then starts dropping frames — and what gets dropped is precisely the
replies you are waiting for. The failure is quiet: a sweep that was finding
hosts reliably starts returning almost nothing once a large broadcast block is
appended behind it.

`ipscan` works around that by sweeping **one `/24` at a time**, with a settle
window between blocks (`--settle`, default 150 ms) and a resend pass
(`--passes`, default 2). Small, likely subnets are swept **before** the large
exhaustive blocks, so the targets that matter get clean replies ahead of any
flood. If the kernel still drops frames, the program says so.

## Report flags

| Flag | Meaning | Severity |
|---|---|---|
| `OUTSIDE_SUBNET` | IP outside every expected subnet — the target | critical |
| `L2_ONLY` | seen on the link (IPv6/frame) with no IPv4 at all | critical |
| `NO_LEASE` | alive, no lease — only when a DHCP baseline exists | high |
| `LEASE_MISMATCH` | DHCP handed out X, the device uses Y | high |
| `DUPLICATE_IP` | two MACs claiming the same IP | high |
| `APIPA` | fell back to 169.254/16: DHCP failed | high |
| `ORPHAN_LEASE` | lease on record, MAC no longer present | info |

`NO_LEASE` only fires when the session has a **DHCP baseline**: a `--leases-file`
loaded, or at least one DHCPACK observed on the wire. With neither source the
flag stays quiet — not seeing a lease is not the same as there being none, and
accusing everyone on missing data would drown the finding that matters. Even
with a baseline, `NO_LEASE` alone is common (every legitimately static host has
it). The strong signals are `OUTSIDE_SUBNET` and `L2_ONLY`.

## Interactive interface (TUI)

Besides the CLI there is an on-demand TUI (`ipscan --tui`) for composing the
scan and inspecting findings interactively:

```
ipscan --tui
```

- **Left pane (form)**: interface, scope (`auto`/`rfc1918`/`private16`/ranges
  only) and the **range list**. Each range carries a three-state marker, cycled
  with `Space`:

  | | swept? | counts as legitimate? | use |
  |---|---|---|---|
  | `[ ]` **network** | yes | yes → stays hidden | the network you are on |
  | `[>]` **target** | yes, first | **no** → flags whoever is there | the range you suspect |
  | `[!]` **ignore** | **not a single packet** | yes → disappears | a range you already ruled out |

  `[!]` is subtracted from the targets **after** the scope is assembled —
  otherwise `auto` would hand it back through the side door. It works at any
  prefix length, including shorter than a `/24`. If no range is left as `[ ]`,
  the interface subnet becomes the baseline; if the interface has no subnet (a
  network without DHCP), there is no baseline — and that is the truth about the
  network.

  An "Advanced" drawer holds spa/rate/settle/passes/no-ipv6/leases/passive.
- **Hypothesis hunting** (`s`): with the cursor on a range, `s` sweeps **only
  that range, now** — ignoring the scope and the other ranges, with no passive
  listening. It is the "type `10.0.0.0/24`, fire, read, switch guess" loop, at
  roughly a second per attempt. `r`/`Enter` remains the full scan.
- **Right pane (results)**: a table with severity (`●` critical / `▲` high /
  `·` ok), MAC, IPv4, vendor and flags — the intruder jumps to the top in red.
  The footer shows the focused host in detail.
- **On demand**: nothing runs by itself; `r`/`Enter` fires. Results stream in
  with a progress bar, and `Esc` cancels while keeping what was already found.

Keys: `r`/`Enter` run · `s` sweep the focused range · `Tab` switch pane ·
`j`/`k` move · `h`/`l` cycle fields · `a`/`d` add/remove range · `Space` cycle
the range marker · `w` whitelist (session) · `y` copy MAC · `p` probe · `/`
filter · `f` flagged-only · `e` export JSON+CSV · `?` help · `q` quit.

Configuration and whitelist live in the session only (nothing is written to
disk except the export).

## Usage

```
# grant the capability once (cargo strips it on every rebuild):
./grant-caps.sh

# listen + directed sweep (the common case), interface auto-detected:
ipscan

# listen only, sending nothing:
ipscan --passive-only -p 30

# exhaustive sweep of the whole RFC1918 space:
ipscan --scope rfc1918

# a specific subnet, JSON output:
ipscan --range 10.37.129.0/24 --json

# continuous monitoring, reporting only what is new:
ipscan --watch

# cross-check against the server's lease file (dnsmasq or ISC dhcpd):
ipscan --leases-file /var/lib/misc/dnsmasq.leases
```

Main options: `-i/--iface`, `-e/--expected CIDR` (legitimate subnets),
`-X/--exclude CIDR` (ranges to ignore — the TUI's `[!]`),
`-s/--scope none|auto|private16|rfc1918`, `-r/--range CIDR`, `-p/--passive-secs`,
`--rate`, `--settle`, `--passes`, `--spa probe|local|dest|neighbor|IP`,
`--json`, `--csv`, `-a/--all`, `-w/--watch`.

## Privilege

Needs `CAP_NET_RAW` (sending and receiving raw frames) and uses `CAP_NET_ADMIN`
when available to force the receive buffer size. Grant it once with
`grant-caps.sh` (via `pkexec`/`sudo`); afterwards it runs as a normal user.
Without the capability the program prints the exact command to run instead of
failing with a raw error.

## Build

```
cargo build --release
./grant-caps.sh
```

## Test

`tests/lab.sh` builds an isolated bridge with two network namespaces — one
legitimate host and one "intruder" holding a static address in a foreign subnet
— so detection can be validated without hardware. See the script header.
