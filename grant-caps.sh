#!/usr/bin/env bash
# Re-grants CAP_NET_RAW to the binary. Cargo relinks the executable on every
# build, which wipes the capabilities — run this after "cargo build".
set -e
BIN="$(cd "$(dirname "$0")" && pwd)/target/release/ipscan"
pkexec setcap cap_net_raw,cap_net_admin+ep "$BIN"
getcap "$BIN"
