#!/usr/bin/env bash
# Grants the capability and brings up the synthetic lab for the TUI test.
# Run with sudo.
set -e
BIN="$(cd "$(dirname "$0")/.." && pwd)/target/release/ipscan"
setcap cap_net_raw,cap_net_admin+ep "$BIN"
echo "capability granted:"; getcap "$BIN"
"$(dirname "$0")/lab.sh" up
