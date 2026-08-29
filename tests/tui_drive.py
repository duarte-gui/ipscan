#!/usr/bin/env python3
"""Drives the TUI through a pty: sends keys, waits, captures the final screen.

Usage: tui_drive.py <iface> [scan_seconds]

Starts the TUI pointed at the synthetic lab (expected 172.31.99.0/24, extra
range 10.37.129.0/24 where the intruder lives), runs the sweep ('r'), waits,
exports ('e') and quits ('q'). Prints the final screen (ANSI stripped) for
inspection.
"""
import os
import pty
import re
import select
import sys
import time

iface = sys.argv[1] if len(sys.argv) > 1 else "br-ipscan-test"
scan_secs = float(sys.argv[2]) if len(sys.argv) > 2 else 8.0
BIN = os.path.join(os.path.dirname(__file__), "..", "target", "release", "ipscan")


def main():
    pid, fd = pty.fork()
    if pid == 0:  # child: runs the TUI
        os.execv(
            BIN,
            [BIN, "--tui", "-i", iface, "-e", "172.31.99.0/24",
             "-r", "10.37.129.0/24", "--scope", "none"],
        )
        os._exit(1)

    buf = bytearray()

    def pump(dur):
        end = time.time() + dur
        while time.time() < end:
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    return
                if not data:
                    return
                buf.extend(data)

    pump(1.0)            # let the TUI draw
    os.write(fd, b"r")   # run the sweep
    pump(scan_secs)      # wait for sweep + collection
    os.write(fd, b"e")   # export
    pump(1.0)
    os.write(fd, b"q")   # quit
    pump(1.0)
    try:
        os.close(fd)
    except OSError:
        pass
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass

    text = buf.decode("utf-8", "replace")
    clean = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
    clean = re.sub(r"\x1b\][0-9];[^\x07]*\x07", "", clean)
    clean = clean.replace("\x1b(B", "").replace("\x1b=", "").replace("\x1b>", "")
    sys.stdout.write(clean[-6000:])


if __name__ == "__main__":
    main()
