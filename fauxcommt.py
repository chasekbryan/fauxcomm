# fauxcommt.py
# FauxComm Transmitter (client/initiator)
from __future__ import annotations

import argparse
import socket
import sys

from fauxcomm_common import (
    perform_handshake_as_client,
    normalize_psk,
)

BANNER = "fauxcommt — Transmitter | AES-256-GCM + X25519 (prototype)"

def main():
    ap = argparse.ArgumentParser(description=BANNER)
    ap.add_argument("--host", required=True, help="Receiver host/IP to connect to")
    ap.add_argument("--port", type=int, default=5000, help="Receiver TCP port (default: 5000)")
    ap.add_argument("--psk", default=None, help="Optional pre-shared password for MITM resistance")
    args = ap.parse_args()

    print(BANNER)
    print("- connecting to {}:{} …".format(args.host, args.port))
    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        psk = normalize_psk(args.psk)
        session, sas = perform_handshake_as_client(sock, psk)
        print("- handshake complete")
        print("- SAS (compare verbally with peer): [{}]".format(sas))
        if psk:
            print("- PSK in use (handshake bound to password)")

        print("- type messages and press Enter to send. /quit to exit.\n")
        for line in sys.stdin:
            text = line.rstrip("\r\n")
            if text.strip() == "/quit":
                break
            data = text.encode("utf-8")
            try:
                session.send_plaintext(data)
            except (BrokenPipeError, OSError):
                print("- connection lost")
                break
    print("- done.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n- exiting.")
        sys.exit(0)
