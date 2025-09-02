# fauxcommr.py
# FauxComm Receiver (server/responder)
from __future__ import annotations

import argparse
import socket
import sys
from cryptography.exceptions import InvalidTag
from fauxcomm_common import (
    perform_handshake_as_server,
    normalize_psk,
)

BANNER = "fauxcommr — Receiver | AES-256-GCM + X25519 (prototype)"

def main():
    ap = argparse.ArgumentParser(description=BANNER)
    ap.add_argument("--host", default="0.0.0.0", help="Host/IP to bind (default: 0.0.0.0)")
    ap.add_argument("--port", type=int, default=5000, help="TCP port to listen on (default: 5000)")
    ap.add_argument("--psk", default=None, help="Optional pre-shared password for MITM resistance")
    args = ap.parse_args()

    print(BANNER)
    print("- listening on {}:{} …".format(args.host, args.port))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((args.host, args.port))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            print("- connection from {}:{}".format(addr[0], addr[1]))
            psk = normalize_psk(args.psk)
            session, sas = perform_handshake_as_server(conn, psk)
            print("- handshake complete")
            print("- SAS (compare verbally with peer): [{}]".format(sas))
            if psk:
                print("- PSK in use (handshake bound to password)")

            print("- ready to receive messages. Ctrl+C to quit.\n")
            while True:
                try:
                    pt = session.recv_plaintext()
                except InvalidTag:
                    print("! ERROR: invalid tag — message tampered or wrong key. Closing.")
                    break
                except (EOFError, OSError):
                    print("- peer closed connection")
                    break
                try:
                    msg = pt.decode("utf-8", errors="replace")
                except Exception:
                    msg = repr(pt)
                print("> {}".format(msg))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n- exiting.")
        sys.exit(0)
