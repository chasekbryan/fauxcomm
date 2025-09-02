# fauxcomm (Python Prototype)

fauxcomm is a minimal encrypted-communication **sandbox** with two programs:
- `fauxcommr` — receiver (server / responder)
- `fauxcommt` — transmitter (client / initiator)

Each user runs both programs on their own machine (receiver to listen, transmitter to send).
Messages are end‑to‑end encrypted using **X25519 ECDH** for key agreement, **HKDF‑SHA256** for key derivation, and **AES‑256‑GCM** for authenticated encryption. Directional keys are derived to avoid nonce/key reuse across directions. A short **SAS** fingerprint is shown after the handshake so peers can verbally verify the channel. Optionally, a **pre‑shared password (PSK)** can be supplied to bind the handshake and resist MITM without out‑of‑band verification.

## Quick start

- `python3 -m venv .venv && source .venv/bin/activate`
- `pip install -r requirements.txt`

### On User A (receiver)
- `python3 fauxcommr.py --host 0.0.0.0 --port 5000 --psk "shared-password"`

### On User B (transmitter)
- `python3 fauxcommt.py --host <UserA_IP> --port 5000 --psk "shared-password"`
- Type a line and press Enter to send. Use `/quit` to exit.

Notes
- PSK is optional. If omitted, compare the **SAS** shown at both ends (12 hex) via a trusted channel; mismatch implies a MITM attempt.
- Make sure the port is reachable (firewall, NAT). For local testing, run both on one machine and connect to `127.0.0.1`.

## Design highlights

- **Key exchange:** Ephemeral X25519 (ECDH) — forward secrecy.
- **KDF:** HKDF‑SHA256 over the shared secret with both public keys bound into the HKDF info.
- **Directional keys:** HKDF yields 64 bytes → split into two 256‑bit AES keys. Initiator uses K1 to send (server receives with K1), and K2 vice‑versa.
- **Nonces:** Per‑sender sequence with 8‑byte random prefix + 4‑byte counter (96‑bit GCM nonce). Unique per sender.
- **AEAD:** AES‑256‑GCM with integrity (rejects tampering).
- **SAS:** 12‑hex Short Authentication String from SHA256(min(pub), max(pub), shared_secret). Compare out‑of‑band if no PSK.
- **MITM resistance:** Either PSK (bound as HKDF salt) or human SAS verification.

## Files

- `fauxcomm_common.py` — crypto and framing primitives (shared)
- `fauxcommr.py` — receiver (server)
- `fauxcommt.py` — transmitter (client)
- `requirements.txt` — Python deps

## Security notes

- Prototype quality — for research/education. Avoid logging plaintext or keys. Review code before production use.
- Nonce exhaustion raises an error after 2^32 messages per run; restart session to re‑key long conversations.
- Consider re‑handshaking periodically for additional forward secrecy.
- Endpoints must be trusted; if a device is compromised, messages can be read before encryption or after decryption.
