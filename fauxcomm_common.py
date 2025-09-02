# fauxcomm_common.py
# Shared primitives for FauxComm (ECDH X25519 + HKDF + AES-256-GCM)
# Prototype for research/education purposes.
from __future__ import annotations

import os
import socket
import struct
import sys
import threading
from dataclasses import dataclass
from typing import Tuple, Optional

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


FAUXCOMM_INFO = b"fauxcomm-v1-handshake"


def _hkdf(shared_secret: bytes, salt: Optional[bytes], info: bytes, length: int) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(shared_secret)


def kdf_split_keys(shared_secret: bytes, psk: Optional[bytes], pub_a: bytes, pub_b: bytes, is_initiator: bool) -> Tuple[bytes, bytes]:
    """
    Derive two 32-byte AES keys: send_key, recv_key.
    The HKDF info binds both public keys in a canonical order to the session.
    The initiator uses the first half as send_key; responder uses it as recv_key.
    This avoids key/nonce reuse across directions.
    """
    # Canonicalize public key order
    first, second = (pub_a, pub_b) if pub_a <= pub_b else (pub_b, pub_a)
    info = FAUXCOMM_INFO + first + second
    material = _hkdf(shared_secret, psk, info, 64)  # 64 bytes -> two AES-256 keys
    k1, k2 = material[:32], material[32:64]
    if is_initiator:
        return (k1, k2)  # initiator sends with k1, receives with k2
    else:
        return (k2, k1)  # responder sends with k2, receives with k1


def sas_fingerprint(shared_secret: bytes, pub_local: bytes, pub_remote: bytes) -> str:
    """
    Compute a short authentication string (SAS) for human verification.
    12 hex chars (~48 bits) from SHA-256 of (min(pub), max(pub), shared_secret).
    """
    first, second = (pub_local, pub_remote) if pub_local <= pub_remote else (pub_remote, pub_local)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(first)
    digest.update(second)
    digest.update(shared_secret)
    h = digest.finalize()
    return h[:6].hex().upper()  # 12 hex nibbles


class NonceSeq:
    """
    Deterministic, unique 96-bit nonce sequence per sender.
    8-byte random prefix + 4-byte big-endian counter.
    """
    __slots__ = ("_prefix", "_ctr")

    def __init__(self):
        self._prefix = os.urandom(8)
        self._ctr = 0

    def next(self) -> bytes:
        if self._ctr >= 0xFFFFFFFF:
            raise RuntimeError("Nonce counter exhausted")
        ctr_bytes = self._ctr.to_bytes(4, "big")
        self._ctr += 1
        return self._prefix + ctr_bytes


def send_frame(sock: socket.socket, payload: bytes) -> None:
    # 4-byte big-endian length prefix + payload
    header = len(payload).to_bytes(4, "big")
    sock.sendall(header + payload)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        chunk = sock.recv(n - len(out))
        if not chunk:
            raise EOFError("Socket closed")
        out.extend(chunk)
    return bytes(out)


def recv_frame(sock: socket.socket) -> bytes:
    # Read 4-byte length then that many bytes
    header = recv_exact(sock, 4)
    (length,) = struct.unpack(">I", header)
    if length > 64 * 1024 * 1024:
        raise ValueError("Frame too large")
    return recv_exact(sock, length)


@dataclass
class Session:
    sock: socket.socket
    aes_send: AESGCM
    aes_recv: AESGCM
    send_nonces: NonceSeq

    def send_plaintext(self, data: bytes, aad: Optional[bytes] = None) -> None:
        nonce = self.send_nonces.next()
        ct = self.aes_send.encrypt(nonce, data, aad)
        send_frame(self.sock, nonce + ct)

    def recv_plaintext(self, aad: Optional[bytes] = None) -> bytes:
        frame = recv_frame(self.sock)
        if len(frame) < 12 + 16:
            raise ValueError("Frame too short")
        nonce, ct = frame[:12], frame[12:]
        try:
            return self.aes_recv.decrypt(nonce, ct, aad)
        except InvalidTag:
            raise InvalidTag("Decryption failed (invalid tag) — message tampered or wrong key")


def perform_handshake_as_client(sock: socket.socket, psk: Optional[bytes]) -> Tuple[Session, str]:
    """
    Client/initiator handshake:
    - generate X25519 keypair
    - send our pubkey (32B), then receive peer pubkey (32B)
    - derive shared secret, split into directional AES keys
    """
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    send_frame(sock, pub)
    peer_pub = recv_frame(sock)
    if len(peer_pub) != 32:
        raise ValueError("Invalid peer public key length")
    peer_key = x25519.X25519PublicKey.from_public_bytes(peer_pub)

    shared = priv.exchange(peer_key)
    k_send, k_recv = kdf_split_keys(shared, psk, pub, peer_pub, is_initiator=True)
    aes_send = AESGCM(k_send)
    aes_recv = AESGCM(k_recv)
    sas = sas_fingerprint(shared, pub, peer_pub)
    sess = Session(sock=sock, aes_send=aes_send, aes_recv=aes_recv, send_nonces=NonceSeq())
    return sess, sas


def perform_handshake_as_server(sock: socket.socket, psk: Optional[bytes]) -> Tuple[Session, str]:
    """
    Server/responder handshake:
    - receive peer pubkey, then send our pubkey
    - derive shared secret, split into directional AES keys
    """
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    peer_pub = recv_frame(sock)
    if len(peer_pub) != 32:
        raise ValueError("Invalid peer public key length")
    send_frame(sock, pub)
    peer_key = x25519.X25519PublicKey.from_public_bytes(peer_pub)

    shared = priv.exchange(peer_key)
    k_send, k_recv = kdf_split_keys(shared, psk, pub, peer_pub, is_initiator=False)
    aes_send = AESGCM(k_send)
    aes_recv = AESGCM(k_recv)
    sas = sas_fingerprint(shared, pub, peer_pub)
    sess = Session(sock=sock, aes_send=aes_send, aes_recv=aes_recv, send_nonces=NonceSeq())
    return sess, sas


def normalize_psk(psk_str: Optional[str]) -> Optional[bytes]:
    """
    Turn a human PSK string into bytes suitable for HKDF salt.
    Uses SHA-256(psk_str UTF-8) for fixed length and to avoid leaking length.
    """
    if psk_str is None or psk_str == "":
        return None
    digest = hashes.Hash(hashes.SHA256())
    digest.update(psk_str.encode("utf-8"))
    return digest.finalize()
