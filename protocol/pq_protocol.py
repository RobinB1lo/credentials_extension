from typing import List
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import hashlib
import secrets
import os

try:
    import oqs  # liboqs-python: provides Dilithium (sig) and Kyber (KEM)
    _HAVE_OQS = True
except ImportError:
    _HAVE_OQS = False

KEM_ALG = "Kyber768"       # replaces classical Diffie-Hellman
SIG_ALG = "ML-DSA-65"     # replaces Ed25519

def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % sp == 0:
            return n == sp
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def _gen_prime(bits: int) -> int:
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(c):
            return c

def _subgroup_generator(p: int, q: int) -> int:
    """An element of order q: take any h to the power (p-1)/q; retry if it lands on 1."""
    cofactor = (p - 1) // q
    while True:
        h = secrets.randbelow(p - 3) + 2
        g = pow(h, cofactor, p)
        if g != 1:
            return g

def generate_parameters(q_bits: int = 160):
    """Returns (p, q, g, g1, g2, g3, h0) — this is the classical discrete-log
    group used ONLY for the Schnorr-style ZKP over the credential. It is
    unrelated to the key exchange or signatures below and stays classical."""
    q = _gen_prime(q_bits)
    while True:
        r = secrets.randbits(q_bits)
        if r % 2: r -= 1
        if r == 0:
            continue
        p = r * q + 1
        if _is_probable_prime(p):
            break
    g = _subgroup_generator(p, q)
    g1 = _subgroup_generator(p, q)
    g2 = _subgroup_generator(p, q)
    g3 = _subgroup_generator(p, q)
    h0 = _subgroup_generator(p, q)
    return p, q, g, g1, g2, g3, h0

def _canon(x: int, p: int) -> bytes:
    """Canonical fixed-width serialization for group elements/scalars mod p."""
    return x.to_bytes((p.bit_length() + 7) // 8, "big")

class Protocol:
    def __init__(self, p: int, q: int, g1: int, g2: int, g3: int, h0: int) -> None:
        self.p = p
        self.q = q
        self.g1 = g1
        self.g2 = g2
        self.g3 = g3
        self.h0 = h0

    def check_generators(self) -> str:
        if (self.p - 1) % self.q != 0:
            return "q does not divide p - 1"
        for name, g in (("g1", self.g1), ("g2", self.g2),
                        ("g3", self.g3), ("h0", self.h0)):
            if pow(g, self.q, self.p) != 1 or g == 1:
                return f"{name} is not a generator of the subgroup of order q"
        return "All generators are valid"

class Issuer:
    """Now signs credentials with Dilithium instead of Ed25519."""
    def __init__(self) -> None:
        if not _HAVE_OQS:
            raise RuntimeError("pip install liboqs-python to use signatures")
        self.signer = oqs.Signature(SIG_ALG)
        self.pk = self.signer.generate_keypair()  # public key bytes

    def sign_credential(self, cred: int, p: int) -> bytes:
        return self.signer.sign(_canon(cred, p))

    def _sign_credentials(self, message_1, message_2, p: int) -> bytes:
        message = _canon(message_1, p) + _canon(message_2, p)
        return self.signer.sign(message)

def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Stateless Dilithium verification (replaces InvalidSignature try/except pattern)."""
    with oqs.Signature(SIG_ALG) as verifier:
        return verifier.verify(message, signature, public_key)

def derive_key(shared_secret: bytes) -> bytes:
    """Map the Kyber shared secret to a 32-byte AES-256 key."""
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=None, info=b"session-key").derive(shared_secret)

class Encryption:
    def __init__(self, shared_secret: bytes) -> None:
        self.key = derive_key(shared_secret)

    def encrypt(self, text: bytes) -> bytes:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        from cryptography.hazmat.primitives import padding
        padder = padding.PKCS7(128).padder()
        padded_text = padder.update(text) + padder.finalize()
        ciphertext = encryptor.update(padded_text) + encryptor.finalize()
        return iv + ciphertext

    def decrypt(self, blob: bytes) -> bytes:
        iv, ct = blob[:16], blob[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_text = decryptor.update(ct) + decryptor.finalize()
        from cryptography.hazmat.primitives import padding
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_text) + unpadder.finalize()


class Alice:
    """Alice is the KEM 'keygen' side: she generates a Kyber keypair and
    publishes the public key; Bob encapsulates against it."""
    def __init__(self, protocol: Protocol, x1: int, x2: str, x3: int,
                 alpha: int) -> None:
        self.protocol = protocol
        self.x1 = x1
        self.x2 = x2
        self.x3 = x3
        self.alpha = alpha
        self.cred = self.compute_credential(x1, x2, x3, alpha)
        if _HAVE_OQS:
            self.sig = oqs.Signature(SIG_ALG)
            self.pk = self.sig.generate_keypair()
            self.kem = oqs.KeyEncapsulation(KEM_ALG)
            self.kem_pub = self.kem.generate_keypair()  # sent to Bob

    def decapsulate(self, ciphertext: bytes) -> bytes:
        return self.kem.decap_secret(ciphertext)

    def compute_credential(self, x1: int, x2: int, x3: int, alpha: int) -> int:
        pr = self.protocol
        return (pow(pr.g1, x1, pr.p) * pow(pr.g2, x2, pr.p)
                * pow(pr.g3, x3, pr.p) * pow(pr.h0, alpha, pr.p)) % pr.p

    def compute_mask_commitment(self, w1: int, w3: int, w4: int) -> int:
        pr = self.protocol
        return (pow(pr.g1, w1, pr.p) * pow(pr.g3, w3, pr.p)
                * pow(pr.h0, w4, pr.p)) % pr.p

    def compute_response(self, k: int, w1: int, w3: int, w4: int):
        q = self.protocol.q
        r1 = (k * self.x1 + w1) % q
        r3 = (k * self.x3 + w3) % q
        r4 = (k * self.alpha + w4) % q
        return r1, r3, r4

    def sign_transcript(self, kem_pub: bytes, kem_ct: bytes) -> bytes:
        return self.sig.sign(kem_pub + kem_ct)

class Bob:
    """Bob is the KEM 'encapsulate' side: given Alice's Kyber public key he
    derives the shared secret locally and sends back only a ciphertext."""
    def __init__(self, protocol: Protocol, x2: int, alice_kem_pub: bytes) -> None:
        self.protocol = protocol
        self.x2 = x2
        if _HAVE_OQS:
            self.sig = oqs.Signature(SIG_ALG)
            self.pk = self.sig.generate_keypair()
            with oqs.KeyEncapsulation(KEM_ALG) as encapper:
                self.kem_ct, self.shared_secret = encapper.encap_secret(alice_kem_pub)

    def verify_credential(self, cred: int, sig: bytes, issuer_pk: bytes) -> bool:
        return verify_signature(_canon(cred, self.protocol.p), sig, issuer_pk)

    def verify_response(self, cred: int, k: int, W: int,
                         r1: int, r3: int, r4: int) -> bool:
        pr = self.protocol
        lhs = (pow(cred, k, pr.p) * W) % pr.p
        rhs = (pow(pr.g1, r1, pr.p)
               * pow(pr.g2, (self.x2 * k) % pr.q, pr.p)
               * pow(pr.g3, r3, pr.p)
               * pow(pr.h0, r4, pr.p)) % pr.p
        return lhs == rhs

    def sign_transcript(self, kem_ct: bytes, kem_pub: bytes) -> bytes:
        return self.sig.sign(kem_ct + kem_pub)


def answer_to_field(answer: str, q: int) -> int:
    normalized = answer.strip().lower()
    digest = hashlib.sha256(normalized.encode('utf-8')).digest()
    return int.from_bytes(digest, "big") % q


if __name__ == "__main__":
    # === SETUP (public) ===
    p, q, g, g1, g2, g3, h0 = generate_parameters(q_bits=160)
    proto = Protocol(p, q, g1, g2, g3, h0)

    correct_answer_str = "send list"
    correct_x2 = answer_to_field(correct_answer_str, q)
    x1 = answer_to_field("question1answer", q)
    x3 = answer_to_field("question3answer", q)
    alpha = secrets.randbelow(q)

    alice = Alice(proto, x1=x1, x2=correct_x2, x3=x3, alpha=alpha)

    issuer = Issuer()
    cred_sig = issuer.sign_credential(alice.cred, p)

    for label, bob_answer_str in (("correct (send list)", "send list"),
                                   ("wrong (send Mike)", "send Mike")):
        bob_x2 = answer_to_field(bob_answer_str, q)
        bob = Bob(proto, x2=bob_x2, alice_kem_pub=alice.kem_pub)

        # --- Bob verifies the credential (Dilithium) ---
        assert bob.verify_credential(alice.cred, cred_sig, issuer.pk), "bad cred sig"

        # --- Kyber key exchange: Bob already has the shared secret from
        # encap_secret(); Alice recovers the same secret by decapsulating
        # the ciphertext Bob sends back. Neither party ever transmits a's/b's
        # discrete-log exponents — nothing DH-breakable crosses the wire. ---
        shared_secret_bob = bob.shared_secret
        shared_secret_alice = alice.decapsulate(bob.kem_ct)
        assert shared_secret_alice == shared_secret_bob, "KEM secret disagreement"
        cipher = Encryption(shared_secret_alice)

        # --- Message 2 (Bob -> Alice): mutual authentication via Dilithium,
        # transcript now binds the Kyber public key + ciphertext instead of ga/gb ---
        message_B = alice.kem_pub + bob.kem_ct
        sig_b = bob.sign_transcript(bob.kem_ct, alice.kem_pub)
        blob_B = cipher.encrypt(sig_b)

        sig_b_recovered = cipher.decrypt(blob_B)
        if not verify_signature(message_B, sig_b_recovered, bob.pk):
            print("Bob authentication FAILED — aborting session")
            break

        # --- Message 3 (Alice -> Bob) ---
        message_A = bob.kem_ct + alice.kem_pub
        sig_a = alice.sign_transcript(alice.kem_pub, bob.kem_ct)
        blob_A = cipher.encrypt(sig_a)

        sig_a_recovered = cipher.decrypt(blob_A)
        if not verify_signature(message_A, sig_a_recovered, alice.pk):
            print("Alice authentication FAILED — aborting session")
            break

        # --- The zero-knowledge proof (unchanged: classical discrete-log Schnorr ZKP) ---
        w1, w3, w4 = (secrets.randbelow(q) for _ in range(3))
        W = alice.compute_mask_commitment(w1, w3, w4)

        k = hashlib.sha256(_canon(proto.p, p) + _canon(proto.q, p) +
                            _canon(alice.cred, p) + _canon(W, p) +
                            alice.kem_pub + bob.kem_ct).digest()
        k = int.from_bytes(k, "big") % q

        r1, r3, r4 = alice.compute_response(k, w1, w3, w4)
        result = bob.verify_response(alice.cred, k, W, r1, r3, r4)
        print(f"Bob's answer {label}: verification = {result}")

        if result:
            blob_result = cipher.encrypt(_canon(bob_x2, p))
            recovered = int.from_bytes(cipher.decrypt(blob_result), "big")
            print("Message from Alice: Correct, Bob! Well done :)")
        else:
            print(f"Message from Alice: The correct answer was {correct_answer_str}, "
                  f"not {bob_answer_str}. Better luck next time :/")