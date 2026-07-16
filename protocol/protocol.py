from typing import List
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import hashlib
import secrets
import os

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.exceptions import InvalidSignature
    _HAVE_CRYPTO = True
except ImportError:
    _HAVE_CRYPTO = False

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

# Should this be a hashing function instead? Since it is not totally "safe"
def _subgroup_generator(p: int, q: int) -> int:
    """An element of order q: take any h to the power (p-1)/q; retry if it lands on 1."""
    cofactor = (p - 1) // q
    while True:
        h = secrets.randbelow(p - 3) + 2
        g = pow(h, cofactor, p)
        if g != 1:
            return g

def generate_parameters(q_bits: int = 160):
    """Returns (p, q, g, g1, g2, g3, h0)"""
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
    """Canonical fixed-width serialization - both signer and verifier MUST match."""
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
    def __init__(self) -> None:
        if not _HAVE_CRYPTO:
            raise RuntimeError("pip install cryptography to use signatures")
        self.sk = Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key()

    def sign_credential(self, cred: int, p: int) -> bytes: 
        return self.sk.sign(_canon(cred, p))
    
    def _sign_credentials(self, message_1, message_2, p: int) -> bytes:
        message = _canon(message_1, p) + _canon(message_2, p)
        return self.sk.sign(message)

    
def derive_key(K: int, p: int) -> bytes:
    """Map the shared DH secret K to a 32-byte AES-256 key."""
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=None, info=b"session-key").derive(_canon(K, p))

class Encryption:
    def __init__(self, K: int, p: int) -> None:
        self.key = derive_key(K, p)  # 32-byte key for AES-256

    def encrypt(self, text: bytes) -> bytes:
        """Encrypt using AES-256 in CTR mode (no authentication)."""
        iv = os.urandom(16)  # 16-byte IV for CBC
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        # WARNING: CBC requires padding. Using PKCS7.
        from cryptography.hazmat.primitives import padding
        padder = padding.PKCS7(128).padder()
        padded_text = padder.update(text) + padder.finalize()
        ciphertext = encryptor.update(padded_text) + encryptor.finalize()
        return iv + ciphertext  # prepend IV

    def decrypt(self, blob: bytes) -> bytes:
        """Decrypt using AES-256 in CBC mode (no authentication check)."""
        iv, ct = blob[:16], blob[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_text = decryptor.update(ct) + decryptor.finalize()
        # Remove PKCS7 padding
        from cryptography.hazmat.primitives import padding
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_text) + unpadder.finalize()


class Alice:
    def __init__(self, protocol: Protocol, x1: int, x2: str, x3: int,
                 alpha: int, a: int, g: int) -> None:
        self.protocol = protocol
        self.x1 = x1          # correct answer to Q1
        self.x2 = x2          # correct answer to Q2 (tested, never revealed)
        self.x3 = x3          # correct answer to Q3
        self.alpha = alpha    # blinding factor
        self.cred = self.compute_credential(x1, x2, x3, alpha)
        self.a = a
        self.ga = pow(g, self.a, protocol.p)
        if _HAVE_CRYPTO:
            self.sk = Ed25519PrivateKey.generate()
            self.pk = self.sk.public_key()

    def compute_session_key(self, gb: int) -> int:
        return pow(gb, self.a, self.protocol.p)

    def compute_credential(self, x1: int, x2: int, x3: int, alpha: int) -> int:
        pr = self.protocol
        return (pow(pr.g1, x1, pr.p) * pow(pr.g2, x2, pr.p)
                * pow(pr.g3, x3, pr.p) * pow(pr.h0, alpha, pr.p)) % pr.p

    def compute_mask_commitment(self, w1: int, w3: int, w4: int) -> int:
        """Computes W (was named self_assessment). Note: NO g2 term."""
        pr = self.protocol
        return (pow(pr.g1, w1, pr.p) * pow(pr.g3, w3, pr.p)
                * pow(pr.h0, w4, pr.p)) % pr.p

    def compute_response(self, k: int, w1: int, w3: int, w4: int):
        q = self.protocol.q
        r1 = (k * self.x1 + w1) % q     
        r3 = (k * self.x3 + w3) % q     
        r4 = (k * self.alpha + w4) % q  
        return r1, r3, r4               

    def sign_transcript(self, ga: int, gb: int) -> bytes:
        return self.sk.sign(_canon(ga, self.protocol.p) + _canon(gb, self.protocol.p))

class Bob:
    def __init__(self, protocol: Protocol, b: int, g: int, x2: int) -> None:
        self.protocol = protocol
        self.b = b
        self.gb = pow(g, self.b, protocol.p)   
        self.x2 = x2
        if _HAVE_CRYPTO:
            self.sk = Ed25519PrivateKey.generate()
            self.pk = self.sk.public_key()

    def compute_session_key(self, ga: int) -> int:
        return pow(ga, self.b, self.protocol.p)

    def verify_credential(self, cred: int, sig: bytes, issuer_pk) -> bool:
        try:
            issuer_pk.verify(sig, _canon(cred, self.protocol.p))
            return True
        except InvalidSignature:
            return False

    def verify_response(self, cred: int, k: int, W: int,
                        r1: int, r3: int, r4: int) -> bool:
        pr = self.protocol
        lhs = (pow(cred, k, pr.p) * W) % pr.p
        rhs = (pow(pr.g1, r1, pr.p)
               * pow(pr.g2, (self.x2 * k) % pr.q, pr.p)
               * pow(pr.g3, r3, pr.p)
               * pow(pr.h0, r4, pr.p)) % pr.p
        return lhs == rhs

    def sign_transcript(self, gb: int, ga: int) -> bytes:
        return self.sk.sign(_canon(gb, self.protocol.p) + _canon(ga, self.protocol.p))

    
def answer_to_field(answer: str, q: int) -> int:
    """Hash a string answer to a field element mod q using SHA-256."""
    normalized = answer.strip().lower()
    digest = hashlib.sha256(normalized.encode('utf-8')).digest()
    return int.from_bytes(digest, "big") % q


if __name__ == "__main__":
    # === SETUP (public) ===
    p, q, g, g1, g2, g3, h0 = generate_parameters(q_bits=160)
    proto = Protocol(p, q, g1, g2, g3, h0)

    # === Alice's answer (hashed to field) ===
    correct_answer_str = "send list"
    correct_x2 = answer_to_field(correct_answer_str, q)  # SHA-256 hash to field
    
    # === Consistent-length answers (also hashed) ===
    x1 = answer_to_field("question1answer", q)
    x3 = answer_to_field("question3answer", q)
    
    alpha = secrets.randbelow(q)
    a = secrets.randbelow(q)
    alice = Alice(proto, x1=x1, x2=correct_x2, x3=x3, alpha=alpha, a=a, g=g)

    issuer = Issuer()
    cred_sig = issuer.sign_credential(alice.cred, p)

    for label, bob_answer_str in (("correct (send list)", "send list"), 
                                   ("wrong (send Mike)", "send Mike")):
        bob_x2 = answer_to_field(bob_answer_str, q)  # Bob hashes his answer
        b = secrets.randbelow(q)
        bob = Bob(proto, b=b, g=g, x2=bob_x2)

        # --- Bob verifies the credential ---
        assert bob.verify_credential(alice.cred, cred_sig, issuer.pk), "bad cred sig"

        # --- Both derive session key (Eve cannot) ---
        K = alice.compute_session_key(bob.gb)
        K_b = bob.compute_session_key(alice.ga)
        assert K == K_b, "DH key disagreement"
        cipher = Encryption(K, p)

        # --- Message 2 (Bob -> Alice) ---
        message_B = _canon(bob.gb, p) + _canon(alice.ga, p)
        sig_b = bob.sign_transcript(bob.gb, alice.ga)
        blob_B = cipher.encrypt(sig_b)

        sig_b_recovered = cipher.decrypt(blob_B)
        try:
            bob.pk.verify(sig_b_recovered, message_B)
        except InvalidSignature:
            print("Bob authentication FAILED — aborting session")
            break

        # --- Message 3 (Alice -> Bob) ---
        message_A = _canon(alice.ga, p) + _canon(bob.gb, p)
        sig_a = alice.sign_transcript(alice.ga, bob.gb)
        blob_A = cipher.encrypt(sig_a)

        sig_a_recovered = cipher.decrypt(blob_A)
        try:
            alice.pk.verify(sig_a_recovered, message_A)
        except InvalidSignature:
            print("Alice authentication FAILED — aborting session")
            break

        # --- The zero-knowledge proof ---
        w1, w3, w4 = (secrets.randbelow(q) for _ in range(3))
        W = alice.compute_mask_commitment(w1, w3, w4)

        k = hashlib.sha256((_canon(proto.p, p) + _canon(proto.q, p) + 
                           _canon(alice.cred, p) + _canon(W, p) + 
                           _canon(alice.ga, p) + _canon(bob.gb, p))).digest()
        k = int.from_bytes(k, "big") % q
        
        r1, r3, r4 = alice.compute_response(k, w1, w3, w4)

        result = bob.verify_response(alice.cred, k, W, r1, r3, r4)
        print(f"Bob's answer {label}: verification = {result}")

        if result:
            blob_result = cipher.encrypt(_canon(bob_x2, p))
            recovered = int.from_bytes(cipher.decrypt(blob_result), "big")
            print(f"Message from Alice: Correct, Bob! Well done :)")
        else:
            print(f"Message from Alice: The correct answer was {correct_answer_str}, "
                  f"not {bob_answer_str}. Better luck next time :/")