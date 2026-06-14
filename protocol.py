''' Questions: 
    - How is k defined?
    - How are the generators g1, g2, g3, h0 chosen? and by whom?
    - How is the session key K derived from gᵃᵇ, and what is E_K?
'''

''' Scenario: Alice holds the answer key commited inside her credential. Bob is a student who wants to check wether his answer to question 2 is correct or not without Alice having
to reveal the correct answer and without exposing Bob's answer if it's wrong. He learns exactly one bit of information; wether he is right or wrong.  
'''
from typing import List
import hashlib
import secrets

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

def _subgroup_generator(p: int, q: int) -> int:
    """An element of order q: take any h to the power (p-1)/q; retry if it lands on 1."""
    cofactor = (p - 1) // q
    while True:
        h = secrets.randbelow(p - 3) + 2
        g = pow(h, cofactor, p)
        if g != 1:
            return g


def generate_parameters(q_bits: int = 160):
    """Returns (p, q, g, g1, g2, g3, h0). Demo-sized — use ~256-bit q / ~3072-bit p for real use."""
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
    """Canonical fixed-width serialization — both signer and verifier MUST match."""
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

def derive_challenge(proto: Protocol, cred: int, W: int, ga: int, gb: int) -> int:
    """Non-interactive Fiat-Shamir challenge over the PUBLIC transcript.
    Alice and Bob both compute the same k. (Interactive alternative: Bob picks a
    random k and sends it as a message.) Never include any secret here."""
    h = hashlib.sha256()
    for v in (proto.p, proto.q, cred, W, ga, gb):
        h.update(_canon(v, proto.p))
    k = int.from_bytes(h.digest(), "big") % proto.q
    return k or 1 

class Issuer:
    def __init__(self) -> None:
        if not _HAVE_CRYPTO:
            raise RuntimeError("pip install cryptography to use signatures")
        self.sk = Ed25519PrivateKey.generate()
        self.pk = self.sk.public_key()

    def sign_credential(self, cred: int, p: int) -> bytes:
        return self.sk.sign(_canon(cred, p))


class Alice:
    def __init__(self, protocol: Protocol, x1: int, x2: int, x3: int,
                 alpha: int, a: int, g: int) -> None:
        self.protocol = protocol
        self.x1 = x1          # correct answer to Q1
        self.x2 = x2          # correct answer to Q2 (tested, never revealed)
        self.x3 = x3          # correct answer to Q3
        self.alpha = alpha    # blinding factor
        self.cred = self.compute_credential(x1, x2, x3, alpha)
        self.a = a
        self.ga = pow(g, self.a, protocol.p)   # FIX: was missing mod p
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
    
if __name__ == "__main__":
    p, q, g, g1, g2, g3, h0 = generate_parameters()
    proto = Protocol(p, q, g1, g2, g3, h0)
    print(proto.check_generators())

    correct_x2 = 42
    alpha = secrets.randbelow(q)
    a = secrets.randbelow(q)
    alice = Alice(proto, x1=7, x2=correct_x2, x3=99, alpha=alpha, a=a, g=g)

    if _HAVE_CRYPTO:
        issuer = Issuer()
        cred_sig = issuer.sign_credential(alice.cred, p)

    for label, bob_answer in (("correct (42)", 42), ("wrong (43)", 43)):
        b = secrets.randbelow(q)
        bob = Bob(proto, b=b, g=g, x2=bob_answer)

        if _HAVE_CRYPTO:
            assert bob.verify_credential(alice.cred, cred_sig, issuer.pk), "bad cred sig"

        K_a = alice.compute_session_key(bob.gb)
        K_b = bob.compute_session_key(alice.ga)
        assert K_a == K_b, "DH key disagreement"

        w1, w3, w4 = (secrets.randbelow(q) for _ in range(3))
        W = alice.compute_mask_commitment(w1, w3, w4)
        k = derive_challenge(proto, alice.cred, W, alice.ga, bob.gb)
        r1, r3, r4 = alice.compute_response(k, w1, w3, w4)

        result = bob.verify_response(alice.cred, k, W, r1, r3, r4)
        print(f"Bob's answer {label}: verification = {result}")