import secrets

def modpow(base, exp, mod):
    return pow(base, exp, mod)

def dh_exchange(p, g):
    a = secrets.randbelow(p - 2) + 1 # private to Alice
    b = secrets.randbelow(p - 2) + 1 # private to Bob

    A = modpow(g, a, p) # public — Alice sends
    B = modpow(g, b, p) # public — Bob sends

    s_alice = modpow(B, a, p) # Alice's shared secret
    s_bob   = modpow(A, b, p) # Bob's shared secret

    assert s_alice == s_bob
    return s_alice

if __name__ == "__main__":
    print(dh_exchange(p=23, g=5))