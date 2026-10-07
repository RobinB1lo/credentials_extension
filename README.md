# Privacy-Preserving Zero-Knowledge Credential Protocol

A hybrid cryptographic protocol combining classical zero-knowledge proofs with post-quantum key exchange and signatures for privacy-preserving credential verification.

## Overview

This protocol enables two parties (Alice and Bob) to establish a secure, authenticated session where Alice can prove knowledge of hidden credential attributes to Bob without revealing the attributes themselves. The protocol combines:

- **Classical Layer:** Schnorr-style zero-knowledge proofs over Pedersen commitments for privacy-preserving equality testing
- **Post-Quantum Layer:** Kyber768 (lattice-based KEM) for key exchange and Dilithium3 (lattice-based signatures) for mutual authentication
- **Symmetric Layer:** AES-256 with HKDF-derived keys for session encryption

## Key Features

- **Privacy-Preserving:** Hidden attributes (x1, x2, x3) remain concealed during proof; only correctness is verified
- **Hybrid Security:** Combines proven discrete-log ZKPs with NIST post-quantum standards
- **Transcript Binding:** Dilithium signatures tie authentication to the exact Kyber public key and ciphertext, preventing replay/substitution attacks
- **Interactive Verification:** Bob confirms Alice's knowledge without access to underlying secrets

## Installation

**Requirements:**
- Python 3.10+
- `cryptography` — symmetric encryption, HKDF, padding
- `liboqs-python` — Dilithium3, Kyber768

## Usage

```bash
python3 -m venv .crypto_env
source .crypto_env/bin/activate
cd protocol
pip install -r requirements.txt
python protocol.py
```

## Security Notes

## License
