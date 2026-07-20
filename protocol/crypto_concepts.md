# Description of crypto concepts

## What is a block cipher and stream cipher?

- A block cipher is an encryption algorithm that encrypts bits (or bytes) chunks at a time, for example AES-128 encrypts 128 bytes at a time. Conversly, a stream cipher encrypts the bytes one at a time, for examples ChaCha20 processes and encrypts one byte at a time by combining it with pseudorandom bytes.

## What is confusion and difusion in cryptography?

- Confusion and Diffusion are both necessary elements of a good encryption algorithm. Confusion is what hides the relationship between the encrypted data and the secret key, this is done by using substituion and non-linear transformations to hide the relationship between the encrypted data and the secret key. Diffusion hides any patterns between similar encrypted data, it ensures that even a tiny bit change results in a completedly different output of the encrypted data. Diffusion is attained by using transpositions and permutations.

## What is a symmetric vs asymmetric encryption algorithm?

- A symmetric encryption algorithm means that the same secret key is required to both encrypt and decrypt data, onyl one single key is needed. This makes symmetric encryption very quick and the norm to encrypt large amounts of data, AES is a common example of a symmetric encryption algorithm. Conversly, an asymmetric encryption algorithm has a public key and a private key that are mathematically linked, where the public key is used to encrypt data and the private key is the only way to decrypt that data. RSA is the most common example of an asymmetric encryption algorithm. 

## What is hashing vs encryption?

- Hashing is a one-way function meant to verify data, while encryption is a two way process meant to hide data from anyone who does not have the decryption key

## AES-128

Overview: AES is a symmetric block-cipher encryption algorithm, there are various versions of this algorithm but we will onyl be covering the 128 bit version (AES-128). The version of the algorithm affects the key length and how many rounds are ran. We will go through AES-128 which has 10 rounds of encryption. For decryption we essentially run these operations backwards.

Encryption

Input: Raw unencrypted data, and a 128 bit encryption key

Step 0 (Before any rounds begin): 

    - We will process the raw unencrypted data 128-bits at a time or pad it to be 128 bits when it is not filled, creating a 4x4 state matrix where each entry is a byte (byte = 8 bits x (4 x 4) = 128)

    - XOR the 128-bits of unencrypted data with the original encryption key (round key 0) that was taken as a hyperparameter

    - Generate unique round keys for all 10 rounds. Some round keys are generated from XORing with prior round keys, others have bits who are cycled to the left, and some are ran through the S-box

We will now do the loop with the following steps 10 times

Step 1 - Byte Substitution: In this first step we utilise something called the S-box (substitution-box) which is a non-linear lookup table used to substitute byte values during the encryption process. The S-box acts as a deterministic mapping function, where the first 4 bits of an entry of the state matrix determines the S-box row and the last 4-bits determines the S-box column. This gives an exact lookup to find the associated value in the S-box for our state matrix entry. 

    - The S-box: The S-box was carefully designed by the creators of AES, to create maximum non-linearity wich avoids the dangers of linear cryptanalysis and defeat interpolation attacks. The way the S-box goes about doing this is with math such as Galois Fields and modulo arithmetic. The irreducible polynomial m(x) = x^8 + x^4 + x^3 + x + 1 is used. To find the inverse of an input byte, it is treated as a polynomial, we then find the inverse of that polynomial using euclid's extended algorithm. We then move do a affine transformation on the inverse bytes, where we treat the inverse byte as an 8x1 column vector and multiply it by a fixed 8x8 binary matrix M, and then XOR it with a vector C. The matrix M is made by shifting a carefully selected algebraic polynomial over and over, and the vector C is simply 0x63. 

Step 2 - Shifting rows: In this step the data in each row of our state matrix is scrambeled horizontally, where in the 0th row the bytes are not shifted at all, the 1st row is shifted 1 byte to the left, the 2nd row is shifted 2 bytes to the left, and so on. This helps cause diffusion horizontall within AES.

Step 3 - Mixing columns: This step scrambles the data vertically, treating each column of the state matrix as a 4-term polynomial and multiplies it against a fixed matrix that was carefully selected to cause the most amount of diffusion which gives us our new entries. This carefully selected matrix is a MDS (Maximum Distance Seperable) matrix, which means that it is mathematically perfect at spreading changes. During the matrix multiplication, instead of adding terms to get our new entry, they are XORd against eachother, which allows us to stay in GF(2^8). This causes difusion vertically within AES. 

    - Note that step 3 is skipped on the last run (10th run) of the algorithm to make it less expensive to decrypt

Step 4 - Finally we XOR our state matrix with our round key respectively

Repeat 10 times

Output: A 128-bit blocks of encrypted data (however many are needed to completely encrypt the input)

Decryption

Input: 128-bit block of ciphertext

Step 0 (Before any rounds begin): 

    - We load our 128-bit block of ciphertext into our 4x4 state matrix

    - The 11 keys that were used during encryption are fetched

    - The State matrix is bitwise XORd with round key 10 (this works becauseXOR is its own inverse)

We will now do the loop with the following steps 9 times 

Step 1 - Inverse Shift Rows: We shift the bytes in the 0th row by 0 to the right, we shift the bytes in the 1st row by 1 to the right, we shift the bytes in the 2nd row by 2 to the right, and so on... 

Step 2 - Inverse byte substitution: Every byte in the state matrix is replaced using the inverse S-box lookup table. 

Step 3 - Inverse add round key: We XOR the state matrix with the corresponding round key for that round.

Step 4 - Inverse mix columns: We unscramble the columns vertically. We simply multiply each column by the inverse MDS matrix in GF(2^8)

    - Note that Inverse mix columns is skipped in the last round because in the final step we XOR with round key 0 which gives us our decrypted data back 

We finally remove any padding that was added

Output: Original un-encrypted data 

## SHA-256

Overview: SHA is a set of one way deterministic hash functions, the original function is SHA-1 but we will be covering SHA-256.

Input: Anything that can be converted into bits, for this example we will work with a string of text where each letter is converted into bits using ASCI

Step 0 (Before any structural changes take place): 
  
    - We first convert our inputs to bits using either ASCII or UTF-8

    - We then pad by:

        - Appending a single 1 bit

        - Append 0's until the total length is 64 short of a multiple of 512

        - Append the original message length encoded as an 64-bit big endian integer

The result must always be a multiple of 512, this is because the comrpession function eats blocks of 512 bits at a time

Step 1 - Initialize the hash state: We have eight 32-bit constants, H0 through H7. They are the first 32 bits of the fractional parts of the square roots of the first 8 primes (2, 3, 5, 7, 11, 13, 17, 19). These are the starting values for the hash state.

    - Why do we pick these fixed seemingly arbitrary constants? They need to be pulbic, fixed, and not secretly chosen because this could allow someone to plant a secret backdoor.

Step 2 - Message schedule expansion: For each 512-bit block, you split into 16 pieces of 32 bits each (16 x 32 = 512) where each block is labeled from W0 to W15. We will then be expanding from W16 all the way to W64 using the following formula:

    - Wt = W(t-16) - alpha0(W(t-15)) + W(t-7) + alpha1(W(t-2)) (mod 2^32)

From W0 to W15 they will stay the same, but from W16 to W63 we will be applying this formula. This step introduces lots of confusion and difusion; the confusion is due to the mixing of the 64 rows and the fact that they are not obviously related, the difusion is caused by the scrambling of the message found in each of the rows, meaning a small change would have a big impact on the output. We call this expanding the message schedule because this is what we will be feeding into the compression function.

    - alpha1() an alpha0() are fixed combinations of right-rotations, right-shifts, and XORs of it's input bits

Step 3 - 64 round constants: Seperately from the message schedule, there are 64 constants K0 to K63, which are the first 32 bits of the dractional parts of the cube roots of the first 64 primes. These are again fixed public constants which are a part of the SHA-256 standard.

Step 4 - The comprerssion function: Take the 8 current hash values H0 to H7 and copy them into 8 working variables - a, b, c, d, e, f, g. Run 64 rounds (t = 0 to 63), where each round computes two nonlinear function:

    - T1 = h + sigma1(e) + Ch(e, f, g) + K[t] + W[t] (mod 2^32)
    - T2 = sigma0(a) + Maj(a, b, c) (mod 2^32)

        - Where:
            - simga1(e) = combination of right-rotations of e
            - Ch(e, f, g) = 'choose' function: for each bit position, picks the bit from f or g depending on the corresponding bit of e
            - simga0(a) = combination of right-rotations of a
            - Maj(a, b, c) = 'majority' function: for each bit position, outputs whichever bit value (0 or 1) appears in at least two of a, b, and c

        - Why Ch and Maj? These are both non-linear and hard to invert, analogous to the S-box in AES. 
        - Why the round constants K[t] and W[t]? They ensure every round behaves differently.

We then shift everything down: h <- g, g <- f, f <- e, e <- d + T1, d <- c, c <- b, b <- a, a <- T1 + T2

Step 5 - Feedforward: After all 64 rounds, add the working variables back into the original values.

    - H0 = H0 + a
    - H1 = H1 + a
    ...
    - H7 = H7 + a

        - Why add rather than overwrite? This step means that even if an attack could invert the compression function, they can't cleanly seperate the contribution of the old state from the new one.
    
These updated H0 to H7 becomes the input state for the next 512-bit block. This is what chains the algorithm together. 

Step 6 - Ouput: After the last block is processed, concatenate H0 through H7 (3 x 32 bits) to get your final 256-bit digest.

## Schnorr Signatures

Overview: A Schnorr signature is a digital signature known for its simplicity, among the first whose security is based on the intractability of discrete logarithm problems. It provides a straightforward way to prove ownership of a private key without revealing it, and is the foundation for many modern signature schemes including Ed25519.

Input: A message M to be signed, and agreed-upon public parameters

Step 0 (Before any cryptographic operations begin):

    - All users agree on a group G of prime order q with generator g in which the discrete log problem is assumed to be hard. Typically a Schnorr group is used (large prime order subgroup of the multiplicative group mod p for some large prime p). To create such a group, we must generate p and q such that p = qr + 1 with both p and q being prime.

    - Users also agree on a cryptographic hash function H (e.g., SHA-256 or SHA-512) that will be used throughout the protocol.

    - Why these parameters? The security relies entirely on the hardness of the discrete logarithm problem in the chosen group. The hash function must be cryptographically secure to prevent collisions and pre-image attacks.

Step 1 - Key generation: Each user chooses a private signing key x uniformly at random from the allowed set {1, ..., q-1}. The corresponding public verification key is computed as y = g^(-x) mod p (or equivalently y = g^(q-x) mod p). This means the discrete logarithm of y to base g is -x, so finding x from y is computationally infeasible.

    - Why do we use g^(-x) instead of g^x? This is a design choice from the original Schnorr scheme that makes the verification equation slightly cleaner. In practice, some implementations use y = g^x instead; the mathematics work identically with appropriate sign adjustments.

Step 2 - Signing our message M: The signer chooses a random nonce k from the allowed set {1, ..., q-1} and computes the commitment r = g^k mod p. They then compute the challenge e = H(r || M) where || denotes concatenation. Finally, they compute the response s = (k + x*e) mod q. The signature is the pair (s, e).

    - Why do we need a random nonce k? The nonce ensures that signing the same message twice produces different signatures (unless k is reused), preventing attackers from learning the private key. It also ensures the signature is probabilistic rather than deterministic.

    - Why do we use H(r || M) rather than just H(M)? By including r in the hash, we bind the commitment to the message, preventing attackers from using a different r that would still satisfy the verification equation.

Step 3 - Sending the signature: The signer transmits the signature (s, e) along with the message M to the verifier. The signature size is typically 2 * log2(q) bits (e.g., if q is 256 bits, the signature is 512 bits or 64 bytes).

Step 4 - Verification: The verifier reconstructs r_v = g^s * y^e mod p, then computes e_v = H(r_v || M). If e_v equals the received e, the signature is accepted as valid; otherwise it is rejected.

    - Why does this work? Substituting y = g^(-x): r_v = g^s * (g^(-x))^e = g^(s - x*e) = g^(k + x*e - x*e) = g^k = r. Therefore r_v equals the original r, so e_v will equal e. This proves that the signer knew x without revealing it.

    - Why is this secure? An attacker who doesn't know x cannot produce a valid (s, e) pair because they would need to solve the discrete logarithm problem to find a value that satisfies both equations simultaneously.

Critical Security Consideration - Nonce reuse: Reusing a nonce value k on two different messages M and M' will allow an observer to recover the private key. Given two signatures (s, e) and (s', e') with the same k but different messages: s' - s = (k + x*e') - (k + x*e) = x(e' - e) mod q. Since e' ≠ e (different messages produce different hashes), x can be isolated as x = (s' - s) * (e' - e)^(-1) mod q. In fact, even slight bias or leakage of k can reveal the private key, which is why deterministic variants like Ed25519 were developed.

Output: A (s, e) signature pair that can be verified by anyone with the public key

## Edwards 25519 (Ed25519)

Overview: Edwards 25519 is a digital signature scheme that is part of the Edwards Digital Signature Algorithm (EdDSA) family. It uses a variant of a Schnorr signature based on a twisted Edwards curve, designed to be faster than existing signature schemes without sacrificing security. Ed25519 offers very fast signature generation and verification with short, fixed-size signatures (64 bytes) and keys (32 bytes). It provides 128 bits of security (meaning it would take 2^128 attempts of classical methods to break it), and is deterministic - unlike the original Schnorr scheme.

    - Why deterministic? Ed25519 derives the nonce deterministically from the private key and message, eliminating the catastrophic risk of nonce reuse that plagues probabilistic Schnorr signatures. This is a major security improvement.

    - What is a twisted Edwards curve? The curve used is -x^2 + y^2 = 1 + d*x^2*y^2 over a finite field, which has special properties that enable fast and constant-time implementations. The specific curve is birationally equivalent to Curve25519 (Montgomery form).

Input: A message M to be signed, and a private key

Step 0 (Before any cryptographic operations begin):

    - The system parameters are fixed and standardized: the twisted Edwards curve Ed25519 with base point G, prime order L (approximately 2^252 + some constant), and SHA-512 as the hash function. These parameters are not chosen by users but are part of the Ed25519 standard.

    - Why are these parameters fixed? Unlike the original Schnorr scheme where parameters must be agreed upon, Ed25519 uses standardized parameters to ensure interoperability and prevent parameter-choice attacks. The curve was carefully selected for security and performance.

Step 1 - Key generation: We first generate a random 32-byte seed (the private key). We hash this seed using SHA-512 to get 64 bytes. The first 32 bytes are "clamped": bits 0, 1, and 2 are cleared (ensuring the scalar is a multiple of 8), bit 255 is cleared, and bit 254 is set. These clamped bytes are interpreted as a little-endian integer (least significant byte first), which becomes our private scalar 'a'. The second 32 bytes of the hash are stored as a prefix for deterministic nonce derivation. We then multiply the base point G on the curve by the scalar 'a' to get the public point A = a*G. We encode this point as 32 bytes (the y-coordinate plus a sign bit for the x-coordinate). This 32-byte encoding is our public key.

    - Why do we clamp the private key? Clearing bits 0, 1, and 2 ensures the scalar is a multiple of 8, which protects against small-subgroup attacks. Setting bit 254 and clearing bit 255 ensures the scalar is in the correct range and prevents timing attacks by ensuring the multiplication always takes the same number of operations. The clamping is a form of "key sanitization."

    - Why do we use a 32-byte seed rather than directly using a scalar? Hashing the seed and extracting the scalar provides a way to generate a secure private key from any random seed, and the second half of the hash is reused for nonce derivation, creating a unified key structure.

Step 2 - Signing our message M: We first repeat the key derivation: hash the private key with SHA-512 to get 64 bytes, extract the first 32 bytes and clamp them to get scalar 'a' (or reuse the previously computed value). Then we hash the concatenation of the prefix (the second 32 bytes from the key hash) and the message M with SHA-512. We interpret this 64-byte hash as a little-endian integer and reduce it modulo L (the curve order) to get scalar 'r'. This 'r' is our deterministic nonce. We multiply the base point G by r to get point R = r*G on the curve. We encode R into 32 bytes (y-coordinate + sign bit) to get R_encoded. We then hash the concatenation of R_encoded, the public key A, and our message M with SHA-512. We interpret this 64-byte hash as a little-endian integer and reduce it modulo L to get scalar 'h'. We then compute S = (r + h * a) mod L, which is the response binding the nonce r, the challenge h, and the private key together. Finally, we encode S as a 32-byte little-endian integer and concatenate it with R_encoded to produce our final 64-byte signature.

    - Why is nonce derivation deterministic? By deriving r = H(prefix || M) instead of choosing it randomly, we ensure that signing the same message twice with the same private key produces the same signature. This eliminates the nonce reuse vulnerability entirely because r is a deterministic function of the message and private key.

    - Why do we include the public key in the challenge hash? This binds the signature to the specific public key, preventing a signature from being valid for a different public key (a form of key substitution attack). It also creates a "domain separation" effect.

    - Why do we encode R and S separately? The signature format is designed to be simple and compact: 32 bytes for R_encoded (the point) and 32 bytes for S (the scalar), making verification straightforward.

Step 3 - Verification: The verifier decodes R from the first 32 bytes of the signature as a point on the curve (validating that it's a valid curve point). They decode S from the last 32 bytes as an integer scalar. They hash the encoded R (as received), the public key A, and the message M with SHA-512. This hash is interpreted as a little-endian integer and reduced modulo L to get scalar 'h'. The verifier then checks the curve equation [S]*G = R + [h]*A, where [n]*P means "multiply point P by scalar n on the elliptic curve." If this equation holds, the signature is valid; if not, it is forged.

    - Why does this work? Substituting A = a*G: R + [h]*A = r*G + h*a*G = (r + h*a)*G = S*G. Therefore, the equation holds if and only if the signer knew both a (the private key) and r (the nonce), and the nonce was bound to the message through the challenge h.

    - Why is verification so fast? Ed25519 uses the efficient Edwards curve arithmetic and the verification equation requires only two scalar multiplications (S*G and h*A) which can be computed efficiently. Additionally, the curve was chosen to allow for fast, constant-time implementations without side-channel leaks.

Critical Security Consideration - Batch verification: For applications that verify many signatures simultaneously (e.g., blockchain nodes), multiple Ed25519 signatures can be verified together in a batch, which is significantly faster than verifying them individually. This is possible because the verification equations can be combined and checked with fewer scalar multiplications overall.

Output: A 64-byte signature (R_encoded || S_encoded) that can be verified by anyone with the public key and message

## What is post-quantum cryptography?

- Post quntum cryptography is the design and analysis of cryptographic algorithms which are deemed quantum resistant. Most of these algorithms involve lattices, because they have properties which make them more resistant to quantum attacks.

    - What are quantum computers: 

## Dilithium (CRYSTALS-Dilithium)

Overview: Dilithium is a part of the CRYSTALS (Cryptographic Suite for Algebraic Lattices) family of cryptographic algorithms designed to withstand attacks from both classical and quantum computers. Dilithium specifically is a lattice-based signature algorithm, which is what allows it to withstand quantum threats. It is one of the finalists in the NIST post-quantum cryptography standardization project and is designed to replace classical signature schemes like ECDSA and Ed25519 that are vulnerable to quantum attacks.

    - Why lattice-based cryptography? Lattice problems like the Module Learning with Errors (MLWE) problem are believed to be hard even for quantum computers. Unlike factoring or discrete logarithms (which Shor's algorithm can solve efficiently), lattice problems have no known quantum algorithms that offer significant speedup.

    - Why is Dilithium needed? Classical signature schemes like Ed25519 rely on elliptic curve discrete logarithms, which quantum computers can break using Shor's algorithm in polynomial time. Dilithium provides a drop-in replacement that maintains security in a post-quantum world.

Input: A message M to be signed, and system parameters

Step 0 (Before any cryptographic operations begin):

    - A public matrix of polynomials A is generated from a public seed. This matrix is known to everyone and is part of the system parameters. Each entry of A is a polynomial with coefficients modulo q, where q is a prime chosen for the specific security level.

    - The system also defines parameters: the dimension k (number of polynomials in vectors), the modulus q, the polynomial degree n (typically 256), and the rejection sampling bounds. These parameters are standardized and depend on the desired security level (Dilithium-2, -3, or -5).

    - Why is A generated from a seed? This allows the matrix to be reproduced by anyone from a compact seed rather than transmitting the entire matrix, which would be very large. The seed is part of the public parameters.

Step 1 - Key generation: The signer randomly samples two small secret polynomial vectors s1 and s2 with coefficients chosen from a centered binomial distribution (or uniform distribution over a small range). Using these, the signer computes the public key component t = A * s1 + s2. In standard Dilithium, t is compressed into a high-order part (t1) and a low-order part (t0) to keep the public key small. Specifically, t = t1 * 2^d + t0, where d determines the compression level. The final public key is (A, t1), and the private key contains (s1, s2, t0).

    - Why do we use small secret polynomials? The security of Dilithium relies on the difficulty of recovering s1 and s2 from t = A*s1 + s2. If s1 and s2 were large, the problem would be easier to solve. Small coefficients ensure that the LWE problem remains hard while allowing efficient operations.

    - Why do we compress t to t1 and t0? Compression reduces the size of the public key significantly (from kilobytes to hundreds of bytes), making it practical for real-world applications. The low-order t0 is kept in the private key to allow for precise verification later.

    - Why do we use centered binomial distribution for randomness? This distribution produces small integer coefficients centered around zero, which is optimal for lattice-based cryptography. It provides the right balance between security (small enough to make the problem hard) and efficiency (small enough to keep arithmetic fast).

Step 2 - Signing our message M: To sign a message securely, Dilithium utilizes a randomized commitment process. The signer picks a random, short secret vector y with small coefficients and computes the commitment w = A * y. The signer extracts the high-order bits of w to get w1 and computes a challenge c by hashing w1 together with the message M. This challenge is encoded as a short polynomial with a fixed Hamming weight (number of non-zero coefficients) to make it efficient to work with.

    - Why do we need a commitment? Just like in Schnorr signatures, the commitment w = A*y hides the random nonce y. The challenge c is then bound to both the commitment and the message, preventing forgery attacks. This is the standard Fiat-Shamir transform applied to lattice-based identification.

    - Why does c have a fixed Hamming weight? By ensuring c has exactly τ non-zero coefficients (each being ±1), multiplication by c becomes very fast (just additions and subtractions) rather than full polynomial multiplication. This is a key optimization in Dilithium.

Step 3 - Response and rejection sampling: The signer computes z = y + c * s1. A clever "rejection sampling" step is applied here: if the coefficients of z reveal any information about the secrets s1 (specifically, if z is too large), the signature is aborted and the process starts over with a new y. The rejection condition is typically checking if any coefficient of z exceeds a certain bound γ1 - β, where β is related to the size of s1. If z passes, it is safe to reveal.

    - Why is rejection sampling necessary? If we simply output z = y + c*s1, the distribution of z would depend on s1 (since the distribution of y is uniform over a bounded range, but adding c*s1 shifts it). By rejecting samples where z is too large, the distribution of z becomes independent of s1, preserving zero-knowledge. This is the lattice analogue of the "masking" in Schnorr signatures.

    - Why do we abort rather than fix the output? Aborting and retrying ensures that the statistical distribution of z is exactly the same regardless of which private key was used. An attacker seeing many signatures cannot distinguish between different keys, which is essential for security.

Step 4 - Hint bits: Because the public key was compressed (t1 and t0), a "hint" vector (h) is computed to help the verifier correctly calculate the high bits of w. Specifically, the verifier needs to reconstruct w1 from z and the compressed public key, but due to compression, the reconstruction may be off by a small amount. The hint h encodes this correction information, telling the verifier which coefficients need to be adjusted.

    - Why do we need hints at all? Without hints, the verifier would need the full uncompressed t to verify signatures, which would make public keys much larger. The hints allow the public key to be compressed while still enabling correct verification.

    - What information is in the hint? Each hint is typically a single bit per coefficient indicating whether the high-bit reconstruction should be rounded up or down. This is enough to correct the small errors introduced by compression.

Step 5 - Signature output: The final signature consists of the tuple (z, c, h), where z is the masked response, c is the challenge, and h is the hint vector. The signature size for Dilithium depends on the security level but is typically between 2-5 kilobytes, significantly larger than classical signatures but necessary for post-quantum security.

    - Why is the signature so large? Lattice-based cryptography inherently deals with large mathematical objects (vectors of polynomials). The signature contains the entire response vector z and hint vector h, which are large compared to the 64 bytes of an Ed25519 signature. This is the price of post-quantum security.

Step 6 - Verification: Anyone with the public key (A, t1) can verify that a valid signer created the signature. The verifier first reconstructs the commitment using the challenge c, the response z, and the public key components. Specifically, they compute w' = A*z - c*t1*2^d, which approximates A*y (the original commitment). The hint h is used to adjust for the compression of t1, giving the correct high-order bits w1'. The verifier then recomputes the challenge by hashing w1' with the original message M to derive c'. If the recomputed challenge c' exactly matches the challenge c provided in the signature, the signature is accepted as valid.

    - Why does verification work? Substituting z = y + c*s1 and t = A*s1 + s2: w' = A*(y + c*s1) - c*t1*2^d = A*y + c*A*s1 - c*(t - t0) = A*y + c*t0. Since t0 is small, w' is close to A*y. The hint h corrects the small error from t0 and compression, allowing the verifier to recover w1 exactly. If the challenge matches, the signature is valid.

    - Why is verification more complex than Ed25519? Dilithium requires multiple polynomial operations (matrix-vector multiplication, polynomial addition, and hint processing) whereas Ed25519 only needs scalar multiplication on an elliptic curve. This is due to the inherent complexity of lattice-based arithmetic.

Critical Security Consideration - Side-channel resistance: Dilithium is designed to be implemented in constant time to prevent timing attacks. Operations like polynomial multiplication and rejection sampling must be performed without branching based on secret data. This is particularly important because the rejection sampling in signing could leak information about s1 if not implemented carefully.

    - What is a timing-attack:

Output: A (z, c, h) signature that can be verified by anyone with the public key and message

## Kyber (CRYSTALS-Kyber)

Overview: Kyber is also a part of the CRYSTALS (Cryptographic Suite for Algebraic Lattices) family of cryptographic algorithms. It is a quantum-resistant Key Encapsulation Mechanism (KEM), designed to replace classical key exchange protocols like Diffie-Hellman which are not quantum resistant. Kyber was selected by NIST as the standard for post-quantum key encapsulation and is designed to be efficient, secure, and practical for real-world deployment.

    - Why a KEM instead of direct key exchange? A KEM allows two parties to agree on a shared secret without the interactive exchange required by protocols like Diffie-Hellman. The sender encapsulates a key and sends it to the receiver, who decapsulates it. This fits naturally into existing protocols like TLS.
    - Is this a one-way send?

    - Why is Kyber needed? Diffie-Hellman relies on the discrete logarithm problem, which Shor's algorithm can solve in polynomial time. Kyber provides a drop-in replacement that maintains security in a post-quantum world while offering competitive performance.

Input: Alice's public key (to Bob) and a message m (to Alice)

Step 0 (Before any cryptographic operations begin):

    - The system defines a matrix A of size k x k where each element is a polynomial with coefficients in a finite field Zq (where q is a prime). Matrix A is generated from a public seed and is known to everyone. The parameters k and q determine the security level: Kyber-512 (k=2), Kyber-768 (k=3), or Kyber-1024 (k=4). Each polynomial has degree n (typically 256).

    - The system also defines a centered binomial distribution for sampling small coefficients, and a compression/decompression scheme for reducing ciphertext and key sizes.

    - Why is A generated from a seed? Similar to Dilithium, this allows A to be reproduced from a compact seed rather than transmitted, saving significant bandwidth. The seed is part of the public parameters.

Step 1 - Key generation: Alice randomly samples a secret vector s and a small error vector e, where the coefficients of these polynomials are tiny integers drawn from a centered binomial distribution. Alice then computes her public vector t using the matrix equation: t = A * s + e. She publishes her public key (A, t) to Bob while keeping her private key s strictly hidden.

    - Why do we need an error vector e? The security of Kyber relies on the Module Learning with Errors (MLWE) problem: given A and t = A*s + e, it is computationally infeasible to recover s. The error e is what makes the problem hard; without it, s could be recovered by solving a system of linear equations.

    - Why use a centered binomial distribution for s and e? This distribution produces small coefficients centered around zero, which is optimal for MLWE. It provides the right balance between security (small enough to make the problem hard) and efficiency (small enough to keep arithmetic fast). The distribution is also easy to sample deterministically from a seed.

Step 2 - Encapsulation: Bob receives Alice's public key (A, t). He wants to generate a random 256-bit symmetric key K, encapsulate it, and send the ciphertext back to Alice. Bob first generates a completely random 32-byte (256-bit) message m. This message m will eventually be hashed to become the final shared cryptographic key K. Bob then acts like a new sender: he generates his own temporary secret vector r and two small error vectors, e1 (a vector of polynomials) and e2 (a single polynomial). He then encrypts the lattice path by computing: u = A^T * r + e1 (where A^T is the transpose of A). Bob converts his 256-bit message m into a polynomial where bits of 0 and 1 are scaled up into large coefficients (typically 0 maps to 0 and 1 maps to q/2). He then hides this message using Alice's public key t and his noise: v = t^T * r + e2 + Encode(m). Bob sends the ciphertext (u, v) to Alice.

    - Why does Bob create his own r and errors? Bob is effectively creating a new MLWE instance but in the "opposite direction." This is the essence of the LWE-based key exchange: both parties contribute randomness and noise, and the shared secret emerges from the algebraic structure.

    - Why is m random rather than directly using K? Bob generates a random m and then hashes it to produce K. This allows the sender to contribute entropy to the shared secret, ensuring that even if Alice's private key is compromised, the session key remains fresh and independent. It also enables the KEM to be "secure" without requiring additional randomness for the session key.

    - Why is Encode(m) scaled to q/2? The message is encoded as either 0 or q/2 so that when Alice decrypts, she can distinguish between the two values based on whether the coefficient is close to 0 or q/2. The error terms are small compared to q/2, making decoding possible.

Step 3 - Decapsulation: Alice receives the ciphertext (u, v) from Bob. She uses her private key s to strip away the mathematical noise and recover Bob's message m. Alice computes a temporary polynomial d by multiplying Bob's ciphertext u by her private key s and subtracting it from Bob's ciphertext v: d = v - s^T * u.

    - Why does the noise cancel out? If we substitute Bob's equations into Alice's calculation, the underlying algebra is:

        d = (t^T * r + e2 + Encode(m)) - s^T * (A^T * r + e1)
        d = (s^T * A^T * r + e^T * r + e2 + Encode(m)) - (s^T * A^T * r + s^T * e1)
        d = Encode(m) + (e^T * r + e2 - s^T * e1)

    - The remaining term (e^T * r + e2 - s^T * e1) is just a collection of multiplied error terms. Because e, r, e2, and s all consist of very small integers, this total combined noise is quite small. Alice runs a decoding algorithm that looks at the coefficients of d: if a coefficient is close to 0 (within a threshold), it decodes to a 0 bit; if it is close to q/2, it decodes to a 1 bit. This successfully recovers Bob's original message m.

    - Why does this work despite the noise? The noise terms are small (typically bounded by a few hundred), while q/2 is large (typically around 2000). The threshold for decoding is chosen so that even the maximum possible noise is less than q/4, ensuring correct decoding with overwhelming probability.

Step 4 - Shared secret derivation: Alice hashes the recovered message m using the exact same hash function Bob used (typically SHA-3 or SHAKE-256). She now holds the identical cryptographic key K. Bob also hashes his original m to get K. They can now safely encrypt their session traffic using standard symmetric encryption like AES.

    - Why hash m rather than using d directly? Hashing provides domain separation and ensures that the final key is uniformly random even if m has some structure. It also binds the key to the specific session, preventing key reuse attacks.

    - Why do we call this a Key Encapsulation Mechanism? Unlike a key exchange where both parties contribute to the shared secret, in a KEM the sender (Bob) chooses the shared secret K and encapsulates it for the receiver (Alice). The receiver then decapsulates it to obtain the same K. This fits the asymmetric encryption model.

Step 5 - Verification (implicit): Unlike signature schemes, Kyber does not have an explicit verification step for the shared key. Instead, the security guarantee is that if Alice and Bob follow the protocol, they will derive the same K with overwhelming probability. If an attacker tries to decrypt the ciphertext without knowing s, they would need to solve the MLWE problem, which is believed to be computationally infeasible.

    - What happens if decryption fails? The probability of decryption failure is extremely small (less than 2^-128) due to careful parameter selection. If it does fail, the protocols using Kyber (like TLS) would typically fall back to resending or aborting the connection.

Critical Security Consideration - Chosen ciphertext security: Kyber is designed to be IND-CCA2 secure (secure against adaptive chosen-ciphertext attacks). This means that even if an attacker can submit arbitrary ciphertexts to Alice and observe her decapsulation behavior, they cannot learn anything about the private key or break the confidentiality of the shared secret. This is achieved through the use of the Fujisaki-Okamoto transformation, which adds additional hashing and re-encapsulation checks to prevent malleability attacks.

    - Why is this important? Without IND-CCA2 security, an attacker could modify Bob's ciphertext in subtle ways and learn information about Alice's private key by observing whether decryption succeeds or fails. This is a common attack vector in practice, which is why KEMs must be designed with this in mind.

Output: A shared 256-bit symmetric key K that can be used for encryption, and a ciphertext (u, v) for transmission

## CAST - Should I?

Overview:
