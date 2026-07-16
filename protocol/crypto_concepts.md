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

## Edwards 25519

Overview: 

## Dilithium 

Overview:

## Crystal-Kyber

Overview:

## CAST 

Overview:
