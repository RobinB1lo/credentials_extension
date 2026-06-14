# Extension of Digital Credentials

## What is Diffy-Helman key exchange?

1. Alice and Bob publicly agree to use a modulus p = 23 and base g = 5 
2. Alice chooses a secret integer a = 4, then sends Bob A = g^a mod p, which is A = 5^4 mod 23 = 4 in this case
3. Bob chooses a secret integer b = 3, then sends Alice B = g^a mod p, which is B = 5^3 mod 23 = 10 in this case
4. Alice computes s = B^a mod p, which is s = 10^4 mod 23 = 18
5. Bob computes s = A^a mod p, which is s = 4^10 mod 23 = 18
6. Alice and Bob now share a secret (the number 18)

## What are Pedersen commitments?

Suppoed Alice and Bob would liek to play a coin tossing game through the phone. One person picks "heads" or "tails" and the other tosses the coin and declares who won or lost. To make this game fair there must be a way for the one flipping the coin to bind their choice before the coin is tossed and to verify that the result is actually what they say - basically making sure the person doesn't lie. This is the role of the Pedersen commitment.

Bob chooses primes p and q, and a generator g of the q-order subgroup of Zp*. Bob also chooses a value b ∈ Zq and computes h = gb mod p. He makes p, q, g, and h public, and keeps b secret. Alice commits to a value x ∈ Zq by choosing a random value r ∈ Zq and computing the commitment com = gx hr mod p. She sends com to Bob. Whenever appropriate, Alice can reveal x and r to Bob; he can check whether gx hr mod p is equal to the commitment com that he received earlier from Alice. If so, he is convinced that this is the true value x to which Alice originally committed.

## What is a Blind Signature?

A blind signature is a digital signature with two important differences. First, there are two parties; a user, Alice, who would like her message to be signed; and a signer, Sam, who possesses the private key signing and is therefore the only one that can vompute the signature. Second, Alice does not want Sam to learn anything about the message. To do this succesfully the message is binded by Alice prior to giving it to Sam, this binding allows for anyone to verify the signature against the original unmodified message.

The following is the RSA digital signature algorithm used to acheive a blind singature: Alice has a message m that she wants Sam to sign, but she doesn't want Sam to learn m. She chooses a random number r and computes m' = mr^e mod n. (The value r unconditionally hides the message m). Alice gives m' to Sam. Sam signes the value m' by computing a conventional RSA signature operation: s' = (m')^d mod n. Sam gives s' to Alice. Alice computes s'(r^-1) mod n = (m')^d(r^-1) = (m^d)(r^ed)(r^-1) = (m^d)(r)(r^-1) = m^d mod n = s. Alice this obtains a valid message-signature pair (m, s) that can be verified by anyone using Sam's public key (e, n) in the familiar RSA signature verification operation: "Is s^e mod n = m?". Note, however, that Same has never seen and cannot compute m or s

## What is a zero-knowledge proof of knowledge?

Suppose that Alice would like to convince Bob that she knows. a particular value, but she does not want him to learn anything at all about what the value is. A zero-knowledge proof of knowledge for the original discussion of this topic is a cryptographic protocol or technique that allows Alice to prove her knowledge, but to prove it in "zero-knowledge". As an example, sa y = g^x mod p where p is a prime and g is a generator of the q-order subgroyp of Zp*. Bob knows y, g, q, and p, but is unable to compute discrete logarithms modulo p and do does not know the value x. Alice want to convince Bob that she knows x without revealing anything about x to him. This can be accomplished as follows. Alice chooses a random value r exists in Zq and computes t - g^r mod p. She sends t to Bob. Bob chooses a random value c exists in Zq and computes t = g^r mod p. She sends t to Bob/ Bob chooses a random value c exists in Zq. He sends c to Alice. Alice computes s = cx + r mod q and sends s to Bob. Bob checks to see wether g^s mod p is equal to ty^c mod p. If so, he is convinced that Alice must know x, but he learns nothing whatsoever about x.

## Explanation of the paper form Professor Adams