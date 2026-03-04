import sys
import Crypto.Util.number
from Crypto.Util.number import getPrime, GCD, inverse

''' This exercise is the exact implementation of slide 44/60 of week 2's lecture
"Crash course on Cryptography"
It implements RSA key generation, encryption and decryption.

Remember that textbook RSA is insecure and serves only for illustration, 
in practice use a standardized version instead.

RSA is defined over integers modulo N; 
encrypting “bigger” numbers just collapses them to the same residue.

Practical RSA encrypts arbitrary data by encoding it into an integer in [0,N−1]
(padding/encoding schemes handle this).

It is important to remember that in practice, RSA should not be used without proper padding
schemes such as OAEP for encryption and PSS for signatures to ensure security against various attacks.'''

def main(bits, message):

    # key generation
    while True:
        # sample two different primes
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        if p == q:
            continue
        N = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
        ''' e needs to be co-prime to phi(N) and typically is chosen to be 65537, 
        which is a common choice for the public exponent in RSA. It is a prime number 
        and has certain properties that make it efficient for encryption and decryption operations.
        e needs to be invertible modulo phi(N) '''
        if GCD(e, phi) > 1:
            continue
        d = inverse(e,phi)

        print(f"Random Prime p = {p}")
        print(f"Random Prime q = {q}")
        print()
        print(f"Modulus N = {N}")
        print(f"Public exponent e = {e}")
        print(f"Private exponent d = {d}")
        break

    # encryption

    # m € [0, N-1] (Z/NZ)
    # compute c = m^e mod N

    m = message % N
    enc = pow(m, e, N)
    dec = pow(enc, d, N)
    print()
    print(f"RSA ciphertext c = m ^ e mod N = {enc}")
    print(f"RSA plaintext c ^ d mod N = {dec}")
    assert dec == m


if __name__ == '__main__':
    if (len(sys.argv) < 3):
        print(f'usage: {sys.argv[0]} <bits> <message>', file=sys.stderr)
        exit(1)
    main(int(sys.argv[1]), int(sys.argv[2]))
