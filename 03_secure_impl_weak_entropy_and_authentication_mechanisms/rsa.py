import sys
import Crypto.Util.number
from Crypto.Util.number import getPrime, GCD, inverse

def encrypt(m, e, N):
	return pow(m, e, N)

def decrypt_branch_free(c, d, N):
    """Branch-free right-to-left exponentiation using pow() selector.
    Constant-time: always same # of iterations and operations regardless of key bits."""
    r = 1
    x = c % N
    for i in range(d.bit_length() - 1, -1, -1): # We need to reverse the order of bits to match right-to-left version, but still do same # of iterations
        r = (r * r) % N
        bit = (d >> i) & 1
        # x^0 = 1, x^1 = x -- always same # of operations either way
        r = (r * pow(x, bit, N)) % N
    return r

def decrypt_branch_free_montgomery(c, d, N):
    """Montgomery Ladder: always does same # of operations"""
    r0, r1 = 1, c % N
    for i in range(d.bit_length() - 1, -1, -1):
        bit = (d >> i) & 1
        # r0 = r0^2 * (r1/r0)^bit, r1 = r1^2 * (r0/r1)^(1-bit)
        r0, r1 = (r0 * r0 * pow(r1 * inverse(r0, N), bit, N)) % N, (r1 * r1 * pow(r0 * inverse(r1, N), 1 - bit, N)) % N
    return r0

# Right-to-left version
def decrypt(c, d, N): # Original implementation 
    # contains information leaked through timing variations based on value of d (key bits)
    r = 1
    x = c % N
    while d > 0: # Timing varies based on value of d!
        if d & 1:
            r = (r * x) % N
        x = (x * x) % N
        d >>= 1 # Loop count depends on d
    return r

# Left-to-right version
def decrypt_ltor(c, d, N):
    r = 1
    for i in range(d.bit_length() - 1, -1, -1):
        r = (r * r) % N
        if (d >> i) & 1:
            r = (r * c) % N
    return r

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
        # e needs to be invertible modulo phi(N)
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

    m = int.from_bytes(message.encode("utf-8"), "big") % N
    enc = encrypt(m, e, N)

    #dec = decrypt(enc, d, N)
    #dec = decrypt_branch_free(enc, d, N)
    dec = decrypt_branch_free_montgomery(enc, d, N)

    plain = dec.to_bytes((N.bit_length() + 7) // 8, 'big')
    print()
    print(f"RSA ciphertext = {enc}") # Showing that encryption works correctly, 
        # and that ciphertext is different each time due to different primes
    print(f"RSA plaintext = {plain.decode("utf-8")}") # Showing that also decryption works correctly

    assert dec == m
    assert decrypt(enc, d, N) == decrypt_ltor(enc, d, N)

if __name__ == '__main__':
    if (len(sys.argv) < 3):
        print(f'usage: {sys.argv[0]} <bits> <message>', file=sys.stderr)
        exit(1)
    main(int(sys.argv[1]), sys.argv[2])
