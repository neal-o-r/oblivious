"""
Hand made version of RSA. For didactic purposes only.
"""
import random as rd
import math
from typing import Tuple


def miller_rabin(n: int, tol: int = 128) -> bool:
    """
    Miller-Rabin, primality test
    https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test

    test if n is definitely composite, or probably prime
    with certainty p <= 1 / 2**tol
    """

    # deal with simple cases
    if n in (2, 3):
        return True
    if (n == 1) or (n % 2 == 0):
        return False

    # find r & d s.t. n = 2**r * d + 1
    def get_dr(d, r):
        if d % 2:
            return d, r
        return get_dr(d // 2, r + 1)

    def test(n, d, r):
        a = rd.randint(2, n - 2)
        x = pow(a, d, n)

        for _ in range(r):
            if x in (1, n - 1):
                return True

            x = (x * x) % n

        return False

    d, r = get_dr(n - 1, 0)
    k = tol // 2 + 1
    # if any of the tests returned False, then it is composite
    # otherwise it's possible prime
    return all(test(n, d, r) for _ in range(k))


def find_prime(bits: int) -> int:
    """
    return a randomly generated prime of a given number of bits
    """
    lo = 2**bits
    hi = 2 ** (bits + 1)

    p = rd.randint(lo, hi)
    while not miller_rabin(p):
        p = rd.randint(lo, hi)

    return p


# in RSA the public key is a tuple of a power and a mod
PubKeys = Tuple[int, int]


class RSA:
    def __init__(self, psize: int):
        # how many bits should our primes have
        self.psize = psize
        self.p = find_prime(psize)
        self.q = find_prime(psize)

        self.n = self.p * self.q

        self.keysize = self.n.bit_length()

        self.lam_n = self._carmichael(self.p, self.q)
        self.e = 65537

        assert math.gcd(self.e, self.lam_n) == 1, "Must be co-prime!"

        # get the modular multiplicative inv of e mod lam(n)
        # this is the private key exponent
        self.d = pow(self.e, -1, self.lam_n)

    def _carmichael(self, p: int, q: int) -> int:
        """
        The Carmichael totient function of p & q
        which is = lcm(p - 1, q - 1)
        """
        a = p - 1
        b = q - 1
        return abs(a * b) // math.gcd(a, b)

    def encrypt(self, message: int, publickey: PubKeys):
        """
        In reality we'd need to pad the message, but we'll ignore that here
        """
        n_pub, e_pub = publickey

        return pow(message, e_pub, n_pub)

    def decrypt(self, cypher: int):
        return pow(cypher, self.d, self.n)

    def publickey(self) -> PubKeys:
        return self.n, self.e

    def encrypt_and_sign(self, message: int, publickey: PubKeys) -> Tuple[int, int]:
        """
        encrypt a messsage, and include a signature
        """
        cypher = self.encrypt(message, publickey)
        signature = pow(hash(message), self.d, self.n)

        return cypher, signature

    def decrypt_and_verify(
        self, signed_message: int, publickey: PubKeys
    ) -> Tuple[bool, int]:
        """
        decrypt a messsage, and check the signature
        """
        cypher, signature = signed_message

        plain = self.decrypt(cypher)

        n_pub, e_pub = publickey
        verify = hash(plain) == hash(pow(signature, e_pub, n_pub))
        return verify, plain


if __name__ == "__main__":

    alice = RSA(128)
    bob = RSA(128)

    plaintext = 12345678

    signed_cyphertext = alice.encrypt_and_sign(plaintext, bob.publickey())

    verified_plaintext = bob.decrypt_and_verify(signed_cyphertext, alice.publickey())

    print(f"Original message was {plaintext}")
    print(f"Bob decrypted: {verified_plaintext[1]}")
    print(f"This was sent with Alice's private key: {verified_plaintext[0]}")
