"""
1-2 Oblivious transfer with RSA

https://en.wikipedia.org/wiki/Oblivious_transfer

Code is structured as two, asymmetric parties, Alice and Bob,
with Alice creating the messages and Bob selecting which one he wants
"""

from rsa import RSA, PubKeys
import random as rd
from typing import Tuple


class Alice:
    def __init__(self, bits, disclose):
        self.r = RSA(bits)
        self.disclose = disclose

        # the messages Bob can choose from
        self.m0 = 1234
        self.m1 = 5678
        if self.disclose:
            print(f"The messages are: {self.m0, self.m1}")

        # random messages of similar size
        self.x0 = rd.randint(1000, 10000)
        self.x1 = rd.randint(1000, 10000)

    def send_publickey(self) -> PubKeys:
        return self.r.publickey()

    def send_random_messages(self) -> Tuple[int, int]:
        return self.x0, self.x1

    def receive_encrypted_choice(self, choice: int):
        self.v = choice
        if self.disclose:
            print(f"Bob has asked for {choice} (Alice can't decrypt this)")

        self.k0 = pow(self.v - self.x0, self.r.d, self.r.n)
        self.k1 = pow(self.v - self.x1, self.r.d, self.r.n)

    def send_encrypted_messages(self) -> Tuple[int, int]:
        m0_ = (self.m0 + self.k0) % self.r.n
        m1_ = (self.m1 + self.k1) % self.r.n

        return m0_, m1_


class Bob:
    def __init__(self, bits, disclose):
        self.bits = bits
        self.disclose = disclose

    def receive_publickey(self, pkey: PubKeys):
        self.n_pub, self.e_pub = pkey

    def receive_random_messages(self, messages: Tuple[int, int]):
        self.xs = messages

    def choose_parameters(self):
        self.b = rd.choice((0, 1)) # which message do you want?
        self.k = rd.randint(0, 2**self.bits)

        if self.disclose:
            print(f"Bob wants message {self.b}")

    def send_encrypted_choice(self):
        x_b = self.xs[self.b]
        return (x_b + self.k ** self.e_pub) % self.n_pub

    def decrypt_choice(self, messages: Tuple[int, int]):
        mb = messages[self.b]

        self.message = (mb - self.k) % self.n_pub
        if self.disclose:
            print(f"Bob has decrypted message {self.b} to {self.message}")
            other = messages[not self.b]
            nonsense = (other - self.k) % self.n_pub
            print(f"If Bob applies the protocol to the other message he gets {nonsense}")


if __name__ == "__main__":

    alice = Alice(128, True)
    bob = Bob(128, True)

    bob.receive_publickey(alice.send_publickey())
    bob.receive_random_messages(alice.send_random_messages())

    bob.choose_parameters()

    alice.receive_encrypted_choice(bob.send_encrypted_choice())

    bob.decrypt_choice(alice.send_encrypted_messages())
