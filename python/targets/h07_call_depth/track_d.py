"""H7 track D: the key size is stored on objects and read back after d object hops."""
from cryptography.hazmat.primitives.asymmetric import rsa


def d_entry_d01():
    return D01Hop01(3072).run()  # GT:H7-D-d01/src


def d_entry_d02():
    return D02Hop01(2048).run()  # GT:H7-D-d02/src


def d_entry_d04():
    return D04Hop01(4096).run()  # GT:H7-D-d04/src


class D01Hop01:
    def __init__(self, bits):
        self.bits = bits

    def run(self):
        return rsa.generate_private_key(public_exponent=65537, key_size=self.bits)  # GT:H7-D-d01


class D02Hop01:
    def __init__(self, bits):
        self.bits = bits

    def run(self):
        return D02Hop02(self.bits).run()


class D02Hop02:
    def __init__(self, bits):
        self.bits = bits

    def run(self):
        return rsa.generate_private_key(public_exponent=65537, key_size=self.bits)  # GT:H7-D-d02


class D04Hop01:
    def __init__(self, bits):
        self.bits = bits

    def run(self):
        return D04Hop02(self.bits).run()


class D04Hop02:
    def __init__(self, bits):
        self.bits = bits

    def run(self):
        return D04Hop03(self.bits).run()


class D04Hop03:
    def __init__(self, bits):
        self.bits = bits

    def run(self):
        return D04Hop04(self.bits).run()


class D04Hop04:
    def __init__(self, bits):
        self.bits = bits

    def run(self):
        return rsa.generate_private_key(public_exponent=65537, key_size=self.bits)  # GT:H7-D-d04
