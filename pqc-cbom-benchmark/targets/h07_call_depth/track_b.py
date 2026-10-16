"""H7 track B: a key-size literal travels through d calls before it reaches the API call."""
from cryptography.hazmat.primitives.asymmetric import rsa


def b_entry_d00():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)  # GT:H7-B-d00


def b_entry_d01():
    return _b_d01_sink(3072)  # GT:H7-B-d01/src


def b_entry_d02():
    return _b_d02_h01(4096)  # GT:H7-B-d02/src


def b_entry_d03():
    return _b_d03_h01(2048)  # GT:H7-B-d03/src


def b_entry_d04():
    return _b_d04_h01(3072)  # GT:H7-B-d04/src


def b_entry_d06():
    return _b_d06_h01(4096)  # GT:H7-B-d06/src


def b_entry_d08():
    return _b_d08_h01(2048)  # GT:H7-B-d08/src


def b_entry_d12():
    return _b_d12_h01(3072)  # GT:H7-B-d12/src


def b_entry_d16():
    return _b_d16_h01(4096)  # GT:H7-B-d16/src


def _b_d02_h01(bits):
    return _b_d02_sink(bits)


def _b_d03_h01(bits):
    return _b_d03_h02(bits)


def _b_d03_h02(bits):
    return _b_d03_sink(bits)


def _b_d04_h01(bits):
    return _b_d04_h02(bits)


def _b_d04_h02(bits):
    return _b_d04_h03(bits)


def _b_d04_h03(bits):
    return _b_d04_sink(bits)


def _b_d06_h01(bits):
    return _b_d06_h02(bits)


def _b_d06_h02(bits):
    return _b_d06_h03(bits)


def _b_d06_h03(bits):
    return _b_d06_h04(bits)


def _b_d06_h04(bits):
    return _b_d06_h05(bits)


def _b_d06_h05(bits):
    return _b_d06_sink(bits)


def _b_d08_h01(bits):
    return _b_d08_h02(bits)


def _b_d08_h02(bits):
    return _b_d08_h03(bits)


def _b_d08_h03(bits):
    return _b_d08_h04(bits)


def _b_d08_h04(bits):
    return _b_d08_h05(bits)


def _b_d08_h05(bits):
    return _b_d08_h06(bits)


def _b_d08_h06(bits):
    return _b_d08_h07(bits)


def _b_d08_h07(bits):
    return _b_d08_sink(bits)


def _b_d12_h01(bits):
    return _b_d12_h02(bits)


def _b_d12_h02(bits):
    return _b_d12_h03(bits)


def _b_d12_h03(bits):
    return _b_d12_h04(bits)


def _b_d12_h04(bits):
    return _b_d12_h05(bits)


def _b_d12_h05(bits):
    return _b_d12_h06(bits)


def _b_d12_h06(bits):
    return _b_d12_h07(bits)


def _b_d12_h07(bits):
    return _b_d12_h08(bits)


def _b_d12_h08(bits):
    return _b_d12_h09(bits)


def _b_d12_h09(bits):
    return _b_d12_h10(bits)


def _b_d12_h10(bits):
    return _b_d12_h11(bits)


def _b_d12_h11(bits):
    return _b_d12_sink(bits)


def _b_d16_h01(bits):
    return _b_d16_h02(bits)


def _b_d16_h02(bits):
    return _b_d16_h03(bits)


def _b_d16_h03(bits):
    return _b_d16_h04(bits)


def _b_d16_h04(bits):
    return _b_d16_h05(bits)


def _b_d16_h05(bits):
    return _b_d16_h06(bits)


def _b_d16_h06(bits):
    return _b_d16_h07(bits)


def _b_d16_h07(bits):
    return _b_d16_h08(bits)


def _b_d16_h08(bits):
    return _b_d16_h09(bits)


def _b_d16_h09(bits):
    return _b_d16_h10(bits)


def _b_d16_h10(bits):
    return _b_d16_h11(bits)


def _b_d16_h11(bits):
    return _b_d16_h12(bits)


def _b_d16_h12(bits):
    return _b_d16_h13(bits)


def _b_d16_h13(bits):
    return _b_d16_h14(bits)


def _b_d16_h14(bits):
    return _b_d16_h15(bits)


def _b_d16_h15(bits):
    return _b_d16_sink(bits)


def _b_d01_sink(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)  # GT:H7-B-d01


def _b_d02_sink(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)  # GT:H7-B-d02


def _b_d03_sink(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)  # GT:H7-B-d03


def _b_d04_sink(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)  # GT:H7-B-d04


def _b_d06_sink(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)  # GT:H7-B-d06


def _b_d08_sink(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)  # GT:H7-B-d08


def _b_d12_sink(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)  # GT:H7-B-d12


def _b_d16_sink(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)  # GT:H7-B-d16
