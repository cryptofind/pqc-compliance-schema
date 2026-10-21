"""H7 track A: the cryptographic call is local to the deepest function of each chain."""
from cryptography.hazmat.primitives.asymmetric import ec


def a_entry_d00():
    mine = ec.generate_private_key(ec.SECP256R1())  # GT:H7-A-d00/keygen
    peer = ec.generate_private_key(ec.SECP256R1())  # GT:H7-A-d00/keygen
    return mine.exchange(ec.ECDH(), peer.public_key())  # GT:H7-A-d00/op


def a_entry_d01():
    return _a_d01_sink()


def a_entry_d02():
    return _a_d02_h01()


def a_entry_d03():
    return _a_d03_h01()


def a_entry_d04():
    return _a_d04_h01()


def a_entry_d06():
    return _a_d06_h01()


def a_entry_d08():
    return _a_d08_h01()


def a_entry_d12():
    return _a_d12_h01()


def a_entry_d16():
    return _a_d16_h01()


def _a_d02_h01():
    return _a_d02_sink()


def _a_d03_h01():
    return _a_d03_h02()


def _a_d03_h02():
    return _a_d03_sink()


def _a_d04_h01():
    return _a_d04_h02()


def _a_d04_h02():
    return _a_d04_h03()


def _a_d04_h03():
    return _a_d04_sink()


def _a_d06_h01():
    return _a_d06_h02()


def _a_d06_h02():
    return _a_d06_h03()


def _a_d06_h03():
    return _a_d06_h04()


def _a_d06_h04():
    return _a_d06_h05()


def _a_d06_h05():
    return _a_d06_sink()


def _a_d08_h01():
    return _a_d08_h02()


def _a_d08_h02():
    return _a_d08_h03()


def _a_d08_h03():
    return _a_d08_h04()


def _a_d08_h04():
    return _a_d08_h05()


def _a_d08_h05():
    return _a_d08_h06()


def _a_d08_h06():
    return _a_d08_h07()


def _a_d08_h07():
    return _a_d08_sink()


def _a_d12_h01():
    return _a_d12_h02()


def _a_d12_h02():
    return _a_d12_h03()


def _a_d12_h03():
    return _a_d12_h04()


def _a_d12_h04():
    return _a_d12_h05()


def _a_d12_h05():
    return _a_d12_h06()


def _a_d12_h06():
    return _a_d12_h07()


def _a_d12_h07():
    return _a_d12_h08()


def _a_d12_h08():
    return _a_d12_h09()


def _a_d12_h09():
    return _a_d12_h10()


def _a_d12_h10():
    return _a_d12_h11()


def _a_d12_h11():
    return _a_d12_sink()


def _a_d16_h01():
    return _a_d16_h02()


def _a_d16_h02():
    return _a_d16_h03()


def _a_d16_h03():
    return _a_d16_h04()


def _a_d16_h04():
    return _a_d16_h05()


def _a_d16_h05():
    return _a_d16_h06()


def _a_d16_h06():
    return _a_d16_h07()


def _a_d16_h07():
    return _a_d16_h08()


def _a_d16_h08():
    return _a_d16_h09()


def _a_d16_h09():
    return _a_d16_h10()


def _a_d16_h10():
    return _a_d16_h11()


def _a_d16_h11():
    return _a_d16_h12()


def _a_d16_h12():
    return _a_d16_h13()


def _a_d16_h13():
    return _a_d16_h14()


def _a_d16_h14():
    return _a_d16_h15()


def _a_d16_h15():
    return _a_d16_sink()


def _a_d01_sink():
    mine = ec.generate_private_key(ec.SECP384R1())  # GT:H7-A-d01/keygen
    peer = ec.generate_private_key(ec.SECP384R1())  # GT:H7-A-d01/keygen
    return mine.exchange(ec.ECDH(), peer.public_key())  # GT:H7-A-d01/op


def _a_d02_sink():
    mine = ec.generate_private_key(ec.SECP521R1())  # GT:H7-A-d02/keygen
    peer = ec.generate_private_key(ec.SECP521R1())  # GT:H7-A-d02/keygen
    return mine.exchange(ec.ECDH(), peer.public_key())  # GT:H7-A-d02/op


def _a_d03_sink():
    mine = ec.generate_private_key(ec.SECP224R1())  # GT:H7-A-d03/keygen
    peer = ec.generate_private_key(ec.SECP224R1())  # GT:H7-A-d03/keygen
    return mine.exchange(ec.ECDH(), peer.public_key())  # GT:H7-A-d03/op


def _a_d04_sink():
    mine = ec.generate_private_key(ec.SECP256K1())  # GT:H7-A-d04/keygen
    peer = ec.generate_private_key(ec.SECP256K1())  # GT:H7-A-d04/keygen
    return mine.exchange(ec.ECDH(), peer.public_key())  # GT:H7-A-d04/op


def _a_d06_sink():
    mine = ec.generate_private_key(ec.BrainpoolP256R1())  # GT:H7-A-d06/keygen
    peer = ec.generate_private_key(ec.BrainpoolP256R1())  # GT:H7-A-d06/keygen
    return mine.exchange(ec.ECDH(), peer.public_key())  # GT:H7-A-d06/op


def _a_d08_sink():
    mine = ec.generate_private_key(ec.BrainpoolP384R1())  # GT:H7-A-d08/keygen
    peer = ec.generate_private_key(ec.BrainpoolP384R1())  # GT:H7-A-d08/keygen
    return mine.exchange(ec.ECDH(), peer.public_key())  # GT:H7-A-d08/op


def _a_d12_sink():
    mine = ec.generate_private_key(ec.BrainpoolP512R1())  # GT:H7-A-d12/keygen
    peer = ec.generate_private_key(ec.BrainpoolP512R1())  # GT:H7-A-d12/keygen
    return mine.exchange(ec.ECDH(), peer.public_key())  # GT:H7-A-d12/op


def _a_d16_sink():
    mine = ec.generate_private_key(ec.SECP192R1())  # GT:H7-A-d16/keygen
    peer = ec.generate_private_key(ec.SECP192R1())  # GT:H7-A-d16/keygen
    return mine.exchange(ec.ECDH(), peer.public_key())  # GT:H7-A-d16/op
