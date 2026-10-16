"""H7 track E: post-quantum key establishment local to the deepest function."""
from cryptography.hazmat.primitives.asymmetric import mlkem


def e_entry_d00():
    receiver = mlkem.MLKEM768PrivateKey.generate()  # GT:H7-E-d00/keygen
    shared, encapsulated = receiver.public_key().encapsulate()  # GT:H7-E-d00/op
    return receiver.decapsulate(encapsulated) == shared


def e_entry_d04():
    return _e_d04_h01()


def e_entry_d16():
    return _e_d16_h01()


def _e_d04_h01():
    return _e_d04_h02()


def _e_d04_h02():
    return _e_d04_h03()


def _e_d04_h03():
    return _e_d04_sink()


def _e_d16_h01():
    return _e_d16_h02()


def _e_d16_h02():
    return _e_d16_h03()


def _e_d16_h03():
    return _e_d16_h04()


def _e_d16_h04():
    return _e_d16_h05()


def _e_d16_h05():
    return _e_d16_h06()


def _e_d16_h06():
    return _e_d16_h07()


def _e_d16_h07():
    return _e_d16_h08()


def _e_d16_h08():
    return _e_d16_h09()


def _e_d16_h09():
    return _e_d16_h10()


def _e_d16_h10():
    return _e_d16_h11()


def _e_d16_h11():
    return _e_d16_h12()


def _e_d16_h12():
    return _e_d16_h13()


def _e_d16_h13():
    return _e_d16_h14()


def _e_d16_h14():
    return _e_d16_h15()


def _e_d16_h15():
    return _e_d16_sink()


def _e_d04_sink():
    receiver = mlkem.MLKEM768PrivateKey.generate()  # GT:H7-E-d04/keygen
    shared, encapsulated = receiver.public_key().encapsulate()  # GT:H7-E-d04/op
    return receiver.decapsulate(encapsulated) == shared


def _e_d16_sink():
    receiver = mlkem.MLKEM768PrivateKey.generate()  # GT:H7-E-d16/keygen
    shared, encapsulated = receiver.public_key().encapsulate()  # GT:H7-E-d16/op
    return receiver.decapsulate(encapsulated) == shared
