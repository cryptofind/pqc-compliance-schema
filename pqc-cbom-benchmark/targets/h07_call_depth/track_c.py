"""H7 track C: the key-size literal crosses one module boundary per call."""
from xmod import level01, sinks


def c_entry_d01():
    return sinks.c_d01(4096)  # GT:H7-C-d01/src


def c_entry_d02():
    return level01.c_d02(2048)  # GT:H7-C-d02/src


def c_entry_d04():
    return level01.c_d04(3072)  # GT:H7-C-d04/src


def c_entry_d08():
    return level01.c_d08(4096)  # GT:H7-C-d08/src
