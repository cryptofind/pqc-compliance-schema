"""H7 track C relay level 1."""
from xmod import level02, sinks


def c_d02(bits):
    return sinks.c_d02(bits)


def c_d04(bits):
    return level02.c_d04(bits)


def c_d08(bits):
    return level02.c_d08(bits)
