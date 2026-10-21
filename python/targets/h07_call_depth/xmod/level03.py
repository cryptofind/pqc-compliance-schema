"""H7 track C relay level 3."""
from xmod import level04, sinks


def c_d04(bits):
    return sinks.c_d04(bits)


def c_d08(bits):
    return level04.c_d08(bits)
