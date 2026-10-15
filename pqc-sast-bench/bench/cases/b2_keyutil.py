"""Generic key helper shared by several services; algorithm module is injected by the caller."""

def make_key(algorithm_module, bits):
    return algorithm_module.generate_private_key(public_exponent=65537, key_size=bits)
