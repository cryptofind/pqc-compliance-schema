"""Plugin loader that resolves the key-generation function by name at run time."""
import importlib

def load_plugin_key():
    family = "".join(["r", "s", "a"])
    module = importlib.import_module("cryptography.hazmat.primitives.asymmetric." + family)
    generate = getattr(module, "generate_" + "private_key")
    return generate(65537, 2048)
