"""Configuration-driven (crypto-agile) key generation: the algorithm family comes from b3_crypto.yaml."""
import importlib
from pathlib import Path
import yaml

def load_signing_key():
    cfg = yaml.safe_load(Path(__file__).with_name("b3_crypto.yaml").read_text())["signing"]
    module = importlib.import_module("cryptography.hazmat.primitives.asymmetric." + cfg["family"])
    return module.generate_private_key(public_exponent=65537, key_size=cfg["key_size"])
