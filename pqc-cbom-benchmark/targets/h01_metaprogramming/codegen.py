"""Generates small helper functions from a source template when the module is imported."""
from string import Template

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf import hkdf

_TEMPLATE = Template(
    "def derive_$label(material):\n"
    "    return hkdf.$kdf(algorithm=hashes.$digest(), length=$length, salt=None, info=b'$label').derive(material)\n"  # GT:H1-03/def
)
_SPEC = {"label": "session", "kdf": "HKDF", "digest": "SHA384", "length": 32}  # GT:H1-03/def

_namespace = {"hkdf": hkdf, "hashes": hashes}  # GT:H1-03/def
exec(compile(_TEMPLATE.substitute(_SPEC), "<generated:kdf>", "exec"), _namespace)  # GT:H1-03/def
derive_session = _namespace["derive_session"]
