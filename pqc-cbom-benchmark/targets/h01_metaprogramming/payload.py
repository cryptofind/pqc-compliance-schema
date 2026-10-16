"""Executes an embedded, encoded routine (upper bound for metaprogramming opacity)."""
import base64
import os

_BLOB = "ZnJvbSBjcnlwdG9ncmFwaHkuaGF6bWF0LnByaW1pdGl2ZXMuY2lwaGVycy5hZWFkIGltcG9ydCBDaGFDaGEyMFBvbHkxMzA1CgoKZGVmIHJvdXRpbmUoZGF0YSwgbm9uY2UpOgogICAga2V5ID0gQ2hhQ2hhMjBQb2x5MTMwNS5nZW5lcmF0ZV9rZXkoKQogICAgcmV0dXJuIENoYUNoYTIwUG9seTEzMDUoa2V5KS5lbmNyeXB0KG5vbmNlLCBkYXRhLCBOb25lKQo="  # GT:H1-06/def


def run(data: bytes) -> bytes:
    namespace = {}
    exec(compile(base64.b64decode(_BLOB), "<embedded>", "exec"), namespace)  # GT:H1-06/def
    return namespace["routine"](data, os.urandom(12))  # GT:H1-06/anchor
