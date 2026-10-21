"""Small AST macro facility: calls to registered macro names are rewritten when a function is decorated."""
import ast
import importlib
import inspect
import os
import textwrap

MACROS = {
    "SEAL": "__aead__.AESGCM(__key__(32)).encrypt(__nonce__(12), __arg0__, None)",  # GT:H1-01/def
    "KEM_KEYPAIR": "__kem__.MLKEM768PrivateKey.generate()",  # GT:H1-02/def
}

_KEYS = {}


def _key(size: int) -> bytes:
    return _KEYS.setdefault(size, os.urandom(size))


_CONTEXT = {
    "__aead__": importlib.import_module("cryptography.hazmat.primitives.ciphers.aead"),  # GT:H1-01/def
    "__kem__": importlib.import_module("cryptography.hazmat.primitives.asymmetric.mlkem"),  # GT:H1-02/def
    "__key__": _key,
    "__nonce__": os.urandom,
}


def SEAL(*_args):
    raise RuntimeError("macro called without expansion")


def KEM_KEYPAIR():
    raise RuntimeError("macro called without expansion")


class _Expander(ast.NodeTransformer):
    def visit_Call(self, node):
        self.generic_visit(node)
        if not (isinstance(node.func, ast.Name) and node.func.id in MACROS):
            return node
        template = ast.parse(MACROS[node.func.id], mode="eval").body
        slots = {f"__arg{i}__": arg for i, arg in enumerate(node.args)}
        inherited = {id(n) for arg in node.args for n in ast.walk(arg)}

        class _Fill(ast.NodeTransformer):
            def visit_Name(self, name):
                return slots.get(name.id, name)

        expanded = _Fill().visit(template)
        for child in ast.walk(expanded):
            if id(child) in inherited or "lineno" not in child._attributes:
                continue
            child.lineno, child.end_lineno = node.lineno, node.end_lineno
            child.col_offset, child.end_col_offset = node.col_offset, node.end_col_offset
        return expanded


def expand(func):
    """Decorator: re-compile *func* with macro calls expanded in place (line numbers are preserved)."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(func)))
    tree.body[0].decorator_list = []
    tree = ast.fix_missing_locations(_Expander().visit(tree))
    ast.increment_lineno(tree, func.__code__.co_firstlineno - 1)
    namespace = dict(func.__globals__)
    namespace.update(_CONTEXT)
    exec(compile(tree, inspect.getsourcefile(func), "exec"), namespace)
    return namespace[func.__name__]
