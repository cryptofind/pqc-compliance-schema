import ast
import hashlib
import secrets
from pathlib import Path


class CryptoInjector(ast.NodeTransformer):
    """
    Injects cryptographic operations into selected functions.

    The generated code contains:
      - SHA-256 hashing
      - AES-GCM encryption
    """

    def visit_FunctionDef(self, node):
        self.generic_visit(node)

        # ---------------------------------------------------------
        # Inject:
        #
        # crypto_digest = hashlib.sha256(
        #     data.encode("utf-8")
        # ).hexdigest()
        # ---------------------------------------------------------

        hash_statement = ast.Assign(
            targets=[
                ast.Name(
                    id="crypto_digest",
                    ctx=ast.Store()
                )
            ],
            value=ast.Call(
                func=ast.Attribute(
                    value=ast.Call(
                        func=ast.Attribute(
                            value=ast.Name(
                                id="hashlib",
                                ctx=ast.Load()
                            ),
                            attr="sha256",
                            ctx=ast.Load()
                        ),
                        args=[],
                        keywords=[]
                    ),
                    attr="hexdigest",
                    ctx=ast.Load()
                ),
                args=[],
                keywords=[]
            )
        )

        # The above expression is intentionally replaced below
        # with a more explicit AST construction.

        hash_statement = ast.parse(
            """
crypto_digest = hashlib.sha256(
    data.encode("utf-8")
).hexdigest()
"""
        ).body[0]

        # ---------------------------------------------------------
        # Inject:
        #
        # aes_key = AESGCM.generate_key(bit_length=128)
        # aes = AESGCM(aes_key)
        # nonce = secrets.token_bytes(12)
        # encrypted_data = aes.encrypt(
        #     nonce,
        #     data.encode("utf-8"),
        #     None
        # )
        # ---------------------------------------------------------

        encryption_statements = ast.parse(
            """
aes_key = AESGCM.generate_key(bit_length=128)
aes = AESGCM(aes_key)
nonce = secrets.token_bytes(12)

encrypted_data = aes.encrypt(
    nonce,
    data.encode("utf-8"),
    None
)
"""
        ).body

        # Insert the injected cryptographic operations
        # immediately after the function begins.
        node.body = (
            encryption_statements
            + [hash_statement]
            + node.body
        )

        return node


def inject_crypto(source_file, output_file):
    source = Path(source_file).read_text()

    tree = ast.parse(source)

    injector = CryptoInjector()
    transformed_tree = injector.visit(tree)

    ast.fix_missing_locations(transformed_tree)

    # Add imports required by the injected code.
    imports = ast.parse(
        """
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
"""
    ).body

    transformed_tree.body = imports + transformed_tree.body

    generated_source = ast.unparse(transformed_tree)

    Path(output_file).write_text(generated_source)

    print(f"[+] Source transformed:")
    print(f"    Input : {source_file}")
    print(f"    Output: {output_file}")


if __name__ == "__main__":
    inject_crypto(
        "application.py",
        "application_injected.py"
    )