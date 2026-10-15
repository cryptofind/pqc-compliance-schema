``` bash
pip install cryptography
```

```text
                 Original Source
                       │
                       ▼
              ┌─────────────────┐
              │ Python AST       │
              │ Transformer      │
              └────────┬────────┘
                       │
                       │ inject
                       ▼
          ┌─────────────────────────┐
          │ Cryptographic elements  │
          │                         │
          │ SHA-256                 │
          │ AES-GCM                 │
          │ AES-128 key generation  │
          │ Random nonce generation │
          └────────────┬────────────┘
                       │
                       ▼
              Modified Source Code
                       │
                       ▼
                    SAST
                       │
                       ▼
             Crypto/PQC Findings
```