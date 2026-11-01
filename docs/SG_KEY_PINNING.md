# Optional RSA public-key pins (SG/CE_RED routers)

The SG client can optionally verify both router RSA keys with SHA-256
fingerprints of their DER SubjectPublicKeyInfo encodings:

```python
router = TplinkRouterSG(
    host, password,
    password_key_pin="sha256:<64-hex-character-fingerprint>",
    auth_key_pin="sha256:<64-hex-character-fingerprint>",
)
router.authorize()
```

Replace the placeholders with your independently verified fingerprints from a
trusted connection. Never enroll automatically on first use. Both pins are
optional; omitted pins preserve the previous login behavior. A malformed pin
is rejected during construction. A key substitution is rejected before a
credential-bearing login request is made, without attempting another password
or updating the pin.

Both keys need pinning to protect against independent password-key and
session-key substitution. Pins **do not** protect against a transparent
full-duplex man-in-the-middle relay over plain HTTP; TLS is needed for that.
A router key rotation requires deliberate verification and pin updates.
