"""safefile: file encryption and integrity verification from the terminal.

The goal is a small tool built with care: authenticated encryption
(AES-256-GCM), key derivation with scrypt, and hash manifests that are
compatible with sha256sum.
"""

__version__ = "1.0.0"
