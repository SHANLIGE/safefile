"""Key derivation from a password.

I use scrypt because it's memory-hard: every guess costs memory as well as
CPU, which makes GPU/ASIC attacks considerably more expensive than with
PBKDF2. Argon2id would be just as good, but scrypt already ships with
`cryptography` and I didn't want to add another dependency.
"""

from dataclasses import dataclass
import os

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEY_SIZE = 32  # 256 bits, for AES-256
SALT_SIZE = 16


@dataclass(frozen=True)
class ScryptParams:
    # N is stored as an exponent (N = 2**log_n) so it fits in a single byte
    # of the header. 2**17 with r=8 uses ~128 MiB, which is roughly what
    # OWASP recommends as a reasonable minimum these days.
    log_n: int = 17
    r: int = 8
    p: int = 1

    def __post_init__(self):
        # We validate because these values are also read from untrusted files;
        # a tampered header with log_n=40 could exhaust the machine's memory.
        if not 10 <= self.log_n <= 22:
            raise ValueError(f"log_n out of range: {self.log_n}")
        if not 1 <= self.r <= 32 or not 1 <= self.p <= 16:
            raise ValueError("scrypt r/p parameters out of range")


def new_salt() -> bytes:
    # os.urandom uses the operating system's CSPRNG, which is what we want.
    return os.urandom(SALT_SIZE)


def derive_key(password: str, salt: bytes, params: ScryptParams) -> bytes:
    if not password:
        raise ValueError("password must not be empty")

    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=2**params.log_n, r=params.r, p=params.p)
    return kdf.derive(password.encode("utf-8"))
