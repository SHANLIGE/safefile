"""Binary header format for encrypted files.

Layout (all big-endian, 34 bytes total):

    magic        4 bytes   b"SFV1"
    version      1 byte
    log_n        1 byte    \
    r            1 byte     > scrypt parameters
    p            1 byte    /
    salt        16 bytes
    nonce_prefix 6 bytes
    chunk_size   4 bytes   uint32

Storing the scrypt parameters in the file lets future versions raise them
without breaking existing files. And since the whole header is used as AAD
when encrypting every chunk, if someone modifies it (for example to lower
the scrypt cost) decryption fails.
"""

from dataclasses import dataclass
import struct

from .errors import InvalidFormatError
from .kdf import SALT_SIZE, ScryptParams

MAGIC = b"SFV1"
FORMAT_VERSION = 1
NONCE_PREFIX_SIZE = 6

_STRUCT = struct.Struct(f">4sBBBB{SALT_SIZE}s{NONCE_PREFIX_SIZE}sI")
HEADER_SIZE = _STRUCT.size

# Bounds so we don't blindly trust whatever a file claims.
MIN_CHUNK_SIZE = 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024


@dataclass(frozen=True)
class Header:
    scrypt: ScryptParams
    salt: bytes
    nonce_prefix: bytes
    chunk_size: int

    def to_bytes(self) -> bytes:
        return _STRUCT.pack(
            MAGIC,
            FORMAT_VERSION,
            self.scrypt.log_n,
            self.scrypt.r,
            self.scrypt.p,
            self.salt,
            self.nonce_prefix,
            self.chunk_size,
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Header":
        if len(raw) != HEADER_SIZE:
            raise InvalidFormatError("file is too short to contain a header")

        magic, version, log_n, r, p, salt, prefix, chunk_size = _STRUCT.unpack(raw)

        if magic != MAGIC:
            raise InvalidFormatError("not a safefile-encrypted file")
        if version != FORMAT_VERSION:
            raise InvalidFormatError(f"unsupported format version: {version}")
        if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
            raise InvalidFormatError(f"invalid chunk size: {chunk_size}")

        try:
            params = ScryptParams(log_n=log_n, r=r, p=p)
        except ValueError as exc:
            raise InvalidFormatError(str(exc)) from exc

        return cls(scrypt=params, salt=salt, nonce_prefix=prefix, chunk_size=chunk_size)
