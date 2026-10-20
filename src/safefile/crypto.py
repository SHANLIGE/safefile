"""Chunked file encryption and decryption with AES-256-GCM.

Encrypting the whole file in a single GCM call means holding all of it in
memory, so we split it into chunks. The problem with splitting naively is
that an attacker could reorder, duplicate or drop chunks without anyone
noticing. To prevent that I follow the idea behind the STREAM construction
(Hoang, Reyhanitabar, Rogaway and Vizár, 2015): each chunk's nonce is built as

    nonce = random prefix (6) || counter (5) || last-chunk flag (1)

With the counter, moving a chunk to another position breaks its
authentication. With the flag, if someone cuts the file short, the chunk left
at the end isn't marked as "last" and fails too. The header also goes in as AAD.
"""

from pathlib import Path
import os
import tempfile
from typing import BinaryIO, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import DecryptionError, InvalidFormatError
from .header import HEADER_SIZE, NONCE_PREFIX_SIZE, Header
from .kdf import ScryptParams, derive_key, new_salt

DEFAULT_CHUNK_SIZE = 64 * 1024
TAG_SIZE = 16
_COUNTER_SIZE = 5
_MAX_CHUNKS = 2 ** (8 * _COUNTER_SIZE)


def _chunk_nonce(prefix: bytes, counter: int, is_last: bool) -> bytes:
    if counter >= _MAX_CHUNKS:
        # With 64 KiB chunks this is ~64 PiB, so it should never happen,
        # but nonce reuse in GCM is catastrophic, so failing is the safe choice.
        raise OverflowError("too many chunks for a single file")
    return prefix + counter.to_bytes(_COUNTER_SIZE, "big") + (b"\x01" if is_last else b"\x00")


def _read_chunks(stream: BinaryIO, size: int) -> Iterator[tuple[bytes, bool]]:
    """Yield (chunk, is_last), reading one chunk ahead.

    We need to know which chunk is the last one before encrypting it, and the
    only reliable way to tell with a stream is to try reading the next one.
    An empty file produces a single empty chunk marked as last, so even that
    case is authenticated.
    """
    current = stream.read(size)
    while True:
        following = stream.read(size)
        if not following:
            yield current, True
            return
        yield current, False
        current = following


def encrypt_stream(
    src: BinaryIO,
    dst: BinaryIO,
    password: str,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    params: ScryptParams = ScryptParams(),
) -> None:
    header = Header(
        scrypt=params,
        salt=new_salt(),
        nonce_prefix=os.urandom(NONCE_PREFIX_SIZE),
        chunk_size=chunk_size,
    )
    header_bytes = header.to_bytes()
    aes = AESGCM(derive_key(password, header.salt, params))

    dst.write(header_bytes)
    for counter, (chunk, is_last) in enumerate(_read_chunks(src, chunk_size)):
        nonce = _chunk_nonce(header.nonce_prefix, counter, is_last)
        dst.write(aes.encrypt(nonce, chunk, header_bytes))


def decrypt_stream(src: BinaryIO, dst: BinaryIO, password: str) -> None:
    header_bytes = src.read(HEADER_SIZE)
    header = Header.from_bytes(header_bytes)
    aes = AESGCM(derive_key(password, header.salt, header.scrypt))

    # Each encrypted chunk is the size of the original plus the 16-byte tag.
    sealed_size = header.chunk_size + TAG_SIZE
    saw_last = False

    for counter, (sealed, is_last) in enumerate(_read_chunks(src, sealed_size)):
        if len(sealed) < TAG_SIZE:
            raise InvalidFormatError("the file is truncated")
        nonce = _chunk_nonce(header.nonce_prefix, counter, is_last)
        try:
            dst.write(aes.decrypt(nonce, sealed, header_bytes))
        except InvalidTag:
            raise DecryptionError(
                "decryption failed: wrong password or the file was modified"
            ) from None
        saw_last = is_last

    if not saw_last:
        raise InvalidFormatError("the encrypted file contains no data")


def _write_atomically(target: Path, writer) -> None:
    """Write to a temporary file and rename it only if everything succeeded.

    This matters most when decrypting: if chunk 50 out of 100 fails
    authentication, we don't want the 49 before it left on disk looking like
    a valid file. os.replace is atomic within the same filesystem.
    """
    target = Path(target)
    fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as tmp:
            writer(tmp)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(tmp_name, target)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


def encrypt_file(src: Path, dst: Path, password: str, **kwargs) -> None:
    with open(src, "rb") as fin:
        _write_atomically(dst, lambda fout: encrypt_stream(fin, fout, password, **kwargs))


def decrypt_file(src: Path, dst: Path, password: str) -> None:
    with open(src, "rb") as fin:
        _write_atomically(dst, lambda fout: decrypt_stream(fin, fout, password))
