import io
import os

import pytest

from safefile.crypto import TAG_SIZE, decrypt_file, decrypt_stream, encrypt_file, encrypt_stream
from safefile.errors import DecryptionError, InvalidFormatError
from safefile.header import HEADER_SIZE

PASSWORD = "correct horse battery staple"
CHUNK = 1024  # small chunk size so even small inputs span several chunks


def encrypt(data, params, password=PASSWORD):
    out = io.BytesIO()
    encrypt_stream(io.BytesIO(data), out, password, chunk_size=CHUNK, params=params)
    return out.getvalue()


def decrypt(blob, password=PASSWORD):
    out = io.BytesIO()
    decrypt_stream(io.BytesIO(blob), out, password)
    return out.getvalue()


# Sizes picked to hit the edge cases: empty, less than one chunk, exactly one
# chunk, and several chunks with and without a remainder.
@pytest.mark.parametrize("size", [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 5 * CHUNK, 5 * CHUNK + 37])
def test_roundtrip(size, fast_params):
    data = os.urandom(size)
    assert decrypt(encrypt(data, fast_params)) == data


def test_same_input_gives_different_ciphertext(fast_params):
    # Salt and nonce are random, so encrypting the same thing twice shouldn't
    # produce the same output (otherwise it would leak information).
    data = b"same content"
    assert encrypt(data, fast_params) != encrypt(data, fast_params)


def test_wrong_password(fast_params):
    blob = encrypt(b"secret", fast_params)
    with pytest.raises(DecryptionError):
        decrypt(blob, password="something else")


def test_flipped_bit_is_detected(fast_params):
    blob = bytearray(encrypt(os.urandom(3 * CHUNK), fast_params))
    blob[HEADER_SIZE + CHUNK + 10] ^= 0x01
    with pytest.raises(DecryptionError):
        decrypt(bytes(blob))


def test_tampered_header_is_detected(fast_params):
    # Flip a byte of the salt. Since the header is used as AAD, even if the
    # key happened to stay the same the tag still wouldn't match.
    blob = bytearray(encrypt(b"data", fast_params))
    blob[10] ^= 0xFF
    with pytest.raises(DecryptionError):
        decrypt(bytes(blob))


def test_truncation_at_chunk_boundary_is_detected(fast_params):
    # This is the attack the last-chunk flag prevents: cutting the file right
    # between two chunks leaves something that would otherwise look valid.
    blob = encrypt(os.urandom(3 * CHUNK), fast_params)
    cut = HEADER_SIZE + 2 * (CHUNK + TAG_SIZE)
    with pytest.raises(DecryptionError):
        decrypt(blob[:cut])


def test_reordered_chunks_are_detected(fast_params):
    blob = encrypt(os.urandom(3 * CHUNK), fast_params)
    size = CHUNK + TAG_SIZE
    header, body = blob[:HEADER_SIZE], blob[HEADER_SIZE:]
    first, second, rest = body[:size], body[size:2 * size], body[2 * size:]
    with pytest.raises(DecryptionError):
        decrypt(header + second + first + rest)


def test_not_a_safefile():
    with pytest.raises(InvalidFormatError):
        decrypt(b"this is not an encrypted file" + b"\x00" * 50)


def test_header_only_is_rejected(fast_params):
    blob = encrypt(b"", fast_params)
    with pytest.raises(InvalidFormatError):
        decrypt(blob[:HEADER_SIZE])


def test_failed_decryption_leaves_no_output(tmp_path, fast_params):
    plain = tmp_path / "doc.txt"
    plain.write_bytes(os.urandom(4 * CHUNK))
    sealed = tmp_path / "doc.txt.sfv"
    encrypt_file(plain, sealed, PASSWORD, chunk_size=CHUNK, params=fast_params)

    # Corrupt the last chunk: the earlier ones would decrypt just fine,
    # but we don't want a partial file left on disk.
    data = bytearray(sealed.read_bytes())
    data[-1] ^= 0x01
    sealed.write_bytes(bytes(data))

    out = tmp_path / "output.txt"
    with pytest.raises(DecryptionError):
        decrypt_file(sealed, out, PASSWORD)
    assert not out.exists()
    assert list(tmp_path.glob("*.tmp")) == []
