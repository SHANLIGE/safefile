# safefile

![tests](https://github.com/YOUR_USERNAME/safefile/actions/workflows/tests.yml/badge.svg)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

A command-line tool to **encrypt and decrypt files** with authenticated encryption and to **verify the integrity** of files and directories using cryptographic hashes.

I built it to understand, hands-on, the details that usually get left out of "how to encrypt a file in Python" examples: what happens when the file doesn't fit in memory, how to stop someone from reordering or cutting encrypted chunks, why the header needs to be authenticated too, and what a hash does (and doesn't) guarantee.

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/safefile.git
cd safefile
pip install -e .
```

Requires Python 3.10 or later. The only dependency is [`cryptography`](https://cryptography.io).

## Usage

### Encrypt and decrypt

```bash
$ safefile encrypt report.pdf
Password:
Repeat password:
Encrypted: report.pdf.sfv

$ safefile decrypt report.pdf.sfv
Password:
Decrypted: report.pdf
```

If the password is wrong, or if the encrypted file was altered by even a single bit, decryption fails and **no output file is written**.

### Hashes and manifests

```bash
# hash one or more files (sha256 by default)
$ safefile hash data.csv -a sha3_256

# build a manifest for a whole directory
$ safefile manifest ./dataset -o dataset/MANIFEST.sha256

# verify later
$ safefile verify dataset/MANIFEST.sha256
customers.csv: MODIFIED
logs/2026-10.txt: MISSING

14/16 files intact
```

`verify` exits with code `1` if anything fails, so it can be used in scripts or CI pipelines. The manifest uses the same format as `sha256sum`, so it can also be checked with `sha256sum -c MANIFEST.sha256`.

Supported algorithms: `sha256`, `sha512`, `sha3_256`, `blake2b`. MD5 and SHA-1 are intentionally excluded because they have known practical collisions.

For non-interactive use, the password can be passed through the `SAFEFILE_PASSWORD` environment variable (see the limitations section).

## Cryptographic design

### Key derivation

The 256-bit key is derived from the password with **scrypt** (N = 2¹⁷, r = 8, p = 1, ~128 MiB of memory) and a random 16-byte salt per file. scrypt is *memory-hard*, which makes brute-force attacks with specialized hardware more expensive than with alternatives such as PBKDF2.

The parameters are stored in each file's header, so they can be strengthened in future versions without breaking compatibility with older files. They are validated against reasonable bounds when read, so a tampered file can't force excessive memory usage.

### Chunked encryption (STREAM)

The file is encrypted with **AES-256-GCM** in 64 KiB chunks, which allows files of any size to be processed with constant memory. Encrypting chunks independently opens the door to reordering, duplicating, or truncating them; to prevent this, the tool follows the **STREAM** construction by Hoang et al. (2015), where each chunk's nonce is:

```
nonce (12 bytes) = random prefix (6) ‖ chunk counter (5) ‖ last-chunk flag (1)
```

- The **counter** binds each chunk to its position: moving it invalidates its tag.
- The **last-chunk flag** detects truncation exactly at a chunk boundary, an attack that would otherwise go unnoticed.
- The **entire header is used as AAD** (additional authenticated data) for every chunk, so any change to the salt, the scrypt parameters, or the chunk size is detected as well.

### File format

```
┌─────────────────────────── header (34 bytes) ──────────────────────────┐
│ "SFV1" │ ver │ log_n │ r │ p │ salt (16) │ prefix (6) │ chunk size (4) │
└────────────────────────────────────────────────────────────────────────┘
│ chunk 0 ciphertext + tag (16) │ chunk 1 + tag │ ... │ last + tag │
```

### Atomic writes

Output is first written to a temporary file in the same directory and only renamed to its destination (`os.replace`) once every chunk has been authenticated. If chunk 50 out of 100 fails, no partially decrypted file that looks valid is left on disk.

## Threat model and limitations

What it protects:

- **Confidentiality** of the content against anyone who obtains the encrypted file without the password.
- **Integrity and authenticity** of the encrypted file: any modification, reordering, or truncation is detected.
- **Integrity** of plaintext files against accidental corruption or modification, through manifests.

What it does **not** protect, and it's worth being clear about it:

- A hash manifest does **not** protect against an attacker who can modify both the files and the manifest: they can simply recompute the hashes. That requires signing the manifest (for example with GPG or minisign) or using an HMAC with a secret key.
- Security depends on the password. scrypt makes each guess expensive, but it can't save a weak password.
- The approximate size of the original file and its metadata (name, timestamps) are not hidden.
- `SAFEFILE_PASSWORD` is convenient for automation, but environment variables may be visible to other processes run by the same user.
- Python offers no reliable way to wipe the key or password from memory after use.
- The code has not undergone an independent security audit.

## Project structure

```
src/safefile/
├── kdf.py         # scrypt key derivation and parameter validation
├── header.py      # binary header serialization and validation
├── crypto.py      # STREAM encryption/decryption with AES-GCM and atomic writes
├── integrity.py   # hashing, manifest generation and verification
├── errors.py      # exception hierarchy
└── cli.py         # command-line interface (no cryptographic logic)
tests/             # pytest suite, including tampering tests
```

The cryptographic and integrity logic doesn't depend on the terminal: it works on streams and paths, so it can be tested directly and reused as a library. `cli.py` only translates arguments and errors.

## Tests

```bash
pip install -e ".[dev]"
pytest -v
```

Besides the normal cases (round trips with sizes at chunk boundaries, empty files), the tests cover attack attempts: wrong password, a single flipped bit, a tampered header, reordered chunks, truncation at a chunk boundary, path traversal in manifests (`../../etc/passwd`), and making sure a failed decryption leaves no files behind. They run on GitHub Actions on Linux, Windows, and macOS.

## Future work

- Manifest signing with Ed25519 to cover the case of an attacker who controls the manifest.
- Argon2id support as an alternative KDF.
- Encryption of whole directories.
- Public-key encryption (X25519) to share files without exchanging passwords.

## References

- V. T. Hoang, R. Reyhanitabar, P. Rogaway, D. Vizár. *Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance*. CRYPTO 2015.
- C. Percival. *Stronger Key Derivation via Sequential Memory-Hard Functions*. 2009.
- NIST SP 800-38D. *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*.
- OWASP Password Storage Cheat Sheet.

## License

MIT — see [LICENSE](LICENSE).
