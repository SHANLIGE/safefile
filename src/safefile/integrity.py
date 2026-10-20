"""File hashes and manifests for integrity verification.

The manifest format is the same one produced by `sha256sum` and friends
("<hash>  <path>"), so it can be checked with standard tools without
depending on this project.

An important caveat, also covered in the README: a hash only detects
accidental changes or changes made by someone who can't touch the manifest.
If the attacker can modify both the file AND the manifest, they just
recompute the hash. That case needs a signature or a keyed HMAC.
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import hashlib
import hmac
from typing import Iterable, Iterator

from .errors import ManifestError

# MD5 and SHA-1 are left out on purpose: both have known practical collisions.
SUPPORTED_ALGORITHMS = ("sha256", "sha512", "sha3_256", "blake2b")
DEFAULT_ALGORITHM = "sha256"
_READ_SIZE = 1024 * 1024


def hash_file(path: Path, algorithm: str = DEFAULT_ALGORITHM) -> str:
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"unsupported algorithm: {algorithm}")

    digest = hashlib.new(algorithm)
    with open(path, "rb") as f:
        # Read in pieces so multi-GB files don't end up in memory.
        while block := f.read(_READ_SIZE):
            digest.update(block)
    return digest.hexdigest()


class Status(Enum):
    OK = "OK"
    MODIFIED = "MODIFIED"
    MISSING = "MISSING"


@dataclass(frozen=True)
class CheckResult:
    path: str
    status: Status


def _iter_files(root: Path, exclude: set[Path]) -> Iterator[Path]:
    # sorted() keeps the manifest deterministic, so it can be versioned with git.
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink() and path.resolve() not in exclude:
            yield path


def build_manifest(root: Path, algorithm: str = DEFAULT_ALGORITHM, exclude: Iterable[Path] = ()) -> str:
    root = Path(root)
    skip = {Path(p).resolve() for p in exclude}
    lines = []
    for path in _iter_files(root, skip):
        # Relative paths with "/" so the manifest works on any OS.
        relative = path.relative_to(root).as_posix()
        lines.append(f"{hash_file(path, algorithm)}  {relative}")
    return "\n".join(lines) + ("\n" if lines else "")


def parse_manifest(text: str) -> list[tuple[str, str]]:
    entries = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip() or line.startswith("#"):
            continue
        # sha256sum uses two spaces, or a space + "*" in binary mode.
        digest, sep, name = line.partition("  ")
        if not sep:
            digest, sep, name = line.partition(" *")
        if not sep or not name or not all(c in "0123456789abcdef" for c in digest.lower()):
            raise ManifestError(f"malformed line {number}: {line!r}")
        entries.append((digest.lower(), name))
    return entries


def _guess_algorithm(digest: str) -> str:
    # The hash length tells us the algorithm in most cases.
    # But sha256 and sha3_256 have the same length (and so do sha512 and
    # blake2b), so if sha3 or blake2b was used it has to be given with --algorithm.
    by_length = {64: "sha256", 128: "sha512"}
    if len(digest) not in by_length:
        raise ManifestError(f"unrecognized hash of {len(digest)} characters")
    return by_length[len(digest)]


def verify_manifest(root: Path, manifest_text: str, algorithm: str | None = None) -> list[CheckResult]:
    root = Path(root).resolve()
    results = []

    for expected, name in parse_manifest(manifest_text):
        target = (root / name).resolve()

        # A malicious manifest could ask us to read "../../etc/shadow".
        # We only check files that are actually inside root.
        if not target.is_relative_to(root):
            raise ManifestError(f"path outside the verified directory: {name}")

        if not target.is_file():
            results.append(CheckResult(name, Status.MISSING))
            continue

        actual = hash_file(target, algorithm or _guess_algorithm(expected))
        # compare_digest runs in constant time. It isn't critical here since
        # hashes aren't secret, but it's a good habit and costs nothing.
        ok = hmac.compare_digest(actual, expected)
        results.append(CheckResult(name, Status.OK if ok else Status.MODIFIED))

    return results
