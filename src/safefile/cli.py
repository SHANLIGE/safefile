"""Command-line interface.

This module only deals with the user: parsing arguments, asking for the
password and printing results. All the real logic lives in crypto.py and
integrity.py, which know nothing about the terminal (and that's why they can
be tested without faking any input).
"""

import argparse
import getpass
import os
from pathlib import Path
import sys

from . import __version__
from .crypto import decrypt_file, encrypt_file
from .errors import SafeFileError
from .integrity import (
    DEFAULT_ALGORITHM,
    SUPPORTED_ALGORITHMS,
    Status,
    build_manifest,
    hash_file,
    verify_manifest,
)

ENCRYPTED_SUFFIX = ".sfv"
PASSWORD_ENV = "SAFEFILE_PASSWORD"
MIN_PASSWORD_LENGTH = 8


def _ask_password(confirm: bool) -> str:
    # The environment variable exists for scripts and CI. It isn't ideal
    # (other processes of the same user can read it), so the default is
    # always getpass, which doesn't echo what you type.
    from_env = os.environ.get(PASSWORD_ENV)
    if from_env:
        return from_env

    password = getpass.getpass("Password: ")
    if confirm:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise SafeFileError(f"use at least {MIN_PASSWORD_LENGTH} characters")
        if getpass.getpass("Repeat password: ") != password:
            raise SafeFileError("passwords do not match")
    return password


def _refuse_overwrite(path: Path, force: bool) -> None:
    if path.exists() and not force:
        raise SafeFileError(f"{path} already exists (use --force to overwrite it)")


def cmd_encrypt(args) -> int:
    output = args.output or args.file.with_name(args.file.name + ENCRYPTED_SUFFIX)
    _refuse_overwrite(output, args.force)
    encrypt_file(args.file, output, _ask_password(confirm=True))
    print(f"Encrypted: {output}")
    return 0


def cmd_decrypt(args) -> int:
    if args.output:
        output = args.output
    elif args.file.suffix == ENCRYPTED_SUFFIX:
        output = args.file.with_suffix("")
    else:
        raise SafeFileError("can't guess the output name, pass it with -o")
    _refuse_overwrite(output, args.force)
    decrypt_file(args.file, output, _ask_password(confirm=False))
    print(f"Decrypted: {output}")
    return 0


def cmd_hash(args) -> int:
    for path in args.files:
        # Same format as sha256sum, so the output can be redirected into a manifest.
        print(f"{hash_file(path, args.algorithm)}  {path}")
    return 0


def cmd_manifest(args) -> int:
    # If the manifest is saved inside the same directory, exclude it so it
    # doesn't try to hash itself.
    exclude = [args.output] if args.output else []
    text = build_manifest(args.directory, args.algorithm, exclude=exclude)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"Manifest saved to {args.output}")
    else:
        sys.stdout.write(text)
    return 0


def cmd_verify(args) -> int:
    root = args.root or args.manifest.parent
    results = verify_manifest(root, args.manifest.read_text(encoding="utf-8"), args.algorithm)

    failures = 0
    for result in results:
        if result.status is not Status.OK:
            failures += 1
        if result.status is not Status.OK or not args.quiet:
            print(f"{result.path}: {result.status.value}")

    print(f"\n{len(results) - failures}/{len(results)} files intact")
    # Non-zero exit code so it can be used in scripts and pipelines.
    return 1 if failures else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safefile",
        description="Encrypt/decrypt files and verify their integrity with hashes.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="encrypt a file with AES-256-GCM")
    enc.add_argument("file", type=Path)
    enc.add_argument("-o", "--output", type=Path)
    enc.add_argument("-f", "--force", action="store_true", help="overwrite the output if it exists")
    enc.set_defaults(handler=cmd_encrypt)

    dec = sub.add_parser("decrypt", help="decrypt a .sfv file")
    dec.add_argument("file", type=Path)
    dec.add_argument("-o", "--output", type=Path)
    dec.add_argument("-f", "--force", action="store_true")
    dec.set_defaults(handler=cmd_decrypt)

    algo = dict(choices=SUPPORTED_ALGORITHMS, default=DEFAULT_ALGORITHM)

    hsh = sub.add_parser("hash", help="compute the hash of one or more files")
    hsh.add_argument("files", type=Path, nargs="+")
    hsh.add_argument("-a", "--algorithm", **algo)
    hsh.set_defaults(handler=cmd_hash)

    man = sub.add_parser("manifest", help="build a hash manifest for a directory")
    man.add_argument("directory", type=Path)
    man.add_argument("-o", "--output", type=Path)
    man.add_argument("-a", "--algorithm", **algo)
    man.set_defaults(handler=cmd_manifest)

    ver = sub.add_parser("verify", help="check files against a manifest")
    ver.add_argument("manifest", type=Path)
    ver.add_argument("--root", type=Path, help="base directory (defaults to the manifest's directory)")
    ver.add_argument("-a", "--algorithm", choices=SUPPORTED_ALGORITHMS,
                     help="only needed if sha3_256 or blake2b was used")
    ver.add_argument("-q", "--quiet", action="store_true", help="only show failures")
    ver.set_defaults(handler=cmd_verify)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except SafeFileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"error: {exc.filename} does not exist", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
