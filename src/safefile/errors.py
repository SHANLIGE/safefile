"""Project-specific exceptions.

I prefer a small hierarchy with a common base: that way the CLI can catch
SafeFileError and print a clean message without a traceback, while any other
unexpected error still shows up in full (because it would be a bug).
"""


class SafeFileError(Exception):
    """Base for every error the user can trigger."""


class InvalidFormatError(SafeFileError):
    """The file doesn't look like it was encrypted with safefile, or it's truncated."""


class DecryptionError(SafeFileError):
    """Authentication failed during decryption.

    Note: we deliberately don't distinguish between "wrong password" and
    "modified file". With GCM both look the same (the tag doesn't match), and
    giving more detail wouldn't help anyone except an attacker.
    """


class ManifestError(SafeFileError):
    """The hash manifest has lines that can't be parsed."""
