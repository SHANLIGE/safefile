import pytest

from safefile import cli
from safefile.kdf import ScryptParams


@pytest.fixture(autouse=True)
def fast_cli(monkeypatch):
    # The CLI uses the real scrypt parameters; here we lower them and pass the
    # password through the environment variable so we don't have to fake getpass.
    monkeypatch.setenv(cli.PASSWORD_ENV, "a-long-password")
    original = cli.encrypt_file
    monkeypatch.setattr(
        cli, "encrypt_file",
        lambda src, dst, pw: original(src, dst, pw, params=ScryptParams(log_n=10)),
    )


def test_encrypt_then_decrypt(tmp_path):
    src = tmp_path / "notes.txt"
    src.write_text("sensitive data")

    assert cli.main(["encrypt", str(src)]) == 0
    sealed = tmp_path / "notes.txt.sfv"
    assert sealed.exists()

    src.unlink()
    assert cli.main(["decrypt", str(sealed)]) == 0
    assert src.read_text() == "sensitive data"


def test_does_not_overwrite_without_force(tmp_path, capsys):
    src = tmp_path / "a.txt"
    src.write_text("x")
    (tmp_path / "a.txt.sfv").write_text("already here")

    assert cli.main(["encrypt", str(src)]) == 2
    assert "--force" in capsys.readouterr().err


def test_verify_exit_code(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "f.txt").write_text("original")
    manifest = tmp_path / "MANIFEST.sha256"

    assert cli.main(["manifest", str(data), "-o", str(manifest)]) == 0
    assert cli.main(["verify", str(manifest), "--root", str(data)]) == 0

    (data / "f.txt").write_text("tampered")
    assert cli.main(["verify", str(manifest), "--root", str(data)]) == 1
