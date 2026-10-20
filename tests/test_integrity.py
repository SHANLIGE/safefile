import hashlib

import pytest

from safefile.errors import ManifestError
from safefile.integrity import Status, build_manifest, hash_file, parse_manifest, verify_manifest


@pytest.fixture
def sample_dir(tmp_path):
    (tmp_path / "a.txt").write_text("hello")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.bin").write_bytes(bytes(range(256)))
    return tmp_path


@pytest.mark.parametrize("algorithm", ["sha256", "sha512", "sha3_256", "blake2b"])
def test_hash_matches_hashlib(tmp_path, algorithm):
    f = tmp_path / "x"
    f.write_bytes(b"test content" * 1000)
    assert hash_file(f, algorithm) == hashlib.new(algorithm, f.read_bytes()).hexdigest()


def test_rejects_weak_algorithms(tmp_path):
    f = tmp_path / "x"
    f.write_bytes(b"")
    with pytest.raises(ValueError):
        hash_file(f, "md5")


def test_manifest_uses_relative_posix_paths(sample_dir):
    names = [name for _, name in parse_manifest(build_manifest(sample_dir))]
    assert names == ["a.txt", "sub/b.bin"]


def test_verify_all_ok(sample_dir):
    results = verify_manifest(sample_dir, build_manifest(sample_dir))
    assert all(r.status is Status.OK for r in results)


def test_verify_detects_modified_and_missing(sample_dir):
    manifest = build_manifest(sample_dir)
    (sample_dir / "a.txt").write_text("hello!")
    (sample_dir / "sub" / "b.bin").unlink()

    statuses = {r.path: r.status for r in verify_manifest(sample_dir, manifest)}
    assert statuses == {"a.txt": Status.MODIFIED, "sub/b.bin": Status.MISSING}


def test_compatible_with_sha256sum_binary_mode(sample_dir):
    digest = hash_file(sample_dir / "a.txt")
    results = verify_manifest(sample_dir, f"{digest} *a.txt\n")
    assert results[0].status is Status.OK


def test_path_traversal_is_rejected(sample_dir):
    evil = f"{'0' * 64}  ../../etc/passwd\n"
    with pytest.raises(ManifestError):
        verify_manifest(sample_dir, evil)


def test_malformed_line(sample_dir):
    with pytest.raises(ManifestError):
        parse_manifest("this is not a manifest\n")


def test_manifest_excludes_itself(sample_dir):
    out = sample_dir / "MANIFEST.sha256"
    out.write_text("")
    assert "MANIFEST" not in build_manifest(sample_dir, exclude=[out])
