"""Tests for SHA-256 helpers and atime-preserving copy."""

from pathlib import Path

from ammit.integrity import copy_noatime, sha256_bytes, sha256_file

# Well-known SHA-256 vectors.
EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_sha256_bytes_known_vectors():
    assert sha256_bytes(b"") == EMPTY
    assert sha256_bytes(b"abc") == ABC


def test_sha256_file_matches_bytes(tmp_path: Path):
    p = tmp_path / "f.bin"
    p.write_bytes(b"abc")
    assert sha256_file(p) == ABC
    assert sha256_file(p) == sha256_bytes(b"abc")


def test_sha256_file_large_multichunk(tmp_path: Path):
    data = b"\xde\xad\xbe\xef" * 500_000  # ~2 MiB, spans read chunks
    p = tmp_path / "big.bin"
    p.write_bytes(data)
    assert sha256_file(p) == sha256_bytes(data)


def test_copy_noatime_preserves_content_and_size(tmp_path: Path):
    src = tmp_path / "src.bin"
    dst = tmp_path / "dst.bin"
    data = b"forensic-evidence\n" * 1000
    src.write_bytes(data)
    size = copy_noatime(src, dst)
    assert size == len(data)
    assert dst.read_bytes() == data
    assert sha256_file(dst) == sha256_file(src)
