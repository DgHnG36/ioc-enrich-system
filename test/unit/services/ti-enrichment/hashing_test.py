from utils.hashing import (
    identify_hash_type,
    md5,
    normalize_hash,
    sha1,
    sha256,
    validate_hash,
)


def test_md5_sha1_sha256_known_values():
    assert md5("abc") == "900150983cd24fb0d6963f7d28e17f72"
    assert sha1("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d"
    assert sha256("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_identify_hash_type():
    assert identify_hash_type("d41d8cd98f00b204e9800998ecf8427e") == "md5"
    assert identify_hash_type("a9993e364706816aba3e25717850c26c9cd0d89d") == "sha1"
    assert identify_hash_type("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == "sha256"


def test_identify_hash_type_invalid():
    assert identify_hash_type("not-a-hash") is None


def test_validate_hash():
    assert validate_hash("d41d8cd98f00b204e9800998ecf8427e", "md5") is True
    assert validate_hash("d41d8cd98f00b204e9800998ecf8427e", "sha256") is False


def test_normalize_hash():
    assert normalize_hash("  ABCDEF  ") == "abcdef"
