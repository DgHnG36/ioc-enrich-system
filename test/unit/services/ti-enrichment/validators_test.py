import pytest

from utils.errors import EnrichmentError
from utils.validators import IoCValidator, validate_ioc


def test_validate_ip_valid():
    assert IoCValidator.validate_ip("8.8.8.8") is True


def test_validate_ip_invalid():
    assert IoCValidator.validate_ip("999.999.999.999") is False


def test_validate_domain_valid_with_www_prefix():
    assert IoCValidator.validate_domain("www.example.com") is True


def test_validate_hash_md5_valid():
    assert IoCValidator.validate_hash("d41d8cd98f00b204e9800998ecf8427e") is True


def test_validate_url_valid():
    assert IoCValidator.validate_url("https://example.com/path") is True


def test_validate_file_path_valid():
    assert IoCValidator.validate_file_path("/tmp/sample.txt") is True


def test_validate_ioc_success():
    validate_ioc("1.1.1.1", "ip")


def test_validate_ioc_invalid_type_raises():
    with pytest.raises(EnrichmentError) as exc:
        validate_ioc("1.1.1.1", "unknown_type")

    assert "Unsupported IoC type" in str(exc.value)


def test_validate_ioc_empty_raises():
    with pytest.raises(EnrichmentError) as exc:
        validate_ioc("", "ip")

    assert "cannot be empty" in str(exc.value)
