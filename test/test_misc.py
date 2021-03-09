import requests
import urlquick
import pytest
import sqlite3


@pytest.mark.parametrize("string", [b"test.string.bytes", "test.string.str", u"test.string.unicode"])
def test_to_bytes_string(string):
    value = urlquick.to_bytes_string(string)
    assert isinstance(value, bytes)


@pytest.mark.parametrize("method, url, body", (
    ("get", "https://httpbin.org/get", b""),
    ("head", "https://httpbin.org/get", b""),
    ("post", "https://httpbin.org/post", b"data"),
    ("post", "https://httpbin.org/post", "data"),
))
def test_hash_url(method, url, body):
    # Build Request object
    req = requests.PreparedRequest()
    req.prepare_method(method)
    req.prepare_url(url, None)
    req.prepare_headers(None)
    req.prepare_body(body, None, None)

    # Test function
    urlhash = urlquick.hash_url(req)
    assert isinstance(urlhash, str)
    assert len(urlhash) == 40


def test_sqlite3_error(mocker):
    mocker.patch("sqlite3.connect", side_effect=sqlite3.Error("Boom!"))
    with pytest.raises(urlquick.CacheError):
        urlquick.Session()


def test_sqlite3_operational_error(mocker):
    session = urlquick.Session()
    mocked = mocker.patch.object(session.cache_adapter, "conn", autospec=True)
    mocked.execute.side_effect = sqlite3.OperationalError("Boom!")

    with pytest.raises(sqlite3.OperationalError):
        session.cache_adapter.wipe()


def test_sqlite3_integrity_error(mocker):
    session = urlquick.Session()
    mocked = mocker.patch.object(session.cache_adapter, "conn", autospec=True)
    mocked.execute.side_effect = sqlite3.IntegrityError("file is encrypted")
    session.cache_adapter.wipe()


def test_cache_cleanup():
    with pytest.deprecated_call():
        urlquick.cache_cleanup()


def test_auto_cache_cleanup():
    with pytest.deprecated_call():
        urlquick.auto_cache_cleanup()
