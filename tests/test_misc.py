import requests
import urlquick
import pytest


@pytest.mark.parametrize("string", [b"test.string.bytes", "test.string.str", u"test.string.unicode"])
def test_to_bytes_string(string):
    value = urlquick.to_bytes_string(string)
    assert isinstance(value, bytes)


@pytest.mark.parametrize("method, url, body", (
    ("get", "https://httpbin.org/get", b""),
    ("head", "https://httpbin.org/get", b""),
    ("post", "https://httpbin.org/post", b"data")
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
