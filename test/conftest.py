import requests
import urlquick
import pytest
import json as _json
import io

from requests import adapters


class MockResponse(object):
    """Mock response that keeps track of when or if the response was called."""
    def __init__(self, body="", json=None, **kwargs):
        if json is not None:
            body = _json.dumps(json)

        # Alieas to some common params
        self._body = body
        kwargs["body"] = io.BytesIO(urlquick.to_bytes_string(body))
        kwargs.setdefault("status", 200)
        kwargs.setdefault("reason", "OK")
        kwargs["preload_content"] = False
        kwargs["decode_content"] = False

        # Add mock headers
        headers = kwargs.setdefault("headers", {})
        headers.setdefault("Content-Type", "text/html; charset=utf8")
        self._kwargs = kwargs
        self._called = 0

    @property
    def response(self):
        """Return the response but increment called counter."""
        self._called += 1
        self._kwargs["body"] = io.BytesIO(urlquick.to_bytes_string(self._body))
        return HTTPResponse(**self._kwargs)

    @property
    def called(self):
        """State that the mock was called at least once."""
        return self._called > 0

    @property
    def called_once(self):
        """State that the mock was called exactly once."""
        return self._called == 1

    def reset_stats(self):
        """Reset the stats counters."""
        self._called = 0


class RequestsMock(object):
    """
    Mock requests HTTPAdapter.

    Example:

    def test(requests_mock):
        requests_mock.get('https://www.test.com', text="data")
        # Now you can run your tests
    """
    def __init__(self, mocker):
        self.mocker = mocker
        self._store = {}

        def mock_send(self_mock, request, **_):
            urlid = urlquick.hash_url(request)
            assert urlid in self._store, "There is no mock response for given method & url"
            return self_mock.build_response(request, self._store[urlid].response)

        mocker.patch.object(adapters.HTTPAdapter, "send", mock_send)

    def request(self, method, url, data=b"", **kwargs):  # type: (str, str, bytes, ...) -> MockResponse
        req = requests.PreparedRequest()
        req.prepare_method(method)
        req.prepare_url(url, None)
        req.prepare_headers(None)
        req.prepare_body(data, None, None)

        urlid = urlquick.hash_url(req)
        mock_response = MockResponse(**kwargs)
        self._store[urlid] = mock_response
        return mock_response

    def get(self, url, **kwargs):  # type: (str, ...) -> MockResponse
        return self.request("GET", url, **kwargs)

    def options(self, url, **kwargs):  # type: (str, ...) -> MockResponse
        return self.request("OPTIONS", url, **kwargs)

    def head(self, url, **kwargs):  # type: (str, ...) -> MockResponse
        return self.request("HEAD", url, **kwargs)

    def post(self, url, data=None, **kwargs):  # type: (...) -> MockResponse
        return self.request("POST", url, data, **kwargs)

    def put(self, url, data=None, **kwargs):  # type: (...) -> MockResponse
        return self.request("PUT", url, data, **kwargs)

    def patch(self, url, data=None, **kwargs):  # type: (...) -> MockResponse
        return self.request("PATCH", url, data, **kwargs)

    def delete(self, url, **kwargs):  # type: (...) -> MockResponse
        return self.request("DELETE", url, **kwargs)


@pytest.fixture(scope="function")
def requests_mock(mocker):
    return RequestsMock(mocker)
