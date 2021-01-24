from pytest_mock import MockerFixture
import requests
import urlquick
import pytest
import io

from requests.adapters import HTTPResponse
from requests import adapters


class RequestsMock(object):
    def __init__(self, mocker):
        self.mocker = mocker
        self._store = {}

        def mock_send(self_mock, request, **_):
            urlid = urlquick.hash_url(request)
            assert urlid in self._store
            return self_mock.build_response(request, self._store[urlid])

        mocker.patch.object(adapters.HTTPAdapter, "send", mock_send)

    @staticmethod
    def build_urllib3_response(text="", **kwargs):  # type: (...) -> HTTPResponse
        # Alieas to some common params
        kwargs["body"] = io.BytesIO(urlquick.to_bytes_string(text))
        kwargs.setdefault("status", 200)
        kwargs.setdefault("reason", "OK")
        kwargs["preload_content"] = False
        kwargs["decode_content"] = False
        return HTTPResponse(**kwargs)

    def request(self, method, url, data=b"", **kwargs):  # type: (str, str, bytes, ...) -> None
        req = requests.PreparedRequest()
        req.prepare_method(method)
        req.prepare_url(url, None)
        req.prepare_headers(None)
        req.prepare_body(data, None, None)

        urlid = urlquick.hash_url(req)
        self._store[urlid] = self.build_urllib3_response(**kwargs)

    def get(self, url, **kwargs):  # type: (str, ...) -> None
        self.request("GET", url, **kwargs)


@pytest.fixture(scope="function")
def requests_mock(mocker):
    return RequestsMock(mocker)
