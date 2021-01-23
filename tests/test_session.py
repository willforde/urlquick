import requests
import urlquick
import pytest


def test_get(requests_mock):
    requests_mock.get('http://test.com', text='data')
    ret = urlquick.get('http://test.com')
    assert ret.text == "data"
