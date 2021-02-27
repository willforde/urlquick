import urlquick
import requests
import shutil
import pytest
import time


@pytest.mark.parametrize("obj", [urlquick, urlquick.Session()])
class TestSessionClean(object):
    """Clean the database before each and every test."""

    # noinspection PyMethodMayBeStatic
    def setup_method(self):
        """Remove cache location before each test."""
        shutil.rmtree(urlquick.CACHE_LOCATION, ignore_errors=True)

    def test_get(self, obj, requests_mock):
        mocked = requests_mock.get('https://www.test.com/test/586', body=b"data")
        ret = obj.get('https://www.test.com/test/586')
        assert mocked.called
        assert ret.from_cache is False
        assert ret.content == b"data"
        assert ret.text == "data"

    def test_options(self, obj, requests_mock):
        mocked = requests_mock.options('https://www.test.com', json={"test": True})
        ret = obj.options('https://www.test.com')
        assert mocked.called
        assert ret.from_cache is False
        assert ret.json() == {"test": True}

    def test_head(self, obj, requests_mock):
        mocked = requests_mock.head('https://www.test.com', headers={"X-TEST": "12345"})
        ret = obj.head('https://www.test.com')
        assert mocked.called
        assert ret.from_cache is False
        assert ret.content == b""
        assert ret.text == ""
        assert "X-TEST" in ret.headers and ret.headers["X-TEST"] == "12345"

    def test_post(self, obj, requests_mock):
        mocked = requests_mock.post('https://www.test.com', json={"test": True}, data=b"test")
        ret = obj.post('https://www.test.com', data=b"test")
        assert mocked.called
        assert ret.from_cache is False
        assert ret.json() == {"test": True}

    def test_put(self, obj, requests_mock):
        mocked = requests_mock.put('https://www.test.com', json={"test": True})
        ret = obj.put('https://www.test.com')
        assert mocked.called
        assert ret.from_cache is False
        assert ret.json() == {"test": True}

    def test_patch(self, obj, requests_mock):
        mocked = requests_mock.patch('https://www.test.com', json={"test": True})
        ret = obj.patch('https://www.test.com')
        assert mocked.called
        assert ret.from_cache is False
        assert ret.json() == {"test": True}

    def test_delete(self, obj, requests_mock):
        mocked = requests_mock.delete('https://www.test.com', json={"test": True})
        ret = obj.delete('https://www.test.com')
        assert mocked.called
        assert ret.from_cache is False
        assert ret.json() == {"test": True}

    def test_headers_none(self, obj, requests_mock):
        mocked = requests_mock.get('https://www.test.com/50', json={"test": True})
        ret = obj.get('https://www.test.com/50', headers=None)
        assert mocked.called
        assert ret.from_cache is False
        assert ret.json() == {"test": True}


class TestSessionCaching(object):
    """Clean the database before each and every test."""

    # noinspection PyMethodMayBeStatic
    def setup_method(self):
        """Remove cache location before each test."""
        shutil.rmtree(urlquick.CACHE_LOCATION, ignore_errors=True)

    def test_cache(self, requests_mock):
        mocked = requests_mock.get('https://www.test.com/1', body=b"data")
        ret = urlquick.get('https://www.test.com/1')
        assert mocked.called
        assert ret.from_cache is False
        assert ret.content == b"data"
        mocked.reset_stats()

        ret = urlquick.get('https://www.test.com/1')
        assert not mocked.called
        assert ret.from_cache is True
        assert ret.content == b"data"

    def test_delay(self, requests_mock):
        mocked = requests_mock.get('https://www.test.com/1', body=b"data")
        ret = urlquick.get('https://www.test.com/1')
        assert mocked.called
        assert ret.from_cache is False
        assert ret.content == b"data"
        mocked.reset_stats()

        time.sleep(1.2)  # 1.2 seconds should be enough
        ret = urlquick.get('https://www.test.com/1', max_age=1)
        assert mocked.called
        assert ret.from_cache is False
        assert ret.content == b"data"

    def test_disable_flag(self, requests_mock):
        mocked = requests_mock.get('https://www.test.com/1', body=b"data")
        ret = urlquick.get('https://www.test.com/1')
        assert mocked.called
        assert ret.from_cache is False
        assert ret.content == b"data"
        mocked.reset_stats()

        ret = urlquick.get('https://www.test.com/1', max_age=-1)
        assert mocked.called
        assert ret.from_cache is False
        assert ret.content == b"data"

    def test_never_valid(self, requests_mock):
        mocked = requests_mock.get('https://www.test.com/1', body=b"data")
        ret = urlquick.get('https://www.test.com/1')
        assert mocked.called
        assert ret.from_cache is False
        assert ret.content == b"data"
        mocked.reset_stats()

        ret = urlquick.get('https://www.test.com/1', max_age=0)
        assert mocked.called
        assert ret.from_cache is False
        assert ret.content == b"data"

    def test_etag(self, requests_mock):
        mocked = requests_mock.get('https://www.test.com/1', body=b"data", headers={"Etag": "12345"})
        ret = urlquick.get('https://www.test.com/1')
        assert mocked.called
        assert ret.from_cache is False
        assert ret.content == b"data"
        mocked.reset_stats()

        ret = urlquick.get('https://www.test.com/1', max_age=0)
        assert mocked.called
        assert ret.from_cache is False
        assert ret.content == b"data"

    def test_last_modified(self, requests_mock):
        mocked = requests_mock.get('https://www.test.com/1', body=b"test 304", headers={"Last-modified": "12345"})
        ret = urlquick.get('https://www.test.com/1')  # Gets cached
        assert mocked.called
        assert ret.from_cache is False
        assert ret.content == b"test 304"

        mocked = requests_mock.get('https://www.test.com/1', headers={"Last-modified": "12345"}, status=304)
        ret = urlquick.get('https://www.test.com/1', max_age=0)
        assert mocked.called
        assert ret.from_cache is True
        assert ret.content == b"test 304"

    def test_wipe(self, requests_mock):
        mocked = requests_mock.get('https://www.test.com/1', body=b"data")
        session = urlquick.Session()

        ret = session.get('https://www.test.com/1')
        assert mocked.called
        assert ret.from_cache is False
        assert ret.content == b"data"
        mocked.reset_stats()

        # Wipe the cache clean
        session.cache_adapter.wipe()

        ret = session.get('https://www.test.com/1')
        assert mocked.called
        assert ret.from_cache is False
        assert ret.content == b"data"

    def test_delete(self, requests_mock):
        url = 'https://www.test.com/1'
        mocked = requests_mock.get(url, body=b"data")
        session = urlquick.Session()

        ret = session.get('https://www.test.com/1')
        assert mocked.called
        assert ret.from_cache is False
        assert ret.content == b"data"
        mocked.reset_stats()

        # Build Request object
        req = requests.PreparedRequest()
        req.prepare_method("GET")
        req.prepare_url(url, None)
        req.prepare_headers(None)
        req.prepare_body(b"", None, None)

        # Test del_cache
        urlhash = urlquick.hash_url(req)
        session.cache_adapter.del_cache(urlhash)

        ret = session.get('https://www.test.com/1')
        assert mocked.called
        assert ret.from_cache is False
        assert ret.content == b"data"


class TestRaiseForStatus(object):
    """Clean the database before each and every test."""

    # noinspection PyMethodMayBeStatic
    def setup_method(self):
        """Remove cache location before each test."""
        shutil.rmtree(urlquick.CACHE_LOCATION, ignore_errors=True)

    def test_false_normal(self, requests_mock):
        mocked = requests_mock.get('https://www.test.com/1', body=b"data", status=200)
        session = urlquick.Session()

        ret = session.get('https://www.test.com/1')
        assert mocked.called
        assert ret.from_cache is False
        assert ret.status_code == 200
        assert ret.content == b"data"

    def test_false_error(self, requests_mock):
        mocked = requests_mock.get('https://www.test.com/1', body=b"data", status=404)
        session = urlquick.Session()

        ret = session.get('https://www.test.com/1')
        assert mocked.called
        assert ret.from_cache is False
        assert ret.status_code == 404
        assert ret.content == b"data"

    def test_true_normal(self, requests_mock):
        mocked = requests_mock.get('https://www.test.com/1', body=b"data", status=200)
        session = urlquick.Session(raise_for_status=True)

        ret = session.get('https://www.test.com/1')
        assert mocked.called
        assert ret.from_cache is False
        assert ret.status_code == 200
        assert ret.content == b"data"

    def test_true_error(self, requests_mock):
        mocked = requests_mock.get('https://www.test.com/1', body=b"data", status=404)
        session = urlquick.Session(raise_for_status=True)

        with pytest.raises(urlquick.HTTPError):
            session.get('https://www.test.com/1')

        assert mocked.called


def test_session_send(requests_mock):
    shutil.rmtree(urlquick.CACHE_LOCATION, ignore_errors=True)

    url = 'https://www.test.com/1'
    mocked = requests_mock.get(url, body=b"data")
    session = urlquick.Session()

    # Build Request object
    req = requests.PreparedRequest()
    req.prepare_method("GET")
    req.prepare_url(url, None)
    req.prepare_headers(None)
    req.prepare_body(b"", None, None)

    ret = session.send(req)
    assert mocked.called
    assert ret.content == b"data"


def test_request_header_none(requests_mock):
    shutil.rmtree(urlquick.CACHE_LOCATION, ignore_errors=True)
    mocked = requests_mock.get('https://www.test.com/test/542', body=b"data")
    session = urlquick.Session()

    ret = session.request("GET", 'https://www.test.com/test/542', None, None, None)
    assert mocked.called
    assert ret.content == b"data"


def test_request_header_data(requests_mock):
    shutil.rmtree(urlquick.CACHE_LOCATION, ignore_errors=True)
    mocked = requests_mock.get('https://www.test.com/test/542', body=b"data")
    session = urlquick.Session()

    ret = session.request("GET", 'https://www.test.com/test/542', None, None, {"X-TEST": "test"})
    assert mocked.called
    assert ret.from_cache is False
    assert ret.content == b"data"


def test_session_method(requests_mock):
    shutil.rmtree(urlquick.CACHE_LOCATION, ignore_errors=True)
    mocked = requests_mock.get('https://www.test.com', body=b"data")
    session = urlquick.session()
    ret = session.get('https://www.test.com')
    assert mocked.called
    assert ret.from_cache is False
    assert ret.content == b"data"
    assert ret.text == "data"


def test_cache_unsupported_protocol(mocker, requests_mock):
    """Test that get_cache will clear the cache on error."""
    shutil.rmtree(urlquick.CACHE_LOCATION, ignore_errors=True)
    mocked_url_1 = requests_mock.get('https://www.test.com/1', body=b"test1")
    mocked_url_2 = requests_mock.get('https://www.test.com/2', body=b"test2")
    session = urlquick.Session()

    # Check that the mocked url is called
    ret = session.get('https://www.test.com/1')
    assert mocked_url_1.called
    assert ret.from_cache is False
    assert ret.content == b"test1"
    mocked_url_1.reset_stats()
    ret = session.get('https://www.test.com/2')
    assert mocked_url_2.called
    assert ret.from_cache is False
    assert ret.content == b"test2"
    mocked_url_2.reset_stats()

    # Should be cached now so mocked should not be called
    ret = session.get('https://www.test.com/1')
    assert not mocked_url_1.called
    assert ret.from_cache is True
    assert ret.content == b"test1"
    mocked_url_1.reset_stats()
    ret = session.get('https://www.test.com/2')
    assert not mocked_url_2.called
    assert ret.from_cache is True
    assert ret.content == b"test2"
    mocked_url_2.reset_stats()

    # Mock CacheRecord to raise ValueError
    mocked = mocker.patch("urlquick.CacheRecord")
    mocked.side_effect = ValueError("unsupported pickle protocol")

    # For a unsupported pickle protocol the whole cache is wiped so both should be called
    ret = session.get('https://www.test.com/1')
    assert mocked_url_1.called
    assert ret.from_cache is False
    assert ret.content == b"test1"
    mocked.stopall()
    # This should be called again
    ret = session.get('https://www.test.com/2')
    assert mocked_url_2.called
    assert ret.from_cache is False
    assert ret.content == b"test2"


def test_cache_unknown_error(mocker, requests_mock):
    """Test that get_cache will clear the cache on error."""
    shutil.rmtree(urlquick.CACHE_LOCATION, ignore_errors=True)
    mocked_url_1 = requests_mock.get('https://www.test.com/1', body=b"test1")
    mocked_url_2 = requests_mock.get('https://www.test.com/2', body=b"test2")
    session = urlquick.Session()

    # Check that the mocked url is called
    ret = session.get('https://www.test.com/1')
    assert mocked_url_1.called
    assert ret.from_cache is False
    assert ret.content == b"test1"
    mocked_url_1.reset_stats()
    ret = session.get('https://www.test.com/2')
    assert mocked_url_2.called
    assert ret.from_cache is False
    assert ret.content == b"test2"
    mocked_url_2.reset_stats()

    # Should be cached now so mocked should not be called
    ret = session.get('https://www.test.com/1')
    assert not mocked_url_1.called
    assert ret.from_cache is True
    assert ret.content == b"test1"
    mocked_url_1.reset_stats()
    ret = session.get('https://www.test.com/2')
    assert not mocked_url_2.called
    assert ret.from_cache is True
    assert ret.content == b"test2"
    mocked_url_2.reset_stats()

    # Mock CacheRecord to raise ValueError
    mocked = mocker.patch.object(urlquick, "CacheRecord")
    mocked.side_effect = ValueError("normal error")

    # For normal errors only the current cache item
    # will be remove but all the rest will stay
    ret = session.get('https://www.test.com/1')
    assert mocked_url_1.called
    assert ret.from_cache is False
    assert ret.content == b"test1"
    mocker.stopall()

    # This request should not be called again
    ret = session.get('https://www.test.com/2')
    assert not mocked_url_2.called
    assert ret.from_cache is True
    assert ret.content == b"test2"
