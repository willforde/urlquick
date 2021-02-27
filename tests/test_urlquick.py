#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import urlquick
import types
import socket
import base64
import json
import sys
import os
import io
import time
import zlib
import logging
import ssl
from random import random
from functools import wraps
from collections import OrderedDict, defaultdict

if urlquick.py3:
    unicode = str
    from gzip import compress as gzip_compress
else:
    from gzip import GzipFile

    def gzip_compress(data, compresslevel=4):
        """Compress data in one shot and return the compressed string.
        Optional argument is the compression level, in range of 0-9.
        """
        buf = io.BytesIO()
        with GzipFile(fileobj=buf, mode='wb', compresslevel=compresslevel) as f:
            f.write(data)
        return buf.getvalue()

logger = urlquick.logger
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
logger.addHandler(ch)


class TestMisc(unittest.TestCase):
    def test_cache_property(self):
        class Cache(object):
            @urlquick.CachedProperty
            def worker(self):
                return random()

        work = Cache()
        # Test that working return a random float
        ret = work.worker
        self.assertTrue(0 < ret < 1)

        # Test the a seccond request returns the same value
        self.assertEqual(work.worker, ret)

        # Test that a new value is return when cache is deleted
        del work.worker
        self.assertNotEqual(work.worker, ret)

        # Test that the setter failes as setter was not enabled
        with self.assertRaises(AttributeError):
            work.worker = 321

    def test_cache_property_setter(self):
        class Cache(object):
            @urlquick.CachedProperty
            def worker(self):
                return random()

            # Enable setter
            worker.allow_setter = True

        work = Cache()
        # Test the setter works and does not raise AttributeError
        work.worker = 321

        # Now test that the value that is returned is what was set and not a random one.
        self.assertEqual(work.worker, 321)

        # Test that a new value is return when cache is deleted
        del work.worker
        self.assertNotEqual(work.worker, 321)

    def test_UnicodeDict(self):
        test_dict1 = {u"test1": u"work1", "test2": "work2", "num": 3}
        test_dict2 = {"test3": u"work3", u"test4": "work4"}
        test_dict3 = {"test5": None}
        test_dict = urlquick.UnicodeDict(test_dict1, test_dict2, test_dict3)

        # Check that all items are unicode
        for key, value in test_dict.items():
            self.assertIsInstance(key, unicode)
            self.assertIsInstance(value, unicode)

    def test_httperror(self):
        test = urlquick.HTTPError("https://httpbin.org/get", 404, "Not Found", {"testing": "yes"})
        self.assertEqual(str(test), "HTTP Client Error 404: Not Found")


class TestPy2Functions(unittest.TestCase):
    def test_quote(self):
        text = urlquick.quote(u"testing&testing")
        self.assertEqual(text, u"testing%26testing")

    def test_unquote(self):
        text = urlquick.unquote(u"testing%26testing")
        self.assertEqual(text, u"testing&testing")

    def test_parse_qsl(self):
        ret = urlquick.parse_qsl(u"test=yes&work=true")
        self.assertEqual(ret, [(u"test", u"yes"), (u"work", u"true")])

    def test_urlencode_list(self):
        test_list = [(u"test", u"yes"), (u"work", u"true")]
        ret = urlquick.urlencode(test_list)
        self.assertEqual(ret, u"test=yes&work=true")

    def test_urlencode_dict(self):
        test_dict = OrderedDict([(u"test", u"yes"), (u"work", u"true")])
        ret = urlquick.urlencode(test_dict)
        self.assertEqual(ret, u"test=yes&work=true")

    def test_urlencode_list_with_list(self):
        test_list = [(u"test", [u"test1", u"test2"]), (u"work", u"true")]
        ret = urlquick.urlencode(test_list)
        self.assertEqual(ret, u"test=%5B%27test1%27%2C+%27test2%27%5D&work=true")

    def test_urlencode_dict_with_list(self):
        test_dict = OrderedDict([(u"test", [u"test1", u"test2"]), (u"work", u"true")])
        ret = urlquick.urlencode(test_dict)
        self.assertEqual(ret, u"test=%5B%27test1%27%2C+%27test2%27%5D&work=true")

    def test_urlencode_list_with_list_doseq(self):
        test_list = [(u"test", [u"test1", u"test2"]), (u"work", u"true")]
        ret = urlquick.urlencode(test_list, doseq=True)
        self.assertEqual(ret, u"test=test1&test=test2&work=true")

    def test_urlencode_dict_with_list_doseq(self):
        test_dict = OrderedDict([(u"test", [u"test1", u"test2"]), (u"work", u"true")])
        ret = urlquick.urlencode(test_dict, doseq=True)
        self.assertEqual(ret, u"test=test1&test=test2&work=true")


class TestCaseInsensitiveDict(unittest.TestCase):
    def test_init(self):
        headers = urlquick.CaseInsensitiveDict()
        self.assertTrue(not headers)

    def test_init_args(self):
        headers = urlquick.CaseInsensitiveDict({u"key1": u"value1"}, {"key2": "value2"})
        self.assertTrue(u"key1" in headers)
        self.assertTrue(u"key2" in headers)
        self.assertEqual(headers[u"key1"], u"value1")
        self.assertEqual(headers[u"key2"], u"value2")

    def test_assign_unicode(self):
        headers = urlquick.CaseInsensitiveDict()
        headers[u"key"] = u"value"
        self.assertTrue(u"key" in headers)
        self.assertEqual(headers[u"key"], u"value")

    def test_assign_bytes(self):
        headers = urlquick.CaseInsensitiveDict()
        headers[b"key"] = b"value"
        self.assertTrue(u"key" in headers)
        self.assertEqual(headers[u"key"], u"value")

    def test_assign_none(self):
        headers = urlquick.CaseInsensitiveDict()
        headers[b"key"] = None
        self.assertFalse(u"key" in headers)

    def test_len(self):
        headers = urlquick.CaseInsensitiveDict({u"key1": u"value1"})
        self.assertEqual(len(headers), 1)

    def test_copy(self):
        headers = urlquick.CaseInsensitiveDict({u"key1": u"value1"}).copy()
        self.assertIsInstance(headers, urlquick.CaseInsensitiveDict)

    def test_iter(self):
        headers = urlquick.CaseInsensitiveDict({u"key1": u"value1", "key2": "value2"})
        ret = list(iter(headers))
        self.assertIsInstance(ret, list)
        self.assertTrue(u"key1" in ret)
        self.assertTrue(u"key2" in ret)

    def test_repr(self):
        headers = urlquick.CaseInsensitiveDict({u"key1": u"value1", "key2": "value2"})
        test = repr(headers)
        self.assertTrue("key1" in test)
        self.assertTrue("value1" in test)
        self.assertTrue("key2" in test)
        self.assertTrue("value2" in test)


class TestCacheHandler(unittest.TestCase):
    class create(object):
        def __init__(self, url, max_age=14400, body=u"", headers=None, status=200, reason=u"OK"):
            response = {u"body": body, u"headers": headers, u"status": status, u"reason": reason,
                        u"version": 11, u"strict": True}
            response[u"body"] = response[u"body"].encode("utf8")

            # Base64 encode the body to make it json serializable
            response[u"body"] = base64.b64encode(response[u"body"]).decode("ascii")
            if response[u"headers"]:
                response[u"headers"] = dict(response[u"headers"])

            if isinstance(url, unicode):
                url = url.encode("utf8")

            hash_url = urlquick.CacheHandler.hash_url(url)
            path = urlquick.CacheHandler.cache_dir()
            cache_file = os.path.join(path, hash_url)

            # Save the response to disk using json Serialization
            with open(cache_file, "w") as stream:
                json.dump(response, stream, indent=4, separators=(",", ":"))

            print(cache_file)
            self.cache = urlquick.CacheHandler(hash_url, max_age)

        def __enter__(self):
            return self.cache

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.cache.delete(self.cache.cache_file)

    def test_cache_dir(self):
        def exists(*args):
            return False
        def makedirs(*args):
            pass

        _exists = os.path.exists
        _makedirs = os.makedirs
        os.path.exists = exists
        os.makedirs = makedirs

        try:
            path = urlquick.CacheHandler.cache_dir()
            self.assertTrue(bool(path))
        finally:
            os.path.exists = _exists
            os.makedirs = _makedirs

    def test_isfilefresh(self):
        fresh = urlquick.CacheHandler.isfilefresh(__file__, 0)
        self.assertFalse(fresh)
        fresh = urlquick.CacheHandler.isfilefresh(__file__, 999999999)
        self.assertTrue(fresh)

    def test_init(self):
        with self.create("https://httpbin.org/get"):
            pass

    def test_always_fresh_status(self):
        with self.create("https://httpbin.org/get", status=301) as cache:
            self.assertTrue(cache.isfresh())

    def test_always_fresh_maxage(self):
        with self.create("https://httpbin.org/get", -1) as cache:
            self.assertFalse(cache.isfresh())

    def test_isfilefresh_yes(self):
        with self.create("https://httpbin.org/get", 999999999) as cache:
            self.assertTrue(cache.isfresh())

    def test_isfilefresh_no(self):
        with self.create("https://httpbin.org/get", 0) as cache:
            self.assertFalse(cache.isfresh())

    def test_reset_timestamp(self):
        with self.create("https://httpbin.org/get") as cache:
            before_reset = os.stat(cache.cache_file).st_mtime
            time.sleep(.1)
            cache.reset_timestamp()
            after_reset = os.stat(cache.cache_file).st_mtime
            self.assertNotEqual(before_reset, after_reset)

    def test_conditional_headers_etag(self):
        headers = urlquick.CaseInsensitiveDict({"Etag": "lksjdfoiwjlksh"})
        with self.create("https://httpbin.org/get", headers=headers) as cache:
            req_headers = urlquick.CaseInsensitiveDict()
            cache.add_conditional_headers(req_headers)
            self.assertTrue("If-none-match" in req_headers)
            self.assertEqual(req_headers["If-none-match"], "lksjdfoiwjlksh")

    def test_conditional_headers_modified(self):
        headers = urlquick.CaseInsensitiveDict({"Last-modified": "Wed, 21 Oct 2015 07:28:00 GMT"})
        with self.create("https://httpbin.org/get", headers=headers) as cache:
            req_headers = urlquick.CaseInsensitiveDict()
            cache.add_conditional_headers(req_headers)
            self.assertTrue("If-modified-since" in req_headers)
            self.assertEqual(req_headers["If-modified-since"], "Wed, 21 Oct 2015 07:28:00 GMT")

    def test_conditional_headers_both(self):
        headers = urlquick.CaseInsensitiveDict({"Etag": "lksjdfoiwjlksh", "Last-modified": "Wed, 21 Oct 2015 07:28:00 GMT"})
        with self.create("https://httpbin.org/get", headers=headers) as cache:
            req_headers = urlquick.CaseInsensitiveDict()
            cache.add_conditional_headers(req_headers)
            self.assertTrue("If-none-match" in req_headers)
            self.assertEqual(req_headers["If-none-match"], "lksjdfoiwjlksh")
            self.assertTrue("If-modified-since" in req_headers)
            self.assertEqual(req_headers["If-modified-since"], "Wed, 21 Oct 2015 07:28:00 GMT")

    def assert_url_hash_Equal(self, url_hash, check):
        self.assertEqual(url_hash, urlquick.CacheHandler.safe_path(check))

    def test_hash_url_unicode(self):
        hashurl = urlquick.CacheHandler.hash_url(u"https://httpbin.org/get")
        self.assert_url_hash_Equal(hashurl, "cache-eadd3f1d0242ca5f05c4c7b89188df7eadc72976")

    def test_hash_url_bytes(self):
        hashurl = urlquick.CacheHandler.hash_url(b"https://httpbin.org/get")
        self.assert_url_hash_Equal(hashurl, "cache-eadd3f1d0242ca5f05c4c7b89188df7eadc72976")

    def test_hash_url_data_unicode(self):
        hashurl = urlquick.CacheHandler.hash_url("https://httpbin.org/get", data=u"data")
        self.assert_url_hash_Equal(hashurl, "cache-da991148ea2a035a6f4204b33265ac70b42b0c4b")

    def test_hash_url_data_bytes(self):
        hashurl = urlquick.CacheHandler.hash_url("https://httpbin.org/get", data=b"data")
        self.assert_url_hash_Equal(hashurl, "cache-da991148ea2a035a6f4204b33265ac70b42b0c4b")

    def test_failed_delete(self):
        def remove(*args, **kwargs):
            raise OSError

        # Check that a failed delete, don't raise an error
        _remove = os.remove
        os.remove = remove

        try:
            with self.create("https://httpbin.org/get") as cache:
                cache.delete(cache.cache_file)
        finally:
            os.remove = _remove

    def test_load_TypeError(self):
        def load(*args, **kwargs):
            raise TypeError

        _load = json.load
        json.load = load
        try:
            with self.create("https://httpbin.org/get") as cache:
                self.assertIsNone(cache.response)
        finally:
            json.load = _load

    def test_load_OSError(self):
        def load(*args, **kwargs):
            raise OSError

        _load = json.load
        json.load = load
        try:
            with self.create("https://httpbin.org/get") as cache:
                self.assertIsNone(cache.response)
        finally:
            json.load = _load

    def test_save_TypeError(self):
        def dump(*args, **kwargs):
            raise TypeError

        _dump = json.dump
        json.dump = dump

        url = urlquick.CacheHandler.hash_url("https://httpbin.org/get")
        cache = urlquick.CacheHandler(url)

        try:
            cache.update({}, b"data", 200, "OK")
            self.assertFalse(os.path.exists(cache.cache_file))
        finally:
            json.dump = _dump

    def test_save_OSError(self):
        def dump(*args, **kwargs):
            raise OSError

        _dump = json.dump
        json.dump = dump

        url = urlquick.CacheHandler.hash_url("https://httpbin.org/get")
        cache = urlquick.CacheHandler(url)

        try:
            cache.update({}, b"data", 200, "OK")
            self.assertFalse(os.path.exists(cache.cache_file))
        finally:
            json.dump = _dump

    def test_update_transfer_encoding(self):
        url = urlquick.CacheHandler.hash_url("https://httpbin.org/get")
        cache = urlquick.CacheHandler(url)

        cache.update({"Transfer-Encoding": "true"}, b"data", 200, "OK")
        self.assertFalse("Transfer-Encoding" in cache.response.headers)

    def test_update_case_headers(self):
        url = urlquick.CacheHandler.hash_url("https://httpbin.org/get")
        cache = urlquick.CacheHandler(url)

        headers = urlquick.CaseInsensitiveDict({"Transfer-Encoding": "true"})
        cache.update(headers, b"data", 200, "OK")
        self.assertFalse("Transfer-Encoding" in cache.response.headers)

    def test_cleanup_no_max_age(self):
        with self.create("https://httpbin.org/get") as cache:
            # Check that no error is raised
            urlquick.cache_cleanup(0)
            self.assertFalse(os.path.exists(cache.cache_file))

    def test_cleanup_max_age(self):
        with self.create("https://httpbin.org/get") as cache:
            # Check that no error is raised
            urlquick.cache_cleanup(99999999)
            self.assertTrue(os.path.exists(cache.cache_file))

    def test_cleanup_invalid_file(self):
        cache_dir = urlquick.CacheHandler.cache_dir()
        tempfile = os.path.join(cache_dir, urlquick.CacheHandler.safe_path("temp.tmp"))
        open(tempfile, 'a').close()

        try:
            with self.create("https://httpbin.org/get") as cache:
                # Check that no error is raised
                urlquick.cache_cleanup(0)
                self.assertFalse(os.path.exists(cache.cache_file))
        finally:
            os.remove(tempfile)

    def test_cache_check_fresh(self):
        with self.create("https://httpbin.org/get"):
            cache = urlquick.CacheAdapter()
            ret = cache.cache_check("GET", "https://httpbin.org/get", None, {})
            self.assertIsInstance(ret, urlquick.CacheResponse)

    def test_cache_check_stale(self):
        headers = {u"x-max-age": 0}
        with self.create("https://httpbin.org/get"):
            cache = urlquick.CacheAdapter()
            ret = cache.cache_check("GET", "https://httpbin.org/get", None, headers)
            self.assertIsNone(ret)

    def test_cache_check_no_cache(self):
        cache = urlquick.CacheAdapter()
        ret = cache.cache_check("GET", "https://httpbin.org/get", None, {})
        self.assertIsNone(ret)

    def test_cache_check_put(self):
        with self.create("https://httpbin.org/get") as _cache:
            cache = urlquick.CacheAdapter()
            ret = cache.cache_check("PUT", "https://httpbin.org/get", None, {})
            self.assertIsNone(ret)
            self.assertFalse(os.path.exists(_cache.cache_file))

    def test_cache_check_delete(self):
        with self.create("https://httpbin.org/get") as _cache:
            cache = urlquick.CacheAdapter()
            ret = cache.cache_check("DELETE", "https://httpbin.org/get", None, {})
            self.assertIsNone(ret)
            self.assertFalse(os.path.exists(_cache.cache_file))

    def test_cache_check_options(self):
        with self.create("https://httpbin.org/get"):
            cache = urlquick.CacheAdapter()
            ret = cache.cache_check("OPTIONS", "https://httpbin.org/get", None, {})
            self.assertIsNone(ret)

    def test_handle_response_304(self):
        with self.create("https://httpbin.org/get"):
            cache = urlquick.CacheAdapter()
            cache.cache_check("GET", "https://httpbin.org/get", None, {})
            ret = cache.handle_response("GET", 304, lambda: True)
            self.assertIsInstance(ret, urlquick.CacheResponse)

    def test_handle_response_200(self):
        callback = lambda: ({}, b"", 200, "OK")
        with self.create("https://httpbin.org/get"):
            cache = urlquick.CacheAdapter()
            cache.cache_check("GET", "https://httpbin.org/get", None, {})
            ret = cache.handle_response("GET", 200, callback)
            self.assertIsInstance(ret, urlquick.CacheResponse)

    def test_handle_response_404(self):
        callback = lambda: ({}, b"", 404, "OK")
        with self.create("https://httpbin.org/get"):
            cache = urlquick.CacheAdapter()
            cache.cache_check("GET", "https://httpbin.org/get", None, {})
            ret = cache.handle_response("GET", 404, callback)
            self.assertIsNone(ret)

    def test_save_path_uni(self):
        ret = urlquick.CacheHandler.safe_path(u"testpath")
        if sys.platform.startswith("win"):
            self.assertIsInstance(ret, unicode)
        else:
            self.assertIsInstance(ret, bytes)

    def test_save_path_force_win(self):
        org = sys.platform
        try:
            sys.platform = "win32"
            ret = urlquick.CacheHandler.safe_path(u"testpath")
        finally:
            sys.platform = org

        self.assertIsInstance(ret, unicode)


class TestRequest(unittest.TestCase):
    def test_with_host(self):
        headers = urlquick.CaseInsensitiveDict()
        headers["host"] = "httpbin.org"
        req = urlquick.Request("get", "https://httpbin.org/get", headers)
        self.assertTrue("host" in req.headers)

    def test_without_host(self):
        req = urlquick.Request("get", "https://httpbin.org/get", urlquick.CaseInsensitiveDict())
        self.assertTrue("host" in req.headers)

    def test_url(self):
        req = urlquick.Request("get", "https://httpbin.org/get", urlquick.CaseInsensitiveDict())
        self.assertEqual(req.url, "https://httpbin.org/get")

    def test_url_ascii_path(self):
        req = urlquick.Request("get", "https://httpbin.org/get", urlquick.CaseInsensitiveDict())
        self.assertEqual(req.url, "https://httpbin.org/get")

    def test_url_non_ascii_path(self):
        req = urlquick.Request("get", u"https://httpbin.org/\u0278", urlquick.CaseInsensitiveDict())
        self.assertEqual(req.url, u"https://httpbin.org/%C9%B8")

    def test_url_query(self):
        req = urlquick.Request("get", "https://httpbin.org/get?test=yes", urlquick.CaseInsensitiveDict())
        self.assertEqual(req.url, "https://httpbin.org/get?test=yes")

    def test_url_query_empty_param(self):
        req = urlquick.Request("get", "https://httpbin.org/get?test=yes&q=", urlquick.CaseInsensitiveDict())
        self.assertEqual(req.url, "https://httpbin.org/get?test=yes&q=")

    def test_url_query_nont_ascii(self):
        req = urlquick.Request("get", u"https://httpbin.org/get?test=\u0278", urlquick.CaseInsensitiveDict())
        self.assertEqual(req.url, u"https://httpbin.org/get?test=%C9%B8")

    def test_url_params(self):
        req = urlquick.Request("get", "https://httpbin.org/get", urlquick.CaseInsensitiveDict(), params={"test":"yes"})
        self.assertEqual(req.url, "https://httpbin.org/get?test=yes")

    def test_url_query_with_params(self):
        req = urlquick.Request("get", "https://httpbin.org/get?test=yes", urlquick.CaseInsensitiveDict(), params={"work":"yes"})
        self.assertEqual(req.url, "https://httpbin.org/get?test=yes&work=yes")

    def test_url_referer(self):
        req = urlquick.Request("get", "/get", urlquick.CaseInsensitiveDict(), referer="https://httpbin.org")
        self.assertEqual(req.url, "https://httpbin.org/get")

    def test_url_no_http(self):
        req = urlquick.Request("get", "://httpbin.org/get", urlquick.CaseInsensitiveDict())
        self.assertEqual(req.url, "http://httpbin.org/get")

    def test_url_no_http_diff(self):
        req = urlquick.Request("get", "//httpbin.org/get", urlquick.CaseInsensitiveDict())
        self.assertEqual(req.url, "http://httpbin.org/get")

    def test_host_idna(self):
        req = urlquick.Request("get", u"http://ドメイン.テスト/get", urlquick.CaseInsensitiveDict())
        self.assertEqual(req.url, "http://xn--eckwd4c7c.xn--zckzah/get")

    def test_url_auth(self):
        req = urlquick.Request("get", "https://user:pass@httpbin.org/get", urlquick.CaseInsensitiveDict())
        self.assertEqual(req.url, "https://httpbin.org/get")
        self.assertIsNotNone(req.auth)
        self.assertTupleEqual(req.auth, ("user","pass"))

    def test_url_auth_no_pass(self):
        req = urlquick.Request("get", "https://user@httpbin.org/get", urlquick.CaseInsensitiveDict())
        self.assertEqual(req.url, "https://httpbin.org/get")
        self.assertIsNotNone(req.auth)
        self.assertTupleEqual(req.auth, ("user",""))

    def test_json(self):
        json_data = {"test":"work"}
        req = urlquick.Request("get", "/get", urlquick.CaseInsensitiveDict(), json=json_data, referer="https://httpbin.org")
        self.assertEqual(req.data, b'{"test": "work"}')
        self.assertTrue("Content-Type" in req.headers)
        self.assertEqual(req.headers["Content-Type"], "application/json")
        self.assertTrue("Content-Length" in req.headers)
        self.assertEqual(req.headers["Content-Length"], "16")

    def test_data(self):
        data = "testing"
        req = urlquick.Request("get", "/get", urlquick.CaseInsensitiveDict(), data=data, referer="https://httpbin.org")
        self.assertEqual(req.data, b'testing')
        self.assertTrue("Content-Length" in req.headers)
        self.assertEqual(req.headers["Content-Length"], "7")

    def test_data_len(self):
        data = "testing"
        headers = urlquick.CaseInsensitiveDict()
        headers["Content-Length"] = "7"
        req = urlquick.Request("get", "/get", headers, data=data, referer="https://httpbin.org")
        self.assertEqual(req.data, b'testing')
        self.assertTrue("Content-Length" in req.headers)
        self.assertEqual(req.headers["Content-Length"], "7")

    def test_data_dict(self):
        data = {"test":"work"}
        req = urlquick.Request("get", "/get", urlquick.CaseInsensitiveDict(), data=data, referer="https://httpbin.org")
        self.assertEqual(req.data, b'test=work')
        self.assertTrue("Content-Type" in req.headers)
        self.assertEqual(req.headers["Content-Type"], "application/x-www-form-urlencoded")
        self.assertTrue("Content-Length" in req.headers)
        self.assertEqual(req.headers["Content-Length"], "9")

    def test_data_with_header_set(self):
        data = {"test": "work"}
        req = urlquick.Request("get", "/get", urlquick.CaseInsensitiveDict(), data=data, referer="https://httpbin.org")
        self.assertEqual(req.data, b'test=work')
        self.assertTrue("Content-Type" in req.headers)
        self.assertEqual(req.headers["Content-Type"], "application/x-www-form-urlencoded")
        self.assertTrue("Content-Length" in req.headers)
        self.assertEqual(req.headers["Content-Length"], "9")

    def test_mehtod_upper(self):
        req = urlquick.Request("get", "https://httpbin.org/get", urlquick.CaseInsensitiveDict())
        self.assertEqual(req.method, "GET")

    def test_selector_without_query(self):
        req = urlquick.Request("get", "https://httpbin.org/get", urlquick.CaseInsensitiveDict())
        self.assertEqual(req.selector, "/get")

    def test_selector_with_query(self):
        req = urlquick.Request("get", "https://httpbin.org/get?test=yes", urlquick.CaseInsensitiveDict())
        self.assertEqual(req.selector, "/get?test=yes")

    def test_header_items(self):
        test_dict = {u"test1": u"work1", "test2": "work2", "num": 3}
        req = urlquick.Request("get", "https://httpbin.org/get", urlquick.CaseInsensitiveDict(test_dict))

        # Check that all items are converted to str type of python version
        for key, value in req.header_items():
            self.assertIsInstance(key, str)
            self.assertIsInstance(value, str)

    def test_invalid_scheme(self):
        with self.assertRaisesRegexp(ValueError, "Unsupported scheme"):
            urlquick.Request("GET", "htsp://httpbin.org/get", urlquick.CaseInsensitiveDict())


class TestConnectionManager(unittest.TestCase):
    org_HTTPConnection = org_HTTPSConnection = None

    class Response(object):
        will_close = False

    class HTTPConnection(object):
        def __init__(self, *args, **kwargs):
            self.headers = defaultdict(list)
            self.selector = None
            self.method = None
            self.data = None
            self.fail = kwargs.get("fail", None)

        def putrequest(self, method, selector, skip_host=1, skip_accept_encoding=1):
            self.selector = selector
            self.method = method

        def putheader(self, header, value):
            count = 1
            if header.lower() in self.headers:
                count += len(self.headers[header.lower()])
            self.headers[header.lower()].append(value)

        def endheaders(self, message_body):
            self.data = message_body
            if self.fail:
                raise self.fail

        def getresponse(self):
            return TestConnectionManager.Response()

        def close(self):
            pass

    @classmethod
    def setUpClass(cls):
        cls.org_HTTPConnection = urlquick.HTTPConnection
        cls.org_HTTPSConnection = urlquick.HTTPSConnection
        urlquick.HTTPConnection = cls.HTTPConnection
        urlquick.HTTPSConnection = cls.HTTPConnection

    @classmethod
    def tearDownClass(cls):
        urlquick.HTTPConnection = cls.org_HTTPConnection
        urlquick.HTTPSConnection = cls.org_HTTPSConnection

    def test_connect(self):
        req = urlquick.Request("GET", "https://httpbin.org/get", urlquick.CaseInsensitiveDict())
        cm = urlquick.ConnectionManager()
        resp = cm.connect(req, 10, True)

        self.assertIsInstance(resp, self.Response)
        self.assertTrue("httpbin.org" in cm.request_handler["https"])
        self.assertIsInstance(cm.request_handler["https"]["httpbin.org"], self.HTTPConnection)

    def test_connect_unverify(self):
        req = urlquick.Request("GET", "https://httpbin.org/get", urlquick.CaseInsensitiveDict())
        cm = urlquick.ConnectionManager()
        resp = cm.connect(req, 10, False)

        self.assertIsInstance(resp, self.Response)
        self.assertTrue("httpbin.org" in cm.request_handler["https"])
        self.assertIsInstance(cm.request_handler["https"]["httpbin.org"], self.HTTPConnection)

    def test_connect_unverify_http(self):
        req = urlquick.Request("GET", "http://httpbin.org/get", urlquick.CaseInsensitiveDict())
        cm = urlquick.ConnectionManager()
        resp = cm.connect(req, 10, False)

        self.assertIsInstance(resp, self.Response)
        self.assertTrue("httpbin.org" in cm.request_handler["http"])
        self.assertIsInstance(cm.request_handler["http"]["httpbin.org"], self.HTTPConnection)

    def test_connect_will_close(self):
        req = urlquick.Request("GET", "https://httpbin.org/get", urlquick.CaseInsensitiveDict())
        self.Response.will_close = True
        try:
            cm = urlquick.ConnectionManager()
            resp = cm.connect(req, 10, True)

            self.assertIsInstance(resp, self.Response)
            self.assertFalse("httpbin.org" in cm.request_handler["https"])
        finally:
            self.Response.will_close = False

    def test_connect_reuse_good(self):
        req = urlquick.Request("GET", "https://httpbin.org/get", urlquick.CaseInsensitiveDict())
        cm = urlquick.ConnectionManager()
        cm.request_handler["https"]["httpbin.org"] = self.HTTPConnection()
        resp = cm.connect(req, 10, True)
        self.assertIsInstance(resp, self.Response)

    def test_connect_reuse_bad(self):
        req = urlquick.Request("GET", "https://httpbin.org/get", urlquick.CaseInsensitiveDict())
        cm = urlquick.ConnectionManager()
        cm.request_handler["https"]["httpbin.org"] = self.HTTPConnection(fail=urlquick.HTTPException)
        self.Response.will_close = True
        try:
            resp = cm.connect(req, 10, True)
            self.assertIsInstance(resp, self.Response)
            self.assertFalse("httpbin.org" in cm.request_handler["https"])
        finally:
            self.Response.will_close = False

    def test_connect_reuse_ugly(self):
        req = urlquick.Request("GET", "https://httpbin.org/get", urlquick.CaseInsensitiveDict())
        cm = urlquick.ConnectionManager()
        cm.request_handler["https"]["httpbin.org"] = self.HTTPConnection(fail=RuntimeError)
        with self.assertRaises(RuntimeError):
            cm.connect(req, 10, True)

    def test_send_request(self):
        conn = self.HTTPConnection()
        cm = urlquick.ConnectionManager()
        headers = {u"Accept-Encoding": u"gzip, deflate"}
        req = urlquick.Request("GET", "https://httpbin.org/get", urlquick.CaseInsensitiveDict(headers), data="testing")
        resp = cm.send_request(conn, req)
        self.assertIsInstance(resp, self.Response)
        self.assertTrue("Accept-Encoding".lower() in conn.headers)
        self.assertEqual(conn.method, "GET")
        self.assertEqual(conn.selector, "/get")
        self.assertEqual(conn.data, b"testing")

    def test_send_request_raises_timeout(self):
        cm = urlquick.ConnectionManager()
        req = urlquick.Request("GET", "https://httpbin.org/get", urlquick.CaseInsensitiveDict())
        conn = self.HTTPConnection(fail=socket.timeout)
        with self.assertRaises(urlquick.Timeout):
            cm.send_request(conn, req)

    def test_send_request_raises_socketerror(self):
        cm = urlquick.ConnectionManager()
        req = urlquick.Request("GET", "https://httpbin.org/get", urlquick.CaseInsensitiveDict())
        conn = self.HTTPConnection(fail=socket.error)
        with self.assertRaises(urlquick.ConnError):
            cm.send_request(conn, req)

    def test_send_request_raises_sslerror(self):
        cm = urlquick.ConnectionManager()
        req = urlquick.Request("GET", "https://httpbin.org/get", urlquick.CaseInsensitiveDict())
        conn = self.HTTPConnection(fail=ssl.SSLError)
        with self.assertRaises(urlquick.ConnError):
            cm.send_request(conn, req)

    def test_send_request_raises_httperror(self):
        cm = urlquick.ConnectionManager()
        req = urlquick.Request("GET", "https://httpbin.org/get", urlquick.CaseInsensitiveDict())
        conn = self.HTTPConnection(fail=urlquick.HTTPException)
        with self.assertRaises(urlquick.ConnError):
            cm.send_request(conn, req)

    def test_close_connections(self):
        cm = urlquick.ConnectionManager()
        cm.request_handler["https"]["httpbin.org"] = self.HTTPConnection()
        cm.close()
        self.assertFalse(cm.request_handler["https"])


def create_resp(body=b"", headers=None, status=200, reason="OK"):
    if headers:
        headers = urlquick.CaseInsensitiveDict(headers)
    else:
        headers = urlquick.CaseInsensitiveDict({"conection": "close"})

    def decorator(function):
        @wraps(function)
        def wrapper(self):
            urlquick.cache_cleanup(0)
            response_data = urlquick.CacheResponse(headers, body, status, reason)
            resp = urlquick.Response(response_data, self.Request(), self.start_time, [])
            function(self, resp)
            resp.close()
        return wrapper
    return decorator


class TestResponse(unittest.TestCase):
    start_time = urlquick.datetime.utcnow()

    class Request(object):
        def __init__(self):
            self.url = "https://httpbin.org/get"

    @create_resp(status=200)
    def test_ok_true(self, resp):
        self.assertTrue(resp.ok)

    @create_resp(status=404)
    def test_ok_false(self, resp):
        self.assertFalse(resp.ok)

    @create_resp(status=200)
    def test_bool_true(self, resp):
        self.assertTrue(resp)

    @create_resp(status=404)
    def test_bool_false(self, resp):
        self.assertFalse(resp)

    @create_resp(headers={"Content-Type": "text/html; charset=utf-8"})
    def test_encoding_with_charset(self, resp):
        self.assertEqual(resp.encoding, "utf-8")

    @create_resp(headers={"Content-Type": "text/html"})
    def test_encoding_without_charset(self, resp):
        self.assertIsNone(resp.encoding)

    @create_resp(b"data")
    def test_content_basic(self, resp):
        self.assertIsInstance(resp.content, bytes)
        self.assertEqual(resp.content, b"data")

    @create_resp(gzip_compress(b"testing data"), headers={"content-encoding": "gzip"})
    def test_content_gzip(self, resp):
        self.assertIsInstance(resp.content, bytes)
        self.assertEqual(resp.content, b"testing data")

    @create_resp(zlib.compress(b"testing data"), headers={"content-encoding": "deflate"})
    def test_content_deflate(self, resp):
        self.assertIsInstance(resp.content, bytes)
        self.assertEqual(resp.content, b"testing data")

    @create_resp(zlib.compress(b"testing data"), headers={"content-encoding": "gzip"})
    def test_content_decompress_fail(self, resp):
        with self.assertRaisesRegexp(urlquick.ContentError, "Failed to decompress content body"):
            test = resp.content

    @create_resp(zlib.compress(b"testing data"), headers={"content-encoding": "fail"})
    def test_content_invalid_fail(self, resp):
        with self.assertRaisesRegexp(urlquick.ContentError, "Unknown encoding:"):
            test = resp.content

    @create_resp(b"data\xc9\xb8", headers={"Content-Type": "text/html; charset=utf-8"})
    def test_text_with_encoding(self, resp):
        self.assertIsInstance(resp.text, unicode)
        self.assertEqual(resp.text, u"dataɸ")

    @create_resp(b"data\xc9\xb8", headers={"Content-Type": "text/html; charset=ascii"})
    def test_text_with_encoding_fail(self, resp):
        self.assertIsInstance(resp.text, unicode)
        self.assertEqual(resp.text, u"dataɸ")

    @create_resp(b"data\xc9\xb8")
    def test_text_with_apparent_encoding(self, resp):
        resp.apparent_encoding = "utf8"
        self.assertIsInstance(resp.text, unicode)
        self.assertEqual(resp.text, u"dataɸ")

    @create_resp(b"data\xc9\xb8")
    def test_text_with_apparent_encoding_fail(self, resp):
        resp.apparent_encoding = "ascii"
        self.assertIsInstance(resp.text, unicode)
        self.assertNotEqual(resp.text, u"dataɸ")

    @create_resp(b"data")
    def test_text_fallback(self, resp):
        resp.encoding = None
        resp.apparent_encoding = None
        self.assertIsInstance(resp.text, unicode)
        self.assertEqual(resp.text, u"data")

    @create_resp(b"data\xc9\xb8")
    def test_text_fallback_fail(self, resp):
        resp.encoding = None
        resp.apparent_encoding = None
        self.assertIsInstance(resp.text, unicode)
        self.assertNotEqual(resp.text, u"dataɸ")

    @create_resp(b"data\xc9\xb8")
    def test_text_with_no_encoding(self, resp):
        resp.encoding = None
        resp.apparent_encoding = None
        self.assertIsInstance(resp.text, unicode)
        self.assertNotEqual(resp.text, u"dataɸ")

    @create_resp(b'{"test": "work"}')
    def test_json(self, resp):
        data = resp.json()
        self.assertIsInstance(data, dict)
        self.assertDictEqual(data, {"test": "work"})

    @create_resp(b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><base><data>Ya, this is data.</data></base>')
    def test_xml(self, resp):
        from xml.etree import ElementTree
        data = resp.xml()
        self.assertIsInstance(data, ElementTree.Element)
        self.assertEqual(data.findtext(u"data"), u"Ya, this is data.")

    @create_resp(b'<html><img src="http://myimages.com/myimage.jpg"/></html>')
    def test_parse(self, resp):
        root_elem = resp.parse()
        assert root_elem.tag == "html"
        assert root_elem[0].tag == "img"
        assert root_elem[0].get("src") == "http://myimages.com/myimage.jpg"

    @create_resp(headers={"Set-Cookie": "test=yes"})
    def test_cookies(self, resp):
        self.assertIsInstance(resp.cookies, dict)
        self.assertDictEqual(resp.cookies, {"test": "yes"})

    @create_resp()
    def test_no_cookies(self, resp):
        self.assertIsInstance(resp.cookies, dict)
        self.assertFalse(resp.cookies)

    @create_resp(status=300)
    def test_no_links(self, resp):
        self.assertIsInstance(resp.links, dict)
        self.assertFalse(resp.links)

    @create_resp(status=300, headers={"Link": "<http://www.acme.com/corporate.css>; REL=stylesheet"})
    def test_links_type1(self, resp):
        self.assertIsInstance(resp.links, dict)
        comp = {'stylesheet': {'url': 'http://www.acme.com/corporate.css', 'rel': 'stylesheet'}}
        self.assertDictEqual(resp.links, comp)

    @create_resp(status=300, headers={"Link": "<http://www.example.com/white-paper.html>; rel"})
    def test_links_type2(self, resp):
        self.assertIsInstance(resp.links, dict)
        comp = {'http://www.example.com/white-paper.html': {'url': 'http://www.example.com/white-paper.html'}}
        self.assertDictEqual(resp.links, comp)

    @create_resp(status=300, headers={"Link": "<http://www.example.com/white-paper.html>"})
    def test_links_type3(self, resp):
        self.assertIsInstance(resp.links, dict)
        comp = {'http://www.example.com/white-paper.html': {'url': 'http://www.example.com/white-paper.html'}}
        self.assertDictEqual(resp.links, comp)

    @create_resp(headers={"test": "yes"})
    def test_headers(self, resp):
        self.assertIsInstance(resp.headers, urlquick.CaseInsensitiveDict)
        self.assertDictEqual(dict(resp.headers), {"test": "yes"})

    @create_resp(status=302, headers={"location": "http://www.example.com"})
    def test_is_redirect_true(self, resp):
        self.assertTrue(resp.is_redirect)

    @create_resp(status=302)
    def test_is_redirect_false(self, resp):
        self.assertFalse(resp.is_redirect)

    @create_resp(status=301, headers={"location": "http://www.example.com"})
    def test_is_permanent_redirect_true(self, resp):
        self.assertTrue(resp.is_permanent_redirect)

    @create_resp(status=301)
    def test_is_permanent_redirect_false(self, resp):
        self.assertFalse(resp.is_permanent_redirect)

    @create_resp(b"body of data")
    def test_iter_content(self, resp):
        data = resp.iter_content(decode_unicode=False)
        self.assertIsInstance(data, types.GeneratorType)
        data = list(data)
        self.assertListEqual(data, [b"body of data"])

    @create_resp(b"body of data")
    def test_iter_content_multiple(self, resp):
        data = resp.iter_content(chunk_size=4, decode_unicode=False)
        self.assertIsInstance(data, types.GeneratorType)
        data = list(data)
        self.assertListEqual(data, [b"body", b" of ", b"data"])

    @create_resp(b"body of data")
    def test_iter_content_unicode(self, resp):
        data = resp.iter_content(decode_unicode=True)
        self.assertIsInstance(data, types.GeneratorType)
        data = list(data)
        self.assertListEqual(data, [u"body of data"])

    @create_resp(b"body of data")
    def test_iter_lines(self, resp):
        data = resp.iter_lines(decode_unicode=False)
        self.assertIsInstance(data, types.GeneratorType)
        data = list(data)
        self.assertListEqual(data ,[b"body of data"])

    @create_resp(b"body\n of \ndata")
    def test_iter_lines_multiple(self, resp):
        data = resp.iter_lines(decode_unicode=False)
        self.assertIsInstance(data, types.GeneratorType)
        data = list(data)
        self.assertListEqual(data, [b"body", b" of ", b"data"])

    @create_resp(b"body of data")
    def test_iter_lines_unicode(self, resp):
        data = resp.iter_lines(decode_unicode=True)
        self.assertIsInstance(data, types.GeneratorType)
        data = list(data)
        self.assertListEqual(data, [u"body of data"])

    @create_resp(b"body of data")
    def test_raise_for_status(self, resp):
        ret = resp.raise_for_status()
        self.assertIsNone(ret)

    @create_resp(status=404)
    def test_raise_for_status_client_error(self, resp):
        with self.assertRaises(urlquick.HTTPError):
            resp.raise_for_status()

    @create_resp(status=501)
    def test_raise_for_status_server_error(self, resp):
        with self.assertRaises(urlquick.HTTPError):
            resp.raise_for_status()

    @create_resp()
    def test_coverage(self, resp):
        list(resp)
        repr(resp)


class Response(object):
    will_close = True

    def __init__(self, body, headers, status, reason, request):
        self.status = status
        self.reason = reason
        self.headers = headers
        self.body = body
        self.request = request

        url = request["url"]
        if url.startswith("/basic-auth/"):
            if not "authorization" in request["headers"]:
                self.reason = "Unauthorized"
                self.status = 401
            else:
                username, sep, password = url.split("/", 2).pop().partition("/")
                auth_header = urlquick.Session._auth_header(username, password)
                if not request["headers"]["authorization"] == auth_header:
                    self.reason = "Unauthorized"
                    self.status = 401

        elif url == "/cache" and "if-none-match" in request["headers"] or "if-modified-since" in request["headers"]:
            self.reason = "Not Modified"
            self.status = 304

        elif url.startswith("/redirect/"):
            self.reason = "Found"
            self.status = 302
            redirect = int(url.split("/").pop())
            if redirect == 1:
                self.headers["Location"] = "/get"
            else:
                location = "/redirect/{}".format(redirect-1)
                self.headers["Location"] = location

        elif url.startswith("/redirect-to?"):
            self.reason = "Found"
            self.status = 302
            redirect = dict(urlquick.parse_qsl(url.split("?", 1).pop()))
            if "url" in redirect:
                self.headers["Location"] = redirect["url"]
            elif "repeat" in redirect:
                self.headers["Location"] = url

            if "status_code" in redirect:
                self.status = int(redirect["status_code"])

    def getheaders(self):
        return self.headers

    def read(self):
        if self.request["method"] == "HEAD":
            return b""
        elif self.body:
            return self.body
        else:
            request = self._unicode_dict(self.request)
            return json.dumps(request).encode("utf8")

    def _unicode_dict(self, _dict):
        new = {}
        for key, value in _dict.items():
            key = self._make_unicode(key)
            value = self._make_unicode(value)
            new[key] = value
        return new

    def _make_unicode(self, data):
        if isinstance(data, bytes):
            return data.decode("utf8")
        elif isinstance(data, dict):
            return self._unicode_dict(data)
        else:
            return unicode(data)

    def close(self):
        pass


class HTTPConnection(object):
    def __init__(self, body, headers, status, reason):
        self.resp_data = [body, headers, status, reason, None]
        self.request = None
        self.reset()

    def reset(self):
        self.request = {"url": None, "method": None, "headers": {}, "body": None}

    def putrequest(self, method, url, **kwargs):
        self.request["method"] = method
        self.request["url"] = url

    def putheader(self, header, value):
        self.request["headers"][header.lower()] = value

    def endheaders(self, message_body):
        self.request["body"] = message_body

    def getresponse(self):
        self.resp_data[4] = self.request
        response = Response(*self.resp_data)
        self.reset()
        return response

    def close(self):
        pass

    def __call__(self, *args, **kwargs):
        return self


def mock_response(body=b"", headers=None, status=200, reason="OK"):
    if headers is None:
        headers = {"conection": "close"}

    def decorator(function):
        @wraps(function)
        def wrapper(self):
            urlquick.cache_cleanup(0)

            # Store original functions
            org_HTTPConnection = urlquick.HTTPConnection
            org_HTTPSConnection = urlquick.HTTPSConnection

            # Mock the HTTPConnection functions
            conn = HTTPConnection(body, headers, status, reason)
            urlquick.HTTPConnection = conn
            urlquick.HTTPSConnection = conn

            try:
                # Call the test
                function(self)
            finally:
                # Replace Mocks with originals
                urlquick.HTTPConnection = org_HTTPConnection
                urlquick.HTTPSConnection = org_HTTPSConnection
        return wrapper
    return decorator


class TestSession(unittest.TestCase):
    def assertResponse(self, resp, resp_type):
        self.assertIsInstance(resp, urlquick.Response)
        self.assertTrue(resp)
        self.assertIsInstance(resp.headers, urlquick.CaseInsensitiveDict)
        self.assertIsInstance(resp.status_code, int)
        self.assertIsInstance(resp.reason, unicode)
        self.assertIsInstance(resp.raw, resp_type)

    @mock_response()
    def test_max_age_local(self):
        with urlquick.Session() as session:
            resp = session.request(u"GET", "https://httpbin.org/get", max_age=14440)
            self.assertResponse(resp, urlquick.CacheResponse)

    @mock_response()
    def test_max_age_session(self):
        with urlquick.Session() as session:
            session.max_age = 14440
            resp = session.request(u"GET", "https://httpbin.org/get")
            self.assertResponse(resp, urlquick.CacheResponse)

    @mock_response()
    def test_disable_max_age_local(self):
        with urlquick.Session() as session:
            resp = session.request(u"GET", "https://httpbin.org/get", max_age=-1)
            self.assertResponse(resp, Response)

    @mock_response()
    def test_disable_max_age_local(self):
        with urlquick.Session() as session:
            session.max_age = -1
            resp = session.request(u"GET", "https://httpbin.org/get")
            self.assertResponse(resp, Response)

    @mock_response()
    def test_max_age_default(self):
        with urlquick.Session() as session:
            resp = session.request(u"GET", "https://httpbin.org/get")
            self.assertResponse(resp, urlquick.CacheResponse)
            # x-max-age should be removed in the cache check
            self.assertTrue("x-max-age" not in resp.request.headers)

    @mock_response()
    def test_no_max_age_at_all(self):
        with urlquick.Session() as session:
            session.max_age = None
            resp = session.request(u"GET", "https://httpbin.org/get")
            self.assertResponse(resp, Response)

    @mock_response()
    def test_caching(self):
        with urlquick.Session() as session:
            resp = session.request(u"GET", "https://httpbin.org/get")
            self.assertResponse(resp, urlquick.CacheResponse)

    @mock_response()
    def test_caching_repeat(self):
        with urlquick.Session() as session:
            # Check that the request is cached
            resp = session.request(u"GET", "https://httpbin.org/get")
            self.assertResponse(resp, urlquick.CacheResponse)
            # Cache show be returned
            resp = session.request(u"GET", "https://httpbin.org/get")
            self.assertResponse(resp, urlquick.CacheResponse)

    @mock_response(status=201)
    def test_uncacheable(self):
        with urlquick.Session() as session:
            resp = session.request(u"GET", "https://httpbin.org/get")
            self.assertResponse(resp, Response)

    @mock_response(headers={"Etag":"dfsdfsdf"})
    def test_cached_304(self):
        with urlquick.Session() as session:
            # Make a request first so that the cache is created
            resp = session.request(u"GET", "https://httpbin.org/get")
            self.assertResponse(resp, urlquick.CacheResponse)
            # Now Now make the same request and the Etag header shoud tigger the 304 response
            resp = session.request(u"GET", "https://httpbin.org/get", max_age=0)
            self.assertResponse(resp, urlquick.CacheResponse)
            self.assertTrue("If-none-match" in resp.request.headers)

    @mock_response()
    def test_headers_local(self):
        with urlquick.Session() as session:
            resp = session.request(u"GET", "https://httpbin.org/get", headers={"testing": "yes"}, max_age=-1)
            self.assertResponse(resp, Response)
            json_data = resp.json()
            self.assertTrue("testing" in json_data["headers"])

    @mock_response()
    def test_headers_session(self):
        with urlquick.Session() as session:
            session.headers["testing"] = "yes"
            resp = session.request(u"GET", "https://httpbin.org/get", max_age=-1)
            self.assertResponse(resp, Response)
            json_data = resp.json()
            self.assertTrue("testing" in json_data["headers"])

    @mock_response()
    def test_cookie_local(self):
        with urlquick.Session() as session:
            cookies = {"test": "yes"}
            resp = session.request(u"GET", "https://httpbin.org/get", cookies=cookies, max_age=-1)
            self.assertResponse(resp, Response)
            self.assertTrue("Cookie" in resp.request.headers)
            self.assertEqual(resp.request.headers["Cookie"], "test=yes")

    @mock_response()
    def test_cookie_session(self):
        with urlquick.Session() as session:
            session.cookies["test"] = "yes"
            resp = session.request(u"GET", "https://httpbin.org/get", max_age=-1)
            self.assertResponse(resp, Response)
            self.assertTrue("Cookie" in resp.request.headers)
            self.assertEqual(resp.request.headers["Cookie"], "test=yes")

    @mock_response()
    def test_cookie_replace(self):
        with urlquick.Session() as session:
            session.cookies = {"test": "yes"}
            resp = session.request(u"GET", "https://httpbin.org/get", max_age=-1)
            self.assertResponse(resp, Response)
            self.assertTrue("Cookie" in resp.request.headers)
            self.assertEqual(resp.request.headers["Cookie"], "test=yes")

    @mock_response()
    def test_cookie_replace_fail(self):
        with urlquick.Session() as session:
            with self.assertRaises(ValueError):
                session.cookies = "test"

    @mock_response()
    def test_params_local(self):
        with urlquick.Session() as session:
            params = {"test": "yes"}
            resp = session.request(u"GET", "https://httpbin.org/get", params=params, max_age=-1)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.url, "https://httpbin.org/get?test=yes")

    @mock_response()
    def test_params_session(self):
        with urlquick.Session() as session:
            session.params["test"] = "yes"
            resp = session.request(u"GET", "https://httpbin.org/get", max_age=-1)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.url, "https://httpbin.org/get?test=yes")

    @mock_response()
    def test_params_replace(self):
        with urlquick.Session() as session:
            session.params = {"test": "yes"}
            resp = session.request(u"GET", "https://httpbin.org/get", max_age=-1)
            self.assertResponse(resp, Response)

    @mock_response()
    def test_params_replace_fail(self):
        with urlquick.Session() as session:
            with self.assertRaises(ValueError):
                session.params = "test"

    @mock_response()
    def test_no_auth(self):
        """Test that authentication failes when no authentication is given."""
        with urlquick.Session() as session:
            resp = session.request(u"GET", "https://httpbin.org/basic-auth/testu/testp", max_age=-1)
            self.assertEqual(resp.status_code, 401, msg="Request authenticated unexpectedly")

    @mock_response()
    def test_auth_local(self):
        """Test that request authenticates with passed in authentication."""
        with urlquick.Session() as session:
            resp = session.request(u"GET", "https://httpbin.org/basic-auth/testu/testp", auth=("testu", "testp"), max_age=-1)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.status_code, 200, msg="Authentication failed")

    @mock_response()
    def test_auth_netloc(self):
        """Test that request authenticates with url authentication."""
        with urlquick.Session() as session:
            resp = session.request(u"GET", "https://testu:testp@httpbin.org/basic-auth/testu/testp", max_age=-1)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.status_code, 200, msg="Authentication failed")

    @mock_response()
    def test_auth_session(self):
        """Test that request authenticates with session level authentication."""
        with urlquick.Session() as session:
            session.auth = ("testu", "testp")
            self.assertTupleEqual(session.auth, ("testu", "testp"))
            resp = session.request(u"GET", "https://httpbin.org/basic-auth/testu/testp", max_age=-1)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.status_code, 200, msg="Authentication failed")

    @mock_response()
    def test_auth_multi_netloc_auth(self):
        """Test that only the auth credentials within the url are used. Ignore session auth."""
        with urlquick.Session() as session:
            session.auth = ("ufail", "pfail")  # Should be ignored
            resp = session.request(u"GET", "https://testu:testp@httpbin.org/basic-auth/testu/testp", max_age=-1)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.status_code, 200, msg="Authentication failed")

    @mock_response()
    def test_auth_multi_local_auth(self):
        """Test that only the auth credentials passed to the request are used. Ignore session and netloc auth."""
        with urlquick.Session() as session:
            session.auth = ("ufail", "pfail")  # Should be ignored
            resp = session.request(u"GET", "https://ufail:pfail@httpbin.org/basic-auth/testu/testp", auth=("testu", "testp"), max_age=-1)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.status_code, 200, msg="Authentication failed")

    @mock_response()
    def test_auth_session_fail(self):
        """Test that a ValueError is raised if invalid authentication type is given to session."""
        with urlquick.Session() as session:
            with self.assertRaises(ValueError):
                session.auth = "testu"

    @mock_response()
    def test_redirect(self):
        with urlquick.Session() as session:
            resp = session.request(u"GET", "https://httpbin.org/redirect/3", max_age=-1)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.url, "https://httpbin.org/get")

    @mock_response()
    def test_max_redirect(self):
        with urlquick.Session() as session:
            with self.assertRaisesRegexp(urlquick.MaxRedirects, "max_redirects exceeded"):
                session.request(u"GET", "https://httpbin.org/redirect/11", max_age=-1)

    @mock_response()
    def test_max_repeat_redirect(self):
        with urlquick.Session() as session:
            with self.assertRaisesRegexp(urlquick.MaxRedirects, "max_repeat_redirects exceeded"):
                session.request(u"GET", "https://httpbin.org/redirect-to?repeat=true", max_age=-1)

    @mock_response()
    def test_redirect_307_keep_method(self):
        with urlquick.Session() as session:
            resp = session.request(u"POST", "https://httpbin.org/redirect-to?status_code=307&url=%2Fpost", data="testing", max_age=-1)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.url, "https://httpbin.org/post")
            self.assertEqual(resp.request.method, "POST")

    @mock_response()
    def test_redirect_force_get(self):
        with urlquick.Session() as session:
            resp = session.request(u"POST", "https://httpbin.org/redirect-to?status_code=308&url=%2Fget", data="testing", max_age=-1)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.url, "https://httpbin.org/get")
            self.assertEqual(resp.request.method, "GET")

    @mock_response()
    def test_unverify(self):
        with urlquick.Session() as session:
            resp = session.request(u"POST", "https://httpbin.org/redirect-to?status_code=308&url=%2Fget",
                                   data="testing", verify=False, max_age=-1)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.url, "https://httpbin.org/get")
            self.assertEqual(resp.request.method, "GET")

    @mock_response()
    def test_redirect_with_auth(self):
        with urlquick.Session() as session:
            resp = session.request(u"GET", "https://httpbin.org/redirect-to?url=%2Fbasic-auth%2Ftestu%2Ftestp", auth=("testu", "testp"), max_age=-1)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.request.method, "GET")

    @mock_response(status=200)
    def test_raise_for_status_pass(self):
        with urlquick.Session() as session:
            resp = session.request(u"GET", "https://httpbin.org/get", max_age=-1, raise_for_status=True)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.url, "https://httpbin.org/get")
            self.assertEqual(resp.status_code, 200)

    @mock_response(status=404)
    def test_raise_for_status_fail(self):
        with urlquick.Session() as session:
            with self.assertRaises(urlquick.HTTPError):
                session.request(u"GET", "https://httpbin.org/get", max_age=-1, raise_for_status=True)

    @mock_response()
    def test_session_get(self):
        with urlquick.Session() as session:
            resp = session.get("https://httpbin.org/get", max_age=-1)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.request.method, "GET")

    @mock_response()
    def test_session_head(self):
        with urlquick.Session() as session:
            resp = session.head("https://httpbin.org/get", max_age=-1)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.request.method, "HEAD")
            self.assertEqual(resp.content, b"")

    @mock_response()
    def test_session_post(self):
        with urlquick.Session() as session:
            resp = session.post("https://httpbin.org/post", data="data", max_age=-1)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.request.method, "POST")
            json_data = resp.json()
            self.assertEqual(json_data["body"], "data")

    @mock_response()
    def test_session_put(self):
        with urlquick.Session() as session:
            resp = session.put("https://httpbin.org/put", data="put", max_age=-1)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.request.method, "PUT")
            json_data = resp.json()
            self.assertEqual(json_data["body"], "put")

    @mock_response()
    def test_session_patch(self):
        with urlquick.Session() as session:
            resp = session.patch("https://httpbin.org/patch", data="patch", max_age=-1)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.request.method, "PATCH")
            json_data = resp.json()
            self.assertEqual(json_data["body"], "patch")

    @mock_response()
    def test_session_delete(self):
        with urlquick.Session() as session:
            resp = session.delete("https://httpbin.org/delete", max_age=-1)
            self.assertResponse(resp, Response)
            self.assertEqual(resp.request.method, "DELETE")

    @mock_response()
    def test_request(self):
        resp = urlquick.request("GET", "https://httpbin.org/get", max_age=-1)
        self.assertResponse(resp, Response)
        self.assertEqual(resp.request.method, "GET")

    @mock_response()
    def test_get(self):
        resp = urlquick.get("https://httpbin.org/get", max_age=-1)
        self.assertResponse(resp, Response)
        self.assertEqual(resp.request.method, "GET")

    @mock_response()
    def test_head(self):
        resp = urlquick.head("https://httpbin.org/get", max_age=-1)
        self.assertResponse(resp, Response)
        self.assertEqual(resp.request.method, "HEAD")
        self.assertEqual(resp.content, b"")

    @mock_response()
    def test_post(self):
        resp = urlquick.post("https://httpbin.org/post", data="data", max_age=-1)
        self.assertResponse(resp, Response)
        self.assertEqual(resp.request.method, "POST")
        json_data = resp.json()
        self.assertEqual(json_data["body"], "data")

    @mock_response()
    def test_put(self):
        resp = urlquick.put("https://httpbin.org/put", data="put", max_age=-1)
        self.assertResponse(resp, Response)
        self.assertEqual(resp.request.method, "PUT")
        json_data = resp.json()
        self.assertEqual(json_data["body"], "put")

    @mock_response()
    def test_patch(self):
        resp = urlquick.patch("https://httpbin.org/patch", data="patch", max_age=-1)
        self.assertResponse(resp, Response)
        self.assertEqual(resp.request.method, "PATCH")
        json_data = resp.json()
        self.assertEqual(json_data["body"], "patch")

    @mock_response()
    def test_delete(self):
        resp = urlquick.delete("https://httpbin.org/delete", max_age=-1)
        self.assertResponse(resp, Response)
        self.assertEqual(resp.request.method, "DELETE")
