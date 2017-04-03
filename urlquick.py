#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# The MIT License (MIT)
#
# Copyright (c) 2017 William Forde
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""
Urlquick
A light-weight http client with requests like interface. Featuring persistent connections and caching support.

This project was origfix bug when passing a none value for errors into str.decode failes.inally created for use by Kodi add-ons, but has grown into something more.
I found that while requests has a very nice interface, there was a noticeable lag when importing the library.
The other option available is to use urllib2 but then you loose the benefit of persistent
connections that requests have. Hence the reason for this project.

All GET, HEAD and POST requests are cached locally for a period of 4 hours. When the cache expires, conditional headers
are added to a new request e.g. 'Etag' and 'Last-modified'. Then if the response returns a 304 Not-Modified response,
the cache is reused, saving having to re-download the content body.

TODO: Create documentation
"""

# Python 2 Compatibility
from __future__ import print_function#, unicode_literals

# Standard library imports
from collections import MutableMapping, defaultdict
from base64 import b64encode, b64decode
from codecs import open
from datetime import datetime
import json as _json
import hashlib
import socket
import time
import zlib
import sys
import re
import os

# Check python version to set the object that can detect non unicode strings
py3 = sys.version_info >= (3, 0)
if py3:
    # noinspection PyUnresolvedReferences
    from http.client import HTTPConnection, HTTPSConnection, HTTPException
    # noinspection PyUnresolvedReferences
    from urllib.parse import urlsplit, urlunsplit, urljoin, SplitResult, urlencode, parse_qsl, quote, unquote
    # noinspection PyUnresolvedReferences
    from http.cookies import SimpleCookie
    # noinspection PyShadowingBuiltins
    unicode = str
else:
    # noinspection PyUnresolvedReferences
    from httplib import HTTPConnection, HTTPSConnection, HTTPException
    # noinspection PyUnresolvedReferences
    from urlparse import urlsplit, urlunsplit, urljoin, SplitResult, parse_qsl as _parse_qsl
    # noinspection PyUnresolvedReferences
    from urllib import urlencode as _urlencode, quote as _quote, unquote as _unquote
    # noinspection PyUnresolvedReferences
    from Cookie import SimpleCookie

    def quote(data, safe=b"/", encoding="utf8", errors="strict"):
        data = data.encode(encoding, errors)
        return _quote(data, safe).decode("ascii")

    def unquote(data, encoding="utf-8", errors="replace"):
        data = data.encode("ascii", errors)
        return _unquote(data).decode(encoding, errors)

    def parse_qsl(qs, encoding="utf8", errors="replace", **kwargs):
        qs = qs.encode(encoding, errors)
        qsl = _parse_qsl(qs, **kwargs)
        return [(key.decode(encoding, errors), value.decode(encoding, errors)) for key, value in qsl]

    def urlencode(query, doseq=False, encoding="utf8", errors=""):
        # Fetch items as a tuple of (key, value)
        items = query.items() if hasattr(query, "items") else query
        new_query = []

        # Process the items and encode unicode strings
        for key, value in items:
            key = key.encode(encoding, errors)
            if isinstance(value, (list, tuple)):
                value = [_value.encode(encoding, errors) for _value in value]
            else:
                value = value.encode(encoding, errors)
            new_query.append((key, value))

        # Decode the output of urlencode back into unicode and return
        return _urlencode(new_query, doseq).decode("ascii")

__all__ = ["get", "head", "post", "Session"]
__copyright__ = "Copyright (C) 2017 William Forde"
__author__ = "William Forde"
__license__ = "GPLv3"
__version__ = "0.0.1"
__credit__ = "urlfetch, keepalive, requests"

# Cacheable request types
CACHEABLE_METHODS = (u"GET", u"HEAD", u"POST")
CACHEABLE_CODES = (200, 203, 204, 300, 301, 302, 303, 307, 308, 410, 414)
REDIRECT_CODES = (301, 302, 303, 307, 308)
CACHE_PERIOD = 14400


class UrlError(IOError):
    """Base exception. All exceptions and errors will subclass from this."""


class Timeout(UrlError):
    """Request timed out."""


class MaxRedirects(UrlError):
    """Too many redirects."""


class ContentDecodingError(UrlError):
    """Failed to decode the content."""


class HTTPError(UrlError):
    """Raised when HTTP error occurs, but also acts like non-error return"""
    def __init__(self, url, code, msg, hdrs):
        self.code = code
        self.msg = msg
        self.hdrs = hdrs
        self.filename = url

    def __str__(self):
        error_type = "Client" if self.code < 500 else "Server"
        return "HTTP {} Error {}: {}".format(error_type, self.code, self.msg)


class CaseInsensitiveDict(MutableMapping):
    """
    A case-insensitive ``dict``-like object.

    Credit goes to requests for this code
    http://docs.python-requests.org/en/master/
    """
    def __init__(self, *args):
        self._store = {}
        for _dict in args:
            if _dict:
                self.update(_dict)

    def __repr__(self):
        return str(dict(self.items()))

    def __setitem__(self, key, value):
        if value is not None:
            key = make_unicode(key, "ascii")
            value = make_unicode(value, "iso-8859-1")
            self._store[key.lower()] = (key, value)

    def __getitem__(self, key):
        return self._store[key.lower()][1]

    def __delitem__(self, key):
        del self._store[key.lower()]

    def __iter__(self):
        return (casedkey for casedkey, _ in self._store.values())

    def __len__(self):
        return len(self._store)

    def copy(self):
        return CaseInsensitiveDict(self._store.values())


class ConnectionManager(object):
    """Manage concurrent http connections"""
    def __init__(self):
        self._connections = {u"http": {}, u"https": {}}

    def reuse_connection(self, conn, req):
        try:
            return self.send_request(conn, req)
        except (socket.error, HTTPException):
            return None

    def start_connection(self, conn, req):
        try:
            return self.send_request(conn, req)
        except socket.timeout as e:
            raise Timeout(e)
        except (socket.error, HTTPException) as e:
            raise UrlError(e)

    @staticmethod
    def send_request(conn, req):
        conn.putrequest(str(req.method), str(req.selector), skip_host=1, skip_accept_encoding=1)

        # Add headers to request
        for hdr, value in req.header_items():
            conn.putheader(hdr, value)

        # Convert data to bytes before sending
        conn.endheaders(req.data)

        # return the response
        return conn.getresponse()

    def request(self, req, timeout):
        if req.urlparts.scheme in self._connections:
            connections = self._connections[req.urlparts.scheme]
        else:
            raise UrlError("Unsupported scheme: {}".format(req.urlparts.scheme))

        host = str(req.host)
        response = None

        # urlparts.schemehost
        if host in connections:
            conn = connections[host]
            try:
                # noinspection PyTypeChecker
                response = self.reuse_connection(conn, req)
            except Exception:
                del connections[host]
                conn.close()
                raise

        if response is None:
            if req.urlparts.scheme == u"https":
                conn = HTTPSConnection(host, timeout=timeout)
            else:
                conn = HTTPConnection(host, timeout=timeout)

            response = self.start_connection(conn, req)
            if not response.will_close:
                connections[host] = conn

        return response


class CachedProperty(object):
    """
    Cached property.

    A property that is only computed once per instance and then replaces
    itself with an ordinary attribute. Deleting the attribute resets the
    property.
    """
    def __init__(self, fget=None):
        self.__get = fget
        self.__doc__ = fget.__doc__
        self.__name__ = fget.__name__
        self.__module__ = fget.__module__

    def __get__(self, instance, owner):
        try:
            return instance.__dict__[self.__name__]
        except KeyError:
            value = instance.__dict__[self.__name__] = self.__get(instance)
            return value

    def __set__(self, instance, value):
        instance.__dict__[self.__name__] = value

    def __delete__(self, instance):
        instance.__dict__.pop(self.__name__, None)


class CacheHandler(object):
    def __init__(self, url_hash, max_age=14400):
        self.max_age = max_age
        self.response = None
        cache_dir = self.cache_dir()
        self.cache_path = cache_path = os.path.join(cache_dir, url_hash)
        if os.path.exists(cache_path):
            self.response = self._load()
            if self.response is None:
                self.delete(cache_path)

    @staticmethod
    def cache_dir():
        current_dir = os.path.dirname(os.path.realpath(__file__))
        cache_dir = os.path.join(current_dir, ".cache")
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)
        return cache_dir

    @staticmethod
    def delete(cache_path):
        """Delete cache from disk"""
        try:
            os.remove(cache_path)
        except OSError as e:
            print("Cache Error: Unable to delete cache from disk.", str(e))
        else:
            print("Removed cache:", cache_path)

    @staticmethod
    def isfilefresh(cache_path, max_age):
        return (time.time() - os.stat(cache_path).st_mtime) < max_age

    def isfresh(self):
        """ Return True if cache is fresh else False """
        # Check that the response is of status 301 or that the cache is not older than the max age
        if self.response.status in (301, 308, 414) or self.max_age == -1:
            return True
        elif self.max_age == 0:
            return False
        else:
            return self.isfilefresh(self.cache_path, self.max_age)

    def reset_timestamp(self):
        """ Reset the last modified timestamp to current time"""
        os.utime(self.cache_path, None)

    def add_conditional_headers(self, headers):
        """Return a dict of conditional headers from cache"""
        # Fetch cached headers
        cached_headers = self.response.headers

        # Check for conditional headers
        if u"Etag" in cached_headers:
            print("Found conditional header: ETag = {}".format(cached_headers[u"ETag"]))
            headers[u"If-none-match"] = cached_headers[u"ETag"]

        if u"Last-modified" in cached_headers:
            print("Found conditional header: Last-Modified = {}".format(cached_headers[u"Last-modified"]))
            headers[u"If-modified-since"] = cached_headers[u"Last-Modified"]

    def update(self, headers, body, status, reason, version=11, strict=True):
        # Convert headers into a Case Insensitive Dict
        if not isinstance(headers, CaseInsensitiveDict):
            headers = CaseInsensitiveDict(headers)

        # Remove Transfer-Encoding from header if exists
        if u"Transfer-Encoding" in headers:
            del headers[u"Transfer-Encoding"]

        # Ensure that reason is unicode
        reason = unicode(reason)

        # Create response data structure
        self.response = CacheResponse(headers, body, status, reason, version, strict)

        # Save response to disk
        self._save(headers=dict(headers), body=body, status=status, reason=reason, version=version, strict=strict)

    def _load(self):
        """ Load the cache response that is stored on disk """
        try:
            # Atempt to read the raw cache data
            with open(self.cache_path, "rb", encoding="utf8") as stream:
                json_data = _json.load(stream)

        except (IOError, OSError) as e:
            print("Cache Error: Failed to read cached response.", str(e))
            return None

        except TypeError as e:
            print("Cache Error: Failed to deserialize cached response.", str(e))
            return None

        # Decode body content using base64
        json_data[u"body"] = b64decode(json_data[u"body"].encode("ascii"))
        return CacheResponse(**json_data)

    def _save(self, **response):
        # Base64 encode the body to make it json serializable
        response[u"body"] = b64encode(response[u"body"]).decode("ascii")

        try:
            # Save the response to disk using json Serialization
            with open(self.cache_path, "wb", encoding="utf8") as stream:
                _json.dump(response, stream, indent=4, separators=(",", ":"))

        except (IOError, OSError) as e:
            print("Cache Error: Failed to write response to cache.", str(e))
            self.delete(self.cache_path)

        except TypeError as e:
            print("Cache Error: Failed to serialize response.", str(e))
            self.delete(self.cache_path)

    def __bool__(self):
        return self.response is not None

    def __nonzero__(self):
        return self.response is not None

    @staticmethod
    def hash_url(url, data=None):
        """ Return url as a sha1 encoded hash """
        # Make sure that url is of type bites
        if isinstance(url, unicode):
            url = url.encode("utf8")

        if data:
            # Make sure that data is of type bites
            if isinstance(data, unicode):
                data = data.encode("utf8")
            url += data

        # Covert hashed url to unicode
        urlhash = hashlib.sha1(url).hexdigest()
        if isinstance(urlhash, bytes):
            urlhash = unicode(urlhash)

        # Append urlhash to the filename
        return "cache-{}".format(urlhash)

    @classmethod
    def cleanup(cls, max_age=None):
        """Remove all stale cache files"""
        max_age = CACHE_PERIOD if max_age is None else max_age
        cache_dir = cls.cache_dir()
        for url_hash in os.listdir(cache_dir):
            # Check that we actually have a cache file
            if url_hash.startswith("cache-"):
                cache_path = os.path.join(cache_dir, url_hash)
                # Check if the cache is not fresh and delete if so
                if not cls.isfilefresh(cache_path, max_age):
                    cls.delete(cache_path)


class CacheAdapter(object):
    def __init__(self):
        self.__cache = None

    def cache_check(self, method, url, data, headers):
        # Fetch max age from request header
        max_age = int(headers.pop(u"x-max-age", CACHE_PERIOD))
        url_hash = CacheHandler.hash_url(url, data)
        if method == u"OPTIONS":
            return None

        # Check if cache exists first
        self.__cache = cache = CacheHandler(url_hash, max_age)
        if cache:
            if method in ("PUT", "DELETE"):
                print("Cache purged, {} request invalidates cache".format(method))
                cache.delete(cache.cache_path)

            elif cache.isfresh():
                print("Cache is fresh, returning cached response")
                return cache.response

            else:
                print("Cache is stale, checking for conditional headers")
                cache.add_conditional_headers(headers)

    def handle_response(self, method, status, callback):
        if status == 304:
            print("Server return 304 Not Modified response, using cached response")
            callback()
            self.__cache.reset_timestamp()
            return self.__cache.response

        # Cache any cachable response
        elif status in CACHEABLE_CODES and method.upper() in CACHEABLE_METHODS:
            response = callback()
            print("Caching {} {} response".format(status, response[3]))

            # Save response to cache and return the cached response
            self.__cache.update(*response)
            return self.__cache.response


class CacheResponse(object):
    def __init__(self, headers, body, status, reason, version=11, strict=True):
        # Convert headers into a Case Insensitive Dict
        if isinstance(headers, CaseInsensitiveDict):
            self.headers = headers
        else:
            self.headers = CaseInsensitiveDict(headers)

        self.body = body
        self.status = status
        self.reason = reason
        self.version = version
        self.strict = strict

    def getheaders(self):
        return self.headers

    def read(self):
        return self.body

    def close(self):
        pass


class Request(object):
    """A Request Object"""
    def __init__(self, method, url, headers, data=None, json=None, params=None, referer=None):
        # Make sure that method is capitalized and unicode
        if isinstance(method, bytes):
            self.method = method.upper().decode("ascii")
        else:
            self.method = method.upper()

        # Request headers
        self.headers = headers = headers.copy()
        self.referer_url = referer
        self.auth = None

        # Convert url into a fully ascii unicode string
        self.urlparts = urlparts = self._parse_url(url, params)
        self.url = urlunsplit((urlparts.scheme, urlparts.netloc, urlparts.path, urlparts.query, urlparts.fragment))
        self.host = urlparts.netloc

        # Add Referer header if not the original request
        if referer:
            self.headers[u"Referer"] = referer

        # Add host header to be compliant with HTTP/1.1
        if u"Host" not in headers:
            self.headers[u"Host"] = self.urlparts.hostname

        # Construct post data from a json object
        if json:
            self.headers[u"Content-Type"] = u"application/json"
            data = _json.dumps(json)

        if data:
            # Convert data into a urlencode string if data is a dict
            if isinstance(data, dict):
                self.headers[u"Content-Type"] = u"application/x-www-form-urlencoded"
                data = urlencode(data, True).encode("utf8")
            elif isinstance(data, unicode):
                data = data.encode("utf8")

            if u"Content-Length" not in headers:
                self.headers[u"Content-Length"] = unicode(len(data))

        # Set post data
        self.data = data

    def _parse_url(self, url, params=None, scheme=u"http"):
        """
        Parse a URL into it's individual components.

        :param str url: Url to parse
        :param dict params: params to add to url as query
        :return: A 5-tuple of URL components
        :rtype: urllib.parse.SplitResult
        """
        # Make sure we have unicode
        if isinstance(url, bytes):
            url = url.decode("utf8")

        # Check for valid url structure
        if not url[:4] == u"http":
            if self.referer_url:
                url = urljoin(self.referer_url, url, allow_fragments=False)

            elif url[:3] == u"://":
                url = url[1:]

        # Parse the url into each element
        scheme, netloc, path, query, _ = urlsplit(url, scheme=scheme)

        # Insure that all element of the url can be encoded into ascii
        self.auth, netloc = self._ascii_netloc(netloc)
        path = self._ascii_path(path) if path else u"/"
        query = self._ascii_query(query, params)

        # noinspection PyArgumentList
        return SplitResult(scheme, netloc, path, query, u"")

    @staticmethod
    def _ascii_netloc(netloc):
        """Make sure that host is ascii compatible"""
        auth = None
        if u"@" in netloc:
            # Extract auth
            auth, netloc = netloc.rsplit(u"@", 1)
            if u":" in auth:
                auth = tuple(auth.split(u":", 1))
            else:
                auth = (auth, u"")

        return auth, netloc.encode("idna").decode("ascii")

    @staticmethod
    def _ascii_path(path):
        """Make sure that path is url encoded and ascii compatible"""
        try:
            # If this statement passes then path must contain only ascii characters
            return path.encode("ascii").decode("ascii")
        except UnicodeEncodeError:
            # Path must contain non ascii characters
            return quote(path)

    @staticmethod
    def _ascii_query(query, params):
        """Make sure that query is urlencoded and ascii compatible"""
        if query:
            # Ensure that query contains only valid characters
            qsl = parse_qsl(query)
            query = urlencode(qsl)

        if query and params:
            extra_query = urlencode(params)
            return u"{}&{}".format(query, extra_query)
        elif params:
            return urlencode(params)
        elif query:
            return query
        else:
            return u""

    @property
    def selector(self):
        """Return a resource selector with the url path and query parts"""
        if self.urlparts.query:
            return u"{}?{}".format(self.urlparts.path, self.urlparts.query)
        else:
            return self.urlparts.path

    def header_items(self):
        """Return request headers with unicode values or str value, depending on python version"""
        if py3:
            return self.headers.items()
        else:
            return self._py2_header_items()

    def _py2_header_items(self):
        """Return request headers with no unicode value to be compatible with python2"""
        for key, value in self.headers.iteritems():
            key = key.encode("ascii")
            value = value.encode("iso-8859-1")
            yield key, value


class UnicodeDict(dict):
    def __init__(self, *mappings):
        super(UnicodeDict, self).__init__()
        for mapping in mappings:
            if mapping:
                # noinspection PyUnresolvedReferences
                for key, value in mapping.items():
                    key = make_unicode(key)
                    value = make_unicode(value)
                    self[key] = value


def make_unicode(data, encoding="utf8", errors=""):
    """Ensure that data is a unicode string"""
    if isinstance(data, bytes):
        return data.decode(encoding, errors)
    else:
        return unicode(data)


# ########################## Public API ##########################


class Session(CacheAdapter):
    """
    Provides cookie persistence, connection-pooling, and configuration.

    Basic Usage:
    >>> import requests
    >>> s = requests.Session()
    >>> s.get("http://httpbin.org/get")
    <Response [200]>

    Or as a context manager:
    >>> with requests.Session() as s:
    >>>     s.get("http://httpbin.org/get")
    <Response [200]>
    """
    def __init__(self):
        super(Session, self).__init__()
        self._headers = CaseInsensitiveDict()

        # Set Default headers
        self._headers[u"Accept"] = u"*/*"
        self._headers[u"Accept-Encoding"] = u"gzip, deflate"
        self._headers[u"Accept-language"] = u"en-gb,en-us,en"
        self._headers[u"Connection"] = u"keep-alive"

        # Session Controls
        self._cm = ConnectionManager()
        self._cookies = dict()
        self._params = dict()
        self.auth = None

        # Session settings
        self.mac_repeats = 4
        self.max_redirects = 10
        self.allow_redirects = True
        self.raise_for_status = False
        self.max_age = CACHE_PERIOD

    @property
    def headers(self):
        """
        Dictionary of headers to attach to each request.

        :return: Session headers
        :rtype: dict
        """
        return self._headers

    @property
    def cookies(self):
        """
        Dictionary of cookies to attach to each request.

        :return: Session cookies
        :rtype: dict
        """
        return self._cookies

    @cookies.setter
    def cookies(self, _dict):
        """Replace session cookies with new cookies dict"""
        if isinstance(_dict, dict):
            self._cookies = _dict
        else:
            raise ValueError("Invalid type: {}, dict required".format(type(_dict)))

    @property
    def params(self):
        """
        Dictionary of querystrings to attach to each Request. The dictionary
        values may be lists for representing multivalued query parameters.

        :return: Session params
        :rtype: dict
        """
        return self._params

    @params.setter
    def params(self, _dict):
        """Replace session params with new params dict"""
        if isinstance(_dict, dict):
            self._params = _dict
        else:
            raise ValueError("Invalid type: {}, dict required".format(type(_dict)))

    def get(self, url, params=None, **kwargs):
        """
        Sends a GET request.

        Requests data from a specified resource.

        :param str url: Url of the remote resource.
        :param dict params: (optional) Dict of url query key/value pairs.
        :param kwargs: Optional arguments that ``request`` takes.

        :return: A requests like :class:`Response <Response>` object
        :rtype: urlquick.Response
        """
        kwargs["params"] = params
        return self.request(u"GET", url, **kwargs)

    def head(self, url, **kwargs):
        """
        Sends a HEAD request.

        Same as GET but returns only HTTP headers and no document body.

        :param str url: Url of the remote resource.
        :param kwargs: Optional arguments that ``request`` takes.

        :return: A requests like :class:`Response <Response>` object
        :rtype: urlquick.Response
        """
        return self.request(u"HEAD", url, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):
        """
        Sends a POST request.

        Send data to a server, for example, customer information, file upload, etc.

        :param str url: Url of the remote resource.
        :param data: (optional) Data to send with the request to the server.
        :param json: (optional) json data to send in the body of the Request.
        :param kwargs: Optional arguments that ``request`` takes.

        :return: A requests like :class:`Response <Response>` object
        :rtype: urlquick.Response
        """
        return self.request(u"POST", url, data=data, json=json, **kwargs)

    def put(self, url, data=None, **kwargs):
        """
        Sends a PUT request.

        Replaces all current representations of the target resource with the uploaded content.

        :param str url: Url of the remote resource.
        :param data: (optional) Data to send with the request to the server.
        :param kwargs: Optional arguments that ``request`` takes.

        :return: A requests like :class:`Response <Response>` object
        :rtype: urlquick.Response
        """
        return self.request(u"PUT", url, data=data, **kwargs)

    def patch(self, url, data=None, **kwargs):
        """
        Sends a PUT request.

        :param str url: Url of the remote resource.
        :param data: (optional) Data to send with the request to the server.
        :param kwargs: Optional arguments that ``request`` takes.

        :return: A requests like :class:`Response <Response>` object
        :rtype: urlquick.Response
        """
        return self.request(u"PATCH", url, data=data, **kwargs)

    def delete(self, url, **kwargs):
        """
        Sends a DELETE request.

        Removes all current representations of the target resource given by a URI.

        :param str url: Url of the remote resource.
        :param kwargs: Optional arguments that ``request`` takes.

        :return: A requests like :class:`Response <Response>` object
        :rtype: urlquick.Response
        """
        return self.request(u"DELETE", url, **kwargs)

    def options(self, url, **kwargs):
        """
        Sends a HEAD request.

        Identify allowed request methods.

        :param str url: Url of the remote resource.
        :param kwargs: Optional arguments that ``request`` takes.

        :return: A requests like :class:`Response <Response>` object
        :rtype: urlquick.Response
        """
        return self.request(u"OPTIONS", url, **kwargs)

    def request(self, method, url, params=None, data=None, json=None, headers=None, cookies=None, auth=None,
                timeout=10, allow_redirects=None, raise_for_status=None, max_age=None):
        """
        Request a url resource.

        :param method: HTTP request method, 'GET', 'HEAD', 'POST'.
        :param str url: Url of the remote resource.
        :param dict params: (optional) Dict of url query key/value pairs.
        :param data: (optional) Data to send with the request to the server.
        :param json: (optional) json data to send in the body of the Request.
        :param dict headers: (optional) HTTP request headers.
        :param cookies: (optional) Dict or CookieJar object to send with the request.
        :param tuple auth: (optional) (username, password) for basic authentication.
        :param int timeout: (optional) Timeout in seconds.
        :param bool allow_redirects: (optional) Boolean. Enable/disable redirection. Defaults to ``True``.
        :param bool raise_for_status: (optional) Raise HTTPError if status code is > 400. Defaults to ``False``.
        :param int max_age: Max age the cache can be before it is considered stale. -1 will disable caching.

        :return: A requests like :class:`Response <Response>` object
        :rtype: urlquick.Response
        """

        # Fetch settings from local or session
        allow_redirects = self.allow_redirects if allow_redirects is None else allow_redirects
        raise_for_status = self.raise_for_status if raise_for_status is None else raise_for_status

        # Ensure that all mappings of unicode data
        reqHeaders = CaseInsensitiveDict(self._headers, headers)
        reqCookies = UnicodeDict(self._cookies, cookies)
        reqParams = UnicodeDict(self._params, params)

        # Add cookies to headers
        if reqCookies and not u"Cookie" in reqHeaders:
            header = u"; ".join([u"{}={}".format(key, value) for key, value in reqCookies.items()])
            reqHeaders[u"Cookie"] = header

        # Fetch max age of cache
        max_age = (-1 if self.max_age is None else self.max_age) if max_age is None else max_age
        if max_age >= 0:
            reqHeaders["x-max-age"] = max_age

        # Parse url into it's individual components including params if given
        req = Request(method, url, reqHeaders, data, json, reqParams, reqCookies)

        # Add Authorization header if needed
        auth = req.auth or auth or self.auth
        if auth:
            auth = self._auth_header(*auth)
            req.headers[u"Authorization"] = auth

        # Request monitors
        history = []
        visited = defaultdict(int)
        start_time = datetime.utcnow()

        while True:
            # Send a request for resource
            if max_age >= 0:
                cached_response = self.cache_check(req.method, req.url, req.data, req.headers)
                if cached_response:
                    resp = Response(cached_response, req, start_time, history[:])
                else:
                    raw_resp = self._cm.request(req, timeout)
                    callback = lambda: (raw_resp.getheaders(), raw_resp.read(), raw_resp.status, raw_resp.reason)
                    cached_response = self.handle_response(req.method, raw_resp.status, callback)
                    if cached_response:
                        resp = Response(cached_response, req, start_time, history[:])
                    else:
                        resp = Response(raw_resp, req, start_time, history[:])
            else:
                raw_resp = self._cm.request(req, timeout)
                resp = Response(raw_resp, req, start_time, history[:])

            visited[req.url] += 1
            # Process the response
            if allow_redirects and resp.is_redirect:
                history.append(resp)
                if len(history) >= self.max_redirects:
                    raise MaxRedirects("max_redirects exceeded")
                if visited[req.url] >= self.mac_repeats:
                    raise MaxRedirects("max_repeat_redirects exceeded")

                # Create new request for redirect
                location = resp.headers.get(u"location")
                if resp.status_code == 307:
                    req = Request(req.method, location, reqHeaders, req.data, referer=req.url)
                else:
                    req = Request(u"GET", location, reqHeaders, referer=req.url)
                print("Redirecting to = {}".format(unquote(req.url)))

            # And Authorization Credentials if needed
            elif auth and resp.status_code == 401 and u"Authorization" not in req.headers:
                req.headers[u"Authorization"] = auth

            # According to RFC 2616, "2xx" code indicates that the client's
            # request was successfully received, understood, and accepted.
            # Therefore all other codes will be considered as errors.
            elif raise_for_status:
                resp.raise_for_status()
                return resp
            else:
                return resp

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    @staticmethod
    def _auth_header(username, password):
        # Ensure that username & password is of type bytes
        if isinstance(username, unicode):
            username = username.encode("utf8")
        if isinstance(password, unicode):
            password = password.encode("utf8")

        # Create basic authentication header
        auth = username + b":" + password
        auth = b64encode(auth).decode("ascii")
        return u"Basic {}".format(auth)


class Response(object):
    """A Response object"""

    def __init__(self, response, org_request, start_time, history):
        # The default encoding to use when no encoding is given
        self.apparent_encoding = "utf8"
        self.raw = None

        # Response properties
        self.url = org_request.url
        self.request = org_request
        self.history = history
        self.raw = response

        # Calculate elapsed time of the request
        self.elapsed = datetime.utcnow() - start_time

        # Response properties stores
        self.status_code = response.status
        self.reason = unicode(response.reason)
        self._body = response.read()
        response.close()

        # Fetch response headers and convert to CaseInsensitiveDict if needed
        headers = response.getheaders()
        if isinstance(headers, CaseInsensitiveDict):
            self._headers = headers
        else:
            self._headers = CaseInsensitiveDict(headers)

    @CachedProperty
    def encoding(self):
        """Encoding to decode with when accessing r.text."""
        if u"Content-Type" in self._headers:
            header = self._headers[u"Content-Type"]
            for sec in header.split(u";"):
                sec = sec.strip()
                if sec.startswith(u"charset"):
                    _, value = sec.split(u"=", 1)
                    return value.strip()

    @CachedProperty
    def content(self):
        """Content of the response, in bytes."""
        # Check if Response need to be decoded, else return raw response
        content_encoding = self._headers.get(u"content-encoding", u"").lower()
        if u"gzip" in content_encoding:
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif u"deflate" in content_encoding:
            decoder = zlib.decompressobj()
        elif content_encoding:
            raise ContentDecodingError("Unknown encoding: {}".format(content_encoding))
        else:
            return self._body

        try:
            return decoder.decompress(self._body)
        except (IOError, zlib.error) as e:
            raise ContentDecodingError("Failed to decompress content body: {}".format(e))

    @CachedProperty
    def text(self):
        """Content of the response, in unicode."""
        if self.encoding:
            return self.content.decode(self.encoding)
        else:
            try:
                return self.content.decode(self.apparent_encoding)
            except UnicodeDecodeError:
                return self.content.decode("iso-8859-1")

    @CachedProperty
    def cookies(self):
        """A dict of Cookies the server sent back."""
        if u"Set-Cookie" in self._headers:
            cookies = self._headers[u"Set-Cookie"]
            if py3:
                cookiejar = SimpleCookie(cookies)
            else:
                cookiejar = SimpleCookie(cookies.encode("iso-8859-1"))

            return {cookie.key: cookie.value for cookie in cookiejar.values()}
        else:
            return {}

    @CachedProperty
    def links(self):
        """Returns the parsed header links of the response, if any."""
        if u"link" in self._headers:
            links = {}

            replace_chars = u" '\""
            for val in re.split(u", *<", self._headers[u"link"]):
                try:
                    url, params = val.split(";", 1)
                except ValueError:
                    url, params = val, u""

                link = {u"url": url.strip("<> '\"")}

                for param in params.split(";"):
                    try:
                        key, value = param.split("=")
                    except ValueError:
                        break

                    link[key.strip(replace_chars).lower()] = value.strip(replace_chars)

                key = link.get(u"rel") or link.get(u"url")
                links[key] = link

            return links
        else:
            return {}

    @property
    def headers(self):
        """Case-insensitive Dictionary of Response Headers"""
        return self._headers

    @property
    def is_redirect(self):
        """True if this Response is a well-formed HTTP redirect that could have been processed automatically"""
        headers = self._headers
        return u"location" in headers and self.status_code in REDIRECT_CODES

    @property
    def is_permanent_redirect(self):
        """True if this Response is one of the permanent versions of redirect"""
        headers = self._headers
        return u"location" in headers and self.status_code in (301, 308)

    @property
    def ok(self):
        """
        Returns True if status_code is less than 400.

        This attribute checks if the status code of the response is between 400 and 600 to see if there
        was a client error or a server error. If the status code, is between 200 and 400, this will return True.
        This is not a check to see if the response code is 200 OK.
        """
        return self.status_code < 400

    def json(self, **kwargs):
        """
        Returns the json-encoded content of a response.

        :param kwargs: (Optional) arguments that json.loads takes.
        :raises ValueError: If the response body does not contain valid json.
        :return: Json encoded content
        """
        return _json.loads(self.text, **kwargs)

    def iter_content(self, chunk_size=512, decode_unicode=False):
        """
        Iterates over the response data. The chunk size is the number of bytes it should read into memory.
        This is not necessarily the length of each item returned as decoding can take place.

        If decode_unicode is True, content will be decoded using the best available encoding based on the response.

        :param int chunk_size: (Optional) The chunk size to use for each chunk. (default=512)
        :param bool decode_unicode: (Optional) True to return unicode, else False to return bytes. (default=False)

        :return: Content chunk.
        :rtype: iter
        """
        content = self.text if decode_unicode else self.content
        prevnl = 0
        while True:
            chucknl = prevnl + chunk_size
            data = content[prevnl:chucknl]
            if not data:
                break
            yield data
            prevnl = chucknl

    # noinspection PyUnusedLocal
    def iter_lines(self, chunk_size=None, decode_unicode=False, delimiter=b"\n"):
        """
        Iterates over the response data, one line at a time.

        :param int chunk_size: (Optional) Unused, here for compatibility with requests.
        :param decode_unicode: (Optional) True to return unicode, else False to return bytes. (default=False)
        :param delimiter: (Optional) Delimiter use as the marker for the end of line. (default='\n')

        :return: Content line.
        :rtype: iter
        """
        if decode_unicode:
            content = self.text
            delimiter = unicode(delimiter)
        else:
            content = self.content

        prevnl = 0
        sepsize = len(delimiter)
        while True:
            nextnl = content.find(delimiter, prevnl)
            if nextnl < 0:
                yield content[prevnl:]
                break
            yield content[prevnl:nextnl]
            prevnl = nextnl + sepsize

    def raise_for_status(self):
        """Raises stored HTTPError, if one occurred."""
        # According to RFC 2616, "2xx" code indicates that the client's
        # request was successfully received, understood, and accepted.
        # Therefore all other codes will be considered as errors.
        if self.status_code >= 400:
            raise HTTPError(self.url, self.status_code, self.reason, self.headers)

    def close(self):
        pass

    def __iter__(self):
        # Allows to use a response as an iterator
        return self.iter_content()

    def __bool__(self):
        # Python3
        return self.ok

    def __nonzero__(self):
        # Python2
        return self.ok

    def __repr__(self):
        return "<Response [{}]>".format(self.status_code)


def request(method, url, **kwargs):
    """
    Make a request for online resource.

    :return: A requests like :class:`Response <Response>` object
    :rtype: urlquick.Response
    """
    with Session() as session:
        return session.request(method, url, **kwargs)


def get(url, params=None, **kwargs):
    """
    Sends a GET request.

    Requests data from a specified resource.

    :param url: Url of the remote resource.
    :param dict params: (optional) Dict of url query key/value pairs.
    :param kwargs: Optional arguments that ``request`` takes.

    :return: A requests like :class:`Response <Response>` object
    :rtype: urlquick.Response
    """
    with Session() as session:
        return session.request(u"GET", url, params=params, **kwargs)


def head(url, **kwargs):
    """
    Sends a HEAD request.

    Same as GET but returns only HTTP headers and no document body.

    :param url: Url of the remote resource.
    :param kwargs: Optional arguments that ``request`` takes.

    :return: A requests like :class:`Response <Response>` object
    :rtype: urlquick.Response
    """
    with Session() as session:
        return session.request(u"HEAD", url, **kwargs)


def post(url, data=None, json=None, **kwargs):
    """
    Sends a POST request.

    Submits data to be processed to a specified resource.

    :param url: Url of the remote resource.
    :param data: (optional) Data to send with the request to the server.
    :param json: (optional) json data to send in the body of the Request.
    :param kwargs: Optional arguments that ``request`` takes.

    :return: A requests like :class:`Response <Response>` object
    :rtype: urlquick.Response
    """
    with Session() as session:
        return session.request(u"POST", url, data=data, json=json, **kwargs)


def put(url, data=None, **kwargs):
    """
    Sends a PUT request.

    Uploads a representation of the specified URI.

    :param url: Url of the remote resource.
    :param data: (optional) Data to send with the request to the server.
    :param kwargs: Optional arguments that ``request`` takes.

    :return: A requests like :class:`Response <Response>` object
    :rtype: urlquick.Response
    """
    with Session() as session:
        return session.request(u"PUT", url, data=data, **kwargs)


def patch(url, data=None, **kwargs):
    """
    Sends a PUT request.

    :param url: Url of the remote resource.
    :param data: (optional) Data to send with the request to the server.
    :param kwargs: Optional arguments that ``request`` takes.

    :return: A requests like :class:`Response <Response>` object
    :rtype: urlquick.Response
    """
    with Session() as session:
        return session.request(u"PATCH", url, data=data, **kwargs)


def delete(url, **kwargs):
    """
    Sends a DELETE request.

    :param url: Url of the remote resource.
    :param kwargs: Optional arguments that ``request`` takes.

    :return: A requests like :class:`Response <Response>` object
    :rtype: urlquick.Response
    """
    with Session() as session:
        return session.request(u"DELETE", url, **kwargs)


def options(url, **kwargs):
    """
    Sends a HEAD request.

    Identifying allowed request methods.

    :param url: Url of the remote resource.
    :param kwargs: Optional arguments that ``request`` takes.

    :return: A requests like :class:`Response <Response>` object
    :rtype: urlquick.Response
    """
    with Session() as session:
        return session.request(u"OPTIONS", url, **kwargs)


def cache_cleanup(max_age=None):
    """Remove all stale cache files"""
    CacheHandler.cleanup(max_age)
