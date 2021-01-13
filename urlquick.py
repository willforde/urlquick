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
--------
A light-weight http client with requests like interface. Featuring persistent connections and caching support.
This project was originally created for use by Kodi add-ons, but has grown into something more.
I found, that while requests has a very nice interface, there was a noticeable lag when importing the library.
The other option available is to use urllib2, but then you loose the benefit of persistent connections that requests
have. Hence the reason for this project.

All GET, HEAD and POST requests are cached locally for a period of 4 hours. When the cache expires,
conditional headers are added to a new request e.g. "Etag" and "Last-modified". Then if the server
returns a 304 Not-Modified response, the cache is reused, saving having to re-download the content body.

Inspired by: urlfetch & requests
urlfetch: https://github.com/ifduyue/urlfetch
requests: http://docs.python-requests.org/en/master/

Github: https://github.com/willforde/urlquick
Documentation: http://urlquick.readthedocs.io/en/stable/?badge=stable
Testing: https://travis-ci.org/willforde/urlquick
Code Coverage: https://coveralls.io/github/willforde/urlquick?branch=master
Code Quality: https://app.codacy.com/app/willforde/urlquick/dashboard
"""

__all__ = ["Session"]
__version__ = "0.9.4"

# Standard Lib
from functools import wraps
from codecs import open
import logging
import hashlib
import sqlite3
import time
import sys
import os

try:
    # noinspection PyPep8Naming, PyUnresolvedReferences
    import cPickle as pickle  # Python 2
except ImportError:
    import pickle  # Works for both python 2 & 3

# Third Party
from requests import adapters
from requests import sessions
from requests import *
import requests


# Check for python 2, for compatibility
py2 = sys.version_info.major == 2

# Unique logger for this module
logger = logging.getLogger("urlquick")

# Cacheable Codes & Methods
CACHEABLE_METHODS = {"GET", "HEAD", "POST"}
CACHEABLE_CODES = {
    codes.ok,
    codes.non_authoritative_info,
    codes.no_content,
    codes.multiple_choices,
    codes.moved_permanently,
    codes.found,
    codes.see_other,
    codes.temporary_redirect,
    codes.permanent_redirect,
    codes.gone,
    codes.request_uri_too_large,
}
REDIRECT_CODES = {
    codes.moved_permanently,
    codes.found,
    codes.see_other,
    codes.temporary_redirect,
    codes.permanent_redirect,
}

#: The default location for the cached files
CACHE_LOCATION = os.path.join(os.getcwd(), ".cache")

#: The default max age of the cache, value is in seconds.
MAX_AGE = 14400  # 4 Hours

# Function components to wrap when overriding requests functions
WRAPPER_ASSIGNMENTS = ["__doc__"]


# Compatible with urlquick v1
class UrlError(RequestException):
    pass


# Compatible with urlquick v1
class MaxRedirects(TooManyRedirects):
    pass


# Compatible with urlquick v1
class ContentError(HTTPError):
    pass


# Compatible with urlquick v1
class ConnError(ConnectionError):
    pass


class CacheError(RequestException):
    pass


class MissingDependency(ImportError):
    """Missing optional Dependency"""


class Response(requests.Response):
    """A Response object containing all data returned from the server."""

    def xml(self):
        """
        Parse's "XML" document into a element tree.

        :return: The root element of the element tree.
        :rtype: xml.etree.ElementTree.Element
        """
        from xml.etree import ElementTree
        return ElementTree.fromstring(self.content)

    def parse(self, tag=u"", attrs=None):
        """
        Parse's "HTML" document into a element tree using HTMLement.

        .. seealso:: The htmlement documentation can be found at.\n
                     http://python-htmlement.readthedocs.io/en/stable/?badge=stable

        :param str tag: [opt] Name of 'element' which is used to filter tree to required section.

        :type attrs: dict
        :param attrs: [opt] Attributes of 'element', used when searching for required section.
                            Attrs should be a dict of unicode key/value pairs.

        :return: The root element of the element tree.
        :rtype: xml.etree.ElementTree.Element

        :raise MissingDependency: If the optional 'HTMLement' dependency is missing.
        """
        try:
            # noinspection PyUnresolvedReferences
            from htmlement import HTMLement
        except ImportError:
            raise MissingDependency("Missing optional dependency: 'HTMLement'")
        else:
            tag = tag.decode() if isinstance(tag, bytes) else tag
            parser = HTMLement(tag, attrs)
            parser.feed(self.text)
            return parser.close()

    @classmethod
    def prepare_response(cls, response):
        self = cls()
        self.__dict__.update(response.__dict__)
        return self

    def __conform__(self, protocol):
        """Convert Response to a sql blob."""
        if protocol is sqlite3.PrepareProtocol:
            data = pickle.dumps(self, protocol=pickle.HIGHEST_PROTOCOL)
            return sqlite3.Binary(data)


class CacheRecord(object):
    """SQL cache data record."""

    def __init__(self, record):  # type: (sqlite3.Row) -> None
        self._fresh = record["fresh"] or self._response.status_code in REDIRECT_CODES
        self._response = pickle.loads(record["response"])

    @property
    def response(self):  # type: () -> Response
        return self._response

    @property
    def isfresh(self):  # type: () -> bool
        return self._fresh

    def add_conditional_headers(self, headers):
        """Return a dict of conditional headers from cache."""
        # Fetch cached headers
        cached_headers = self._response.headers

        # Check for conditional headers
        if "Etag" in cached_headers:
            headers["If-none-match"] = cached_headers["ETag"]
        if "Last-modified" in cached_headers:
            headers["If-modified-since"] = cached_headers["Last-Modified"]


class CacheHTTPAdapter(adapters.HTTPAdapter):
    def __init__(self, cache_location, *args, **kwargs):
        super(CacheHTTPAdapter, self).__init__(*args, **kwargs)
        # sqlite3.enable_callback_tracebacks(True)

        # Create any missing directorys
        self.cache_file = os.path.join(cache_location, ".urlquick.slite3")
        if not os.path.exists(cache_location):
            os.makedirs(cache_location)

        # Connect to database
        self.conn = self.connect()

    def connect(self):  # type: () -> sqlite3.Connection
        """Connect to SQLite Database."""
        try:
            conn = sqlite3.connect(self.cache_file, timeout=1)
        except sqlite3.Error as e:
            raise CacheError(str(e))
        else:
            conn.row_factory = sqlite3.Row
            # conn.isolation_level = None
            conn.execute("""
            CREATE TABLE IF NOT EXISTS urlcache
            (
                key TEXT PRIMARY KEY NOT NULL,
                response BLOB NOT NULL,
                cached_date TIMESTAMP NOT NULL
            )""")

        return conn

    def execute(self, query, values=(), repeat=False):  # type: (str, tuple, bool) -> sqlite3.Cursor
        """Execute SQL Query."""
        try:
            with self.conn:
                # Automatically commits or rolls back on exception
                return self.conn.execute(query, values)
        except (sqlite3.IntegrityError, sqlite3.OperationalError) as e:
            # Check if database is currupted
            if repeat is False and (str(e).find("file is encrypted") > -1 or str(e).find("not a database") > -1):
                logger.debug("Corrupted database detected, Cleaning...")
                self.close()
                os.remove(self.cache_file)
                self.conn = self.connect()
                return self.execute(query, values, repeat=True)
            else:
                raise e

    def close(self):  # type: () -> None
        self.conn.cursor().close()
        self.conn.close()

    # noinspection PyMethodMayBeStatic, PyShadowingNames
    def hash_url(self, request):  # type: (PreparedRequest) -> str
        """Return url as a sha1 encoded hash."""
        url = request.url.encode("utf8") if isinstance(request.url, type(u"")) else request.url
        method = request.method.encode("utf8") if isinstance(request.method, type(u"")) else request.method
        return hashlib.sha1(b''.join((method, url, request.body or b''))).hexdigest()

    def get_cache(self, urlhash, max_age):  # type: (str, int) -> CacheRecord
        """Return a cached response if one exists."""
        result = self.execute("""SELECT key, response, 
        CASE WHEN ? == -1 THEN 1 ELSE strftime('%s', 'now') - strftime('%s', cached_date, 'unixepoch') < ? END AS fresh 
        FROM urlcache WHERE key = ?""", (max_age, max_age, urlhash))
        record = result.fetchone()
        if record is not None:
            return CacheRecord(record)

    def set_cache(self, urlhash, resp):  # type: (str, Response) -> Response
        """Save a response to database and return original response."""
        self.execute(
            "REPLACE INTO urlcache (key, response, cached_date) VALUES (?,?,strftime('%s', 'now'))",
            (urlhash, resp)
        )
        return resp

    def reset_cache(self, urlhash):  # type: (str) -> None
        """Reset the cached date to current time."""
        self.execute("UPDATE urlcache SET cached_date=strftime('%s', 'now') WHERE key=?", (urlhash,))

    def clean(self, max_age=60*60*24*7):  # type: (int) -> None
        """Clean the database of expired caches."""
        self.execute(
            "DELETE FROM urlcache WHERE strftime('%s', 'now') - strftime('%s', cached_date, 'unixepoch') > ?",
            (max_age,)
        )

    # noinspection PyShadowingNames
    def send(self, request, **kwargs):
        max_age = int(request.headers.pop("x-cache-max-age"))
        urlhash = self.hash_url(request)

        # Check if request has a valid cache and return it
        if request.method in CACHEABLE_METHODS:
            cache = self.get_cache(urlhash, max_age)
            if cache and cache.isfresh:
                logger.debug("Cache is fresh")
                return cache.response
            elif cache:
                # Allows for Not Modified check
                logger.debug("Cache is stale, adding conditional headers to request")
                cache.add_conditional_headers(request.headers)
        else:
            cache = None

        # Send request for remote resource
        response = super(CacheHTTPAdapter, self).send(request, **kwargs)

        # Check for Not Modified response
        if cache and response.status_code == codes.not_modified:
            logger.debug("Server return 304 Not Modified response, using cached response")
            response.close()
            self.reset_cache(urlhash)
            return cache.response

        # Cache any cacheable responses
        elif request.method in CACHEABLE_METHODS and response.status_code in CACHEABLE_CODES:
            logger.debug("Caching %s %s response", response.status_code, response.reason)
            response = self.set_cache(urlhash, response)

        return response

    def build_response(self, req, resp):
        """Replace response object with our customized version."""
        resp = super(CacheHTTPAdapter, self).build_response(req, resp)
        return Response.prepare_response(resp)


class Session(sessions.Session):
    # This is here so the kodi related code can change
    # this value to True for a better kodi expereance.
    default_raise_for_status = False

    def __init__(self, cache_location=CACHE_LOCATION, **kwargs):
        super(Session, self).__init__()

        #: When set to True, This attribute checks if the status code of the
        #: response is between 400 and 600 to see if there was a client error
        #: or a server error. Raising a :class:`HTTPError` if so.
        self.raise_for_status = kwargs.get("raise_for_status", self.default_raise_for_status)

        #: Age the 'cache' can be, before it’s considered stale. -1 will disable caching.
        #: Defaults to :data:`MAX_AGE <urlquick.MAX_AGE>`
        self.max_age = kwargs.get("max_age", MAX_AGE)

        self.adapter = adapter = CacheHTTPAdapter(cache_location)
        self.mount("https://", adapter)
        self.mount("http://", adapter)

    def _raise_for_status(self, response, raise_for_status):  # type: (Response, bool) -> None
        """Raise error if status code is between 400 and 600."""
        if self.raise_for_status if raise_for_status is None else raise_for_status:
            response.raise_for_status()

    def _merge_max_age(self, max_age):  # type: (int) -> int
        return (-1 if self.max_age is None else self.max_age) if max_age is None else max_age

    def request(self, *args, **kwargs):  # type: (...) -> Response
        # Sometimes people pass in None for headers
        # So we need to keep this in mind
        if len(args) >= 5:
            headers = args[4] or {}
            args[4] = headers
        else:
            headers = kwargs.get("headers") or {}
            kwargs["headers"] = headers

        # Add max age to headers so the adapter can access it
        max_age = self._merge_max_age(kwargs.pop("max_age", None))
        headers["x-cache-max-age"] = str(max_age)

        # This is here to indicate to 'self.send' that it's been called internally
        # This is to pervent 'self.send' checking for max age & raise_for_status
        headers["x-cache-internal"] = "true"

        raise_for_status = kwargs.pop("raise_for_status", None)
        response = super(Session, self).request(*args, **kwargs)
        self._raise_for_status(response, raise_for_status)
        return response

    # noinspection PyShadowingNames
    def send(self, request, **kwargs):  # type: (...) -> Response
        # If the headers does not contain 'x-cache-internal' then this method
        # must be getting called directly, so check for extra parameters
        if request.headers.pop("x-cache-internal", None):
            return super(Session, self).send(request, **kwargs)
        else:
            # Add max age to request headers
            max_age = self._merge_max_age(kwargs.pop("max_age", None))
            request.headers["x-cache-max-age"] = str(max_age)

            # Make request and check for status code
            raise_for_status = kwargs.pop("raise_for_status", None)
            response = super(Session, self).send(request, **kwargs)
            self._raise_for_status(response, raise_for_status)
            return response

    def get(self, url, **kwargs):  # type: (...) -> Response
        return super(Session, self).get(url, **kwargs)

    def options(self, url, **kwargs):  # type: (...) -> Response
        return super(Session, self).options(url, **kwargs)

    def head(self, url, **kwargs):  # type: (...) -> Response
        return super(Session, self).head(url, **kwargs)

    def post(self, url, data=None, json=None, **kwargs):  # type: (...) -> Response
        return super(Session, self).post(url, data, json, **kwargs)

    def put(self, url, data=None, **kwargs):  # type: (...) -> Response
        return super(Session, self).put(url, data, **kwargs)

    def patch(self, url, data=None, **kwargs):  # type: (...) -> Response
        return super(Session, self).patch(url, data, **kwargs)

    def delete(self, url, **kwargs):  # type: (...) -> Response
        return super(Session, self).delete(url, **kwargs)


@wraps(requests.request, assigned=WRAPPER_ASSIGNMENTS)
def request(method, url, **kwargs):  # type: (...) -> Response
    with Session() as s:
        return s.request(method=method, url=url, **kwargs)


@wraps(requests.get, assigned=WRAPPER_ASSIGNMENTS)
def get(url, params=None, **kwargs):  # type: (...) -> Response
    return requests.get(url, params, **kwargs)


@wraps(requests.options, assigned=WRAPPER_ASSIGNMENTS)
def options(url, **kwargs):  # type: (...) -> Response
    return requests.options(url, **kwargs)


@wraps(requests.head, assigned=WRAPPER_ASSIGNMENTS)
def head(url, **kwargs):  # type: (...) -> Response
    return requests.head(url, **kwargs)


@wraps(requests.post, assigned=WRAPPER_ASSIGNMENTS)
def post(url, data=None, json=None, **kwargs):  # type: (...) -> Response
    return requests.post(url, data, json, **kwargs)


@wraps(requests.put, assigned=WRAPPER_ASSIGNMENTS)
def put(url, data=None, **kwargs):  # type: (...) -> Response
    return requests.put(url, data, **kwargs)


@wraps(requests.patch, assigned=WRAPPER_ASSIGNMENTS)
def patch(url, data=None, **kwargs):  # type: (...) -> Response
    return requests.patch(url, data, **kwargs)


@wraps(requests.delete, assigned=WRAPPER_ASSIGNMENTS)
def delete(url, **kwargs):  # type: (...) -> Response
    return requests.delete(url, **kwargs)


@wraps(requests.session, assigned=WRAPPER_ASSIGNMENTS)
def session():  # type: (...) -> Session
    return Session()


def cache_cleanup(max_age=None):
    """
    Remove all stale cache files.

    :param int max_age: [opt] The max age the cache can be before removal.
                        defaults => :data:`MAX_AGE <urlquick.MAX_AGE>`
    """
    logger.info("Initiating cache cleanup")
    with Session() as s:
        # noinspection PyUnresolvedReferences
        s.adapter.clean(max_age)


def auto_cache_cleanup(max_age=60*60*24*14):
    """
    Check if the cache needs cleanup. Uses a empty file to keep track.

    :param int max_age: [opt] The max age the cache can be before removal.
                        defaults => 1209600 (14 days)

    :returns: True if cache was cleaned else false if no cache cleanup was started.
    :rtype: bool
    """
    check_file = os.path.join(CACHE_LOCATION, ".urlquick_check")
    last_check = os.stat(check_file).st_mtime if os.path.exists(check_file) else 0
    current_time = time.time()

    # Check if it's time to initiate a cache cleanup
    if current_time - last_check > max_age * 2:
        cache_cleanup(max_age)
        try:
            os.utime(check_file, None)
        except OSError:
            open(check_file, "a").close()
        return True
    return False


#############
# Kodi Only #
#############

# Set the location of the cache file to the addon data directory
# _addon_data = __import__("xbmcaddon").Addon()
# _CACHE_LOCATION = __import__("xbmc").translatePath(_addon_data.getAddonInfo("profile"))
# CACHE_LOCATION = _CACHE_LOCATION.decode("utf8") if isinstance(_CACHE_LOCATION, bytes) else _CACHE_LOCATION
# logger.debug("Cache location: %s", CACHE_LOCATION)
# Session.default_raise_for_status = True

# Check if cache cleanup is required
# auto_cache_cleanup()
