.. image:: https://badge.fury.io/py/urlquick.svg
    :target: https://pypi.python.org/pypi/urlquick

.. image:: https://readthedocs.org/projects/urlquick/badge/?version=stable
    :target: http://urlquick.readthedocs.io/en/stable/?badge=stable

.. image:: https://travis-ci.org/willforde/urlquick.svg?branch=master
    :target: https://travis-ci.org/willforde/urlquick

.. image:: https://coveralls.io/repos/github/willforde/urlquick/badge.svg?branch=master
    :target: https://coveralls.io/github/willforde/urlquick?branch=master

.. image:: https://api.codacy.com/project/badge/Grade/25951f521ebd4534ae64c725e0be9441
    :target: https://www.codacy.com/app/willforde/urlquick?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=willforde/urlquick&amp;utm_campaign=Badge_Grade

.. image:: https://img.shields.io/pypi/pyversions/urlquick.svg
    :target: https://pypi.python.org/pypi/urlquick

.. image:: https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg
   :target: https://saythanks.io/to/willforde

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

Features
--------
* Simple Keep-Alive & Connection Pooling
* Sessions with limited Cookie Controls
* International Domains and URLs
* Automatic Content Decoding
* Elegant Key/Value Cookies
* Automatic Decompression
* Unicode Response Bodies
* Basic Authentication
* Connection Timeouts
* Resource Caching

Install
-------
Run ::

    pip install urlquick

-or- ::

    pip install git+https://github.com/willforde/urlquick.git

Usage
-----

Urlquick is similar to the requests library but it only implements most top level methods
like GET, POST and PUT. The Session class is also implemented in a more limited form.
The response object is fully comparable with the 'requests' response object. # link request object ::

    >>> import urlquick
    >>> r = urlquick.get('https://api.github.com/events')
    >>> r.status_code
    200
    >>> r.headers['content-type']
    'text/html; charset=utf-8'
    >>> r.encoding
    'utf-8'
    >>> r.content
    b'[{"repository":{"open_issues":0,"url":"https://github.com/...
    >>> r.text
    u'[{"repository":{"open_issues":0,"url":"https://github.com/...
    >>> r.json()
    [{u'repository': {u'open_issues': 0, u'url': 'https://github.com/...

