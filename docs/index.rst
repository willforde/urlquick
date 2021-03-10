Urlquick II: Requests, but with caching
=======================================

.. image:: https://img.shields.io/pypi/v/urlquick
    :target: https://pypi.org/project/urlquick
    :alt: PyPI Version

.. image:: https://readthedocs.org/projects/urlquick/badge/?version=stable
    :target: https://urlquick.readthedocs.io/en/stable/?badge=stable
    :alt: Documentation Status

.. image:: https://www.travis-ci.com/willforde/urlquick.svg?branch=master
    :target: https://www.travis-ci.com/willforde/urlquick
    :alt: Test Build Status

.. image:: https://coveralls.io/repos/github/willforde/urlquick/badge.svg?branch=master
    :target: https://coveralls.io/github/willforde/urlquick?branch=master
    :alt: Test Coverage

.. image:: https://api.codeclimate.com/v1/badges/4f622589a4b8e24ac996/maintainability
   :target: https://codeclimate.com/github/willforde/urlquick/maintainability
   :alt: Maintainability


Urlquick II
-----------

Urlquick 2 is a wrapper for requests that add's support for http caching.
It acts just like requests but with a few extra parameters and features.
'Requests' itself is left untouched.

All GET, HEAD and POST requests are cached locally for a period of 4 hours, this can be changed. When the cache expires,
conditional headers are added to any new request e.g. "Etag" and "Last-modified". Then if the server
returns a 304 Not-Modified response, the cache is used, saving having to re-download the content body.

All of Requests ``get``, ``head``, ``post`` and ``request`` functions/methods all get 2 extra optional parameters.
Both these 2 parameters can also be set on a session object too.

    * ``max_age``: Age the 'cache' can be before it’s considered stale.
    * ``raise_for_status``: Boolean that when set to ``True`` will call ``resp.raise_for_status()`` for you automatically.

The Requests response objects also gets too new methods.

    * ``parse()``: Parse’s “HTML” document into a element tree using HTMLement.
    * ``xml()``: Parse’s XML document into a element tree.



API
===

Globals
-------

.. autodata:: urlquick.MAX_AGE
.. data:: urlquick.CACHE_LOCATION
    :annotation: = "."

    Location for the cache directory. Defaults to the current working directory.

.. autoexception:: urlquick.CacheError


Session
-------

.. class:: urlquick.Session

    This class is idendical to the requests `SESSION`_ class, except for 2 small differences.
    The following parameters can also be set as a keyword only argument on all the request methods.

    .. autoattribute:: max_age
        :annotation: = MAX_AGE

    .. autoattribute:: raise_for_status
        :annotation: = False

Response
--------

.. autoclass:: urlquick.Response
    :members: parse, xml

    This class is idendical to the requests `RESPONSE`_ class, except for 2 small differences.


External Links
==============

Requests Docs: https://requests.readthedocs.io/en/master/

HTMLement Docs: https://python-htmlement.readthedocs.io/en/stable/?badge=stable

Requests Docs: https://requests.readthedocs.io/en/master/

Bug Tracker: https://github.com/willforde/urlquick/issues

.. _SESSION: https://requests.readthedocs.io/en/master/api/#request-sessions

.. _RESPONSE: https://requests.readthedocs.io/en/master/api/#requests.Response