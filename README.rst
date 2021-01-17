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
Urlquick2 is a wrapper for requests that add's support for http caching.
It act's just like requests but with a few extra parameters and features.
'Requests' itself is left untouched.

All GET, HEAD and POST requests are cached locally for a period of 4 hours, this can be changed. When the cache expires,
conditional headers are added to any new request e.g. "Etag" and "Last-modified". Then if the server
returns a 304 Not-Modified response, the cache is used, saving having to re-download the content body.

Install
-------
Stable ::

    pip install urlquick

Unstable ::

    pip install git+https://github.com/willforde/urlquick.git

Usage
-----

Urlquick is similar to the requests library but it only implements most top level methods
like GET, POST and PUT. The Session class is also implemented in a more limited form.
The response object is fully comparable with the 'requests' response object.

```pycon
>>> import urlquick

# Make a request.
>>> r = urlquick.get('https://httpbin.org/ip')

# View response data.
>>> r.status_code
200
>>> r.json()
{'ip': '172.69.48.124'}
```
