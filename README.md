Urlquick II: Requests, but with caching
=======================================

[![PyPI](https://img.shields.io/pypi/v/urlquick)](https://pypi.org/project/urlquick/)
[![Documentation Status](https://readthedocs.org/projects/urlquick/badge/?version=stable)](https://urlquick.readthedocs.io/en/stable/?badge=stable)
[![Build Status](https://www.travis-ci.com/willforde/urlquick.svg?branch=master)](https://www.travis-ci.com/willforde/urlquick)
[![Coverage Status](https://coveralls.io/repos/github/willforde/urlquick/badge.svg?branch=master)](https://coveralls.io/github/willforde/urlquick?branch=master)
[![Maintainability](https://api.codeclimate.com/v1/badges/4f622589a4b8e24ac996/maintainability)](https://codeclimate.com/github/willforde/urlquick/maintainability)


Urlquick II
-----------
Urlquick2 is a wrapper for requests that add's support for http caching.
It act's just like requests but with a few extra parameters and features.
'Requests' itself is left untouched.

All GET, HEAD and POST requests are cached locally for a period of 4 hours, this can be changed. When the cache expires,
conditional headers are added to any new request e.g. "Etag" and "Last-modified". Then if the server
returns a 304 Not-Modified response, the cache is used, saving having to re-download the content body.


Usage
-----

```python
>>> from urlquick import Session

# Make a connection pool.
>>> http = Session()

# Make a request.
>>> r = http.get('https://httpbin.org/ip')

# View response data.
>>> r.json()
{'ip': '172.69.48.124'}
```


Install
-------
Stable
```console
$ pip install urlquick
```

Unstable
```console
$ pip install git+https://github.com/willforde/urlquick.git
```
